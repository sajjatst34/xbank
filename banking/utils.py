"""
X Bank - Security & OTP Utilities
Handles OTP generation, 2FA, card validation, and audit logging.
"""
import pyotp
import qrcode
import base64
import hashlib
import secrets
import io
import logging
from decimal import Decimal
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone
from django.template.loader import render_to_string

logger = logging.getLogger('banking')


# ─── OTP ──────────────────────────────────────────────────────────────────────

def send_otp(user, purpose, channel='EMAIL'):
    """
    Generate and send an OTP to the user.
    Returns the OTPVerification object.
    """
    from banking.models import OTPVerification, generate_otp

    # Invalidate any existing unused OTPs for this purpose
    OTPVerification.objects.filter(
        user=user, purpose=purpose, is_used=False
    ).update(is_used=True)

    otp_code = generate_otp()
    expires_at = timezone.now() + timezone.timedelta(
        seconds=getattr(settings, 'OTP_EXPIRY_SECONDS', 300)
    )

    otp_obj = OTPVerification.objects.create(
        user=user,
        otp_code=otp_code,
        purpose=purpose,
        channel=channel,
        expires_at=expires_at,
    )

    if channel == 'EMAIL':
        _send_otp_email(user, otp_code, purpose)
    elif channel == 'SMS':
        _send_otp_sms(user, otp_code, purpose)

    logger.info(f"OTP sent to {user.username} for {purpose} via {channel}")
    return otp_obj


def _send_otp_email(user, otp_code, purpose):
    """Send OTP via email."""
    purpose_labels = {
        'LOGIN': 'Login Verification',
        'TRANSACTION': 'Transaction Authorization',
        'PASSWORD_RESET': 'Password Reset',
        'EMAIL_VERIFY': 'Email Verification',
        'PHONE_VERIFY': 'Phone Verification',
        'CARD_ACTIVATE': 'Card Activation',
    }
    label = purpose_labels.get(purpose, 'Verification')
    subject = f'X Bank - {label} OTP'
    message = f"""
Dear {user.get_full_name() or user.username},

Your X Bank {label} OTP is:

    {otp_code}

This OTP is valid for 5 minutes. Do NOT share it with anyone.
X Bank will never ask for your OTP over phone or email.

If you did not request this, please contact our security team immediately.

Best regards,
X Bank Security Team
    """.strip()

    try:
        send_mail(
            subject=subject,
            message=message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            fail_silently=False,
        )
    except Exception as e:
        logger.error(f"Failed to send OTP email to {user.email}: {e}")


def _send_otp_sms(user, otp_code, purpose):
    """Placeholder for SMS OTP (integrate Twilio / local SMS gateway)."""
    logger.info(f"[SMS MOCK] OTP {otp_code} would be sent to {user.phone}")
    # To integrate Twilio:
    # from twilio.rest import Client
    # client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
    # client.messages.create(
    #     body=f'Your X Bank OTP is {otp_code}. Valid for 5 minutes.',
    #     from_=settings.TWILIO_PHONE_NUMBER,
    #     to=user.phone
    # )


def verify_otp(user, otp_code, purpose):
    """
    Verify an OTP. Returns True/False.
    """
    from banking.models import OTPVerification

    try:
        otp_obj = OTPVerification.objects.filter(
            user=user,
            purpose=purpose,
            is_used=False,
        ).latest('created_at')

        return otp_obj.verify(otp_code)
    except OTPVerification.DoesNotExist:
        return False


# ─── TOTP (Google Authenticator style) ───────────────────────────────────────

def generate_totp_secret():
    """Generate a new TOTP secret for a user."""
    return pyotp.random_base32()


def get_totp_uri(user, secret):
    """Get the URI to encode as QR code for Google Authenticator."""
    issuer = getattr(settings, 'OTP_TOTP_ISSUER', 'X Bank')
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=user.email, issuer_name=issuer)


def get_totp_qr_base64(user, secret):
    """Generate a base64-encoded QR code image for TOTP setup."""
    uri = get_totp_uri(user, secret)
    img = qrcode.make(uri)
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    buffer.seek(0)
    return base64.b64encode(buffer.read()).decode('utf-8')


def verify_totp(user, token):
    """Verify a TOTP token against the user's secret."""
    if not user.totp_secret:
        return False
    totp = pyotp.TOTP(user.totp_secret)
    return totp.verify(token, valid_window=1)  # Allow 30s drift


# ─── CARD UTILITIES ───────────────────────────────────────────────────────────

def hash_cvv(cvv: str, card_number: str) -> str:
    """Hash CVV with card number as salt (never store plain CVV)."""
    salted = f"{card_number}:{cvv}:{settings.SECRET_KEY}"
    return hashlib.sha256(salted.encode()).hexdigest()


def verify_cvv(cvv: str, card_number: str, stored_hash: str) -> bool:
    """Verify CVV against stored hash."""
    return hash_cvv(cvv, card_number) == stored_hash


def hash_pin(pin: str, account_number: str) -> str:
    """Hash a card PIN."""
    salted = f"{account_number}:{pin}:{settings.SECRET_KEY}"
    return hashlib.sha256(salted.encode()).hexdigest()


def luhn_check(card_number: str) -> bool:
    """Validate card number using Luhn algorithm."""
    digits = [int(d) for d in card_number.replace(' ', '') if d.isdigit()]
    if len(digits) != 16:
        return False
    total = 0
    for i, digit in enumerate(reversed(digits)):
        if i % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


def detect_card_network(card_number: str) -> str:
    """Detect card network from number prefix."""
    n = card_number.replace(' ', '')
    if n.startswith('4'):
        return 'VISA'
    elif n[:2] in ['51', '52', '53', '54', '55'] or (2221 <= int(n[:4]) <= 2720):
        return 'MASTERCARD'
    elif n[:2] in ['34', '37']:
        return 'AMEX'
    return 'UNKNOWN'


# ─── TRANSACTION SECURITY ─────────────────────────────────────────────────────

def check_transaction_limits(account, amount):
    """
    Check daily transaction limits.
    Returns (ok: bool, reason: str)
    """
    from banking.models import Transaction
    from django.utils import timezone

    today = timezone.now().date()
    daily_total = Transaction.objects.filter(
        account=account,
        created_at__date=today,
        status='COMPLETED',
        transaction_type__in=['TRANSFER_OUT', 'WITHDRAWAL', 'BILL_PAYMENT',
                               'RECHARGE', 'CARD_PAYMENT', 'DONATION'],
    ).aggregate(
        total=__import__('django.db.models', fromlist=['Sum']).Sum('amount')
    )['total'] or Decimal('0.00')

    max_daily = getattr(settings, 'MAX_DAILY_TRANSFER', 500000)
    max_single = getattr(settings, 'MAX_SINGLE_TRANSACTION', 100000)
    min_amount = getattr(settings, 'MIN_TRANSACTION', 10)

    if amount < min_amount:
        return False, f'Minimum transaction amount is ৳{min_amount}'
    if amount > max_single:
        return False, f'Single transaction limit is ৳{max_single:,}'
    if daily_total + Decimal(str(amount)) > max_daily:
        remaining = max_daily - float(daily_total)
        return False, f'Daily limit exceeded. Remaining: ৳{remaining:,.2f}'
    return True, ''


# ─── AUDIT LOGGING ────────────────────────────────────────────────────────────

def audit_log(request, action, description, metadata=None):
    """Create an audit log entry."""
    from banking.models import AuditLog
    from banking.middleware import get_client_ip

    user = request.user if request.user.is_authenticated else None
    ip = get_client_ip(request)

    AuditLog.objects.create(
        user=user,
        action=action,
        description=description,
        ip_address=ip,
        user_agent=request.META.get('HTTP_USER_AGENT', '')[:500],
        metadata=metadata or {},
    )


# ─── MISC ─────────────────────────────────────────────────────────────────────

def generate_secure_token(length=32):
    """Generate a cryptographically secure random token."""
    return secrets.token_urlsafe(length)


def mask_account_number(account_number: str) -> str:
    """Return masked account number like ****1234."""
    return f"****{account_number[-4:]}"


def mask_phone(phone: str) -> str:
    """Return masked phone like +880*****5678."""
    if len(phone) >= 8:
        return phone[:4] + '*' * (len(phone) - 8) + phone[-4:]
    return '****'
