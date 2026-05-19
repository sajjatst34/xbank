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



import random
import requests
from django.conf import settings
from django.utils import timezone
from datetime import timedelta

from .models import OTP


# ===============================
# OTP GENERATOR
# ===============================
def generate_otp():
    return str(random.randint(100000, 999999))


# ===============================
# MAIN OTP FUNCTION (USED BY VIEWS)
# ===============================
def send_otp(user, purpose, method="EMAIL"):
    """
    Called from views.py
    """

    otp_code = generate_otp()

    # delete old OTP
    OTP.objects.filter(user=user, purpose=purpose).delete()

    # save OTP
    OTP.objects.create(
        user=user,
        code=otp_code,
        purpose=purpose,
        expires_at=timezone.now() + timedelta(minutes=5),
    )

    if method == "EMAIL":
        _send_otp_email(user, otp_code, purpose)

    print(f"OTP sent to {user.username} for {purpose} via {method}")


# ===============================
# RESEND EMAIL SENDER
# ===============================
def _send_otp_email(user, otp_code, purpose):

    url = "https://api.resend.com/emails"

    payload = {
        "from": settings.DEFAULT_FROM_EMAIL,
        "to": [user.email],
        "subject": f"XBank OTP - {purpose}",
        "html": f"""
            <h2>XBank Security Verification</h2>
            <p>Your OTP code is:</p>
            <h1>{otp_code}</h1>
            <p>Valid for 5 minutes.</p>
        """,
    }

    headers = {
        "Authorization": f"Bearer {settings.RESEND_API_KEY}",
        "Content-Type": "application/json",
    }

    response = requests.post(url, json=payload, headers=headers)

    print("RESEND STATUS:", response.status_code)
    print("RESEND RESPONSE:", response.text)

    if response.status_code not in (200, 201):
        raise Exception("Resend email failed")

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
