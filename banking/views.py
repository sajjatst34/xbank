"""
X Bank - Views
Handles all banking operations with security, OTP verification, and audit logging.
"""
import logging
from decimal import Decimal
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.views.decorators.http import require_POST, require_http_methods
from django.views.decorators.cache import never_cache
from django.utils import timezone
from django.db import transaction as db_transaction
from django.db.models import Sum
from django.http import JsonResponse
from django.core.paginator import Paginator

from .models import (
    User, Account, Card, Transaction, OTPVerification,
    LoanApplication, SavingsPlan, BillPayment, MobileRecharge,
    Donation, AuditLog, generate_otp
)
from .forms import (
    RegistrationForm, SecureLoginForm, OTPVerifyForm, TOTPSetupForm,
    ChangePasswordForm, DepositForm, WithdrawForm, TransferForm,
    CardPaymentForm, BillPaymentForm, RechargeForm, DonationForm,
    LoanApplicationForm, SavingsPlanForm
)
from .utils import (
    send_otp, verify_otp, verify_totp, generate_totp_secret,
    get_totp_qr_base64, hash_cvv, verify_cvv, luhn_check,
    detect_card_network, check_transaction_limits, audit_log,
    mask_account_number, mask_phone
)
from .middleware import get_client_ip

logger = logging.getLogger('banking')


# ─── HELPERS ─────────────────────────────────────────────────────────────────

def get_user_primary_account(user):
    return Account.objects.filter(user=user, is_primary=True, status='ACTIVE').first() or \
           Account.objects.filter(user=user, status='ACTIVE').first()


def require_otp_verified(request, purpose='TRANSACTION'):
    """Check if OTP was verified for this session/purpose."""
    key = f'otp_verified_{purpose}'
    return request.session.get(key, False)


def mark_otp_verified(request, purpose='TRANSACTION'):
    request.session[f'otp_verified_{purpose}'] = True
    request.session[f'otp_verified_{purpose}_time'] = timezone.now().timestamp()


def clear_otp_session(request, purpose='TRANSACTION'):
    request.session.pop(f'otp_verified_{purpose}', None)
    request.session.pop(f'otp_verified_{purpose}_time', None)


# ─── ERROR PAGES ─────────────────────────────────────────────────────────────

def error_403(request, exception=None):
    return render(request, 'banking/errors/403.html', status=403)

def error_404(request, exception=None):
    return render(request, 'banking/errors/404.html', status=404)

def error_500(request):
    return render(request, 'banking/errors/500.html', status=500)


# ─── HOME ─────────────────────────────────────────────────────────────────────

def home(request):
    if request.user.is_authenticated:
        return redirect('banking:dashboard')
    return render(request, 'banking/home.html')


# ─── REGISTRATION ─────────────────────────────────────────────────────────────

@never_cache
def register(request):
    if request.user.is_authenticated:
        return redirect('banking:dashboard')

    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            try:
                with db_transaction.atomic():
                    user = form.save(commit=False)
                    user.is_active = True
                    user.save()

                    # Create bank account
                    account_type = form.cleaned_data.get('account_type', 'SAVINGS')
                    account = Account.objects.create(
                        user=user,
                        account_type=account_type,
                        is_primary=True,
                        balance=Decimal('0.00'),
                    )

                    # Send email verification OTP
                    send_otp(user, 'EMAIL_VERIFY', 'EMAIL')

                    # Store pending user id in session
                    request.session['pending_verify_user'] = user.pk

                    audit_log(request, 'ACCOUNT_ACTION',
                              f'New user registered: {user.username}',
                              {'account_number': account.account_number})

                    messages.success(request,
                        f'Account created! Account #{account.account_number}. '
                        'Please verify your email with the OTP sent.')
                    return redirect('banking:verify_email')

            except Exception as e:
                logger.error(f"Registration error: {e}")
                messages.error(request, 'Registration failed. Please try again.')
        else:
            messages.error(request, 'Please correct the errors below.')
    else:
        form = RegistrationForm()

    return render(request, 'banking/register.html', {'form': form})


# ─── EMAIL VERIFICATION ───────────────────────────────────────────────────────

@never_cache
def verify_email(request):
    user_pk = request.session.get('pending_verify_user')
    if not user_pk:
        return redirect('banking:login')

    user = get_object_or_404(User, pk=user_pk)

    if request.method == 'POST':
        form = OTPVerifyForm(request.POST)
        if form.is_valid():
            code = form.cleaned_data['otp_code']
            if verify_otp(user, code, 'EMAIL_VERIFY'):
                user.is_email_verified = True
                user.save()
                request.session.pop('pending_verify_user', None)
                messages.success(request, 'Email verified! You can now login.')
                audit_log(request, 'OTP_VERIFIED', f'Email verified for {user.username}')
                return redirect('banking:login')
            else:
                messages.error(request, 'Invalid or expired OTP. Please try again.')
    else:
        form = OTPVerifyForm()

    return render(request, 'banking/verify_otp.html', {
        'form': form, 'purpose': 'Email Verification',
        'masked_contact': user.email[:3] + '***@' + user.email.split('@')[1],
        'resend_url': 'banking:resend_otp_email',
    })


# ─── LOGIN ─────────────────────────────────────────────────────────────────────

@never_cache
def user_login(request):
    if request.user.is_authenticated:
        return redirect('banking:dashboard')

    if request.method == 'POST':
        form = SecureLoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            ip = get_client_ip(request)

            # Check if 2FA is enabled
            if user.two_factor_enabled: # type: ignore
                # Store user in session, redirect to 2FA
                request.session['2fa_user_pk'] = user.pk
                request.session['2fa_ip'] = ip
                # Send email OTP for 2FA
                send_otp(user, 'LOGIN', 'EMAIL')
                audit_log(request, 'LOGIN', f'2FA triggered for {user.username}')
                return redirect('banking:two_factor_verify')
            else:
                # Direct login
                login(request, user)
                user.last_login_ip = ip # type: ignore
                user.failed_login_attempts = 0 # type: ignore
                user.save(update_fields=['last_login_ip', 'failed_login_attempts'])
                request.session['last_activity'] = timezone.now().timestamp()

                if not form.cleaned_data.get('remember_me'):
                    request.session.set_expiry(0)  # Expire on browser close

                audit_log(request, 'LOGIN', f'Successful login: {user.username}', {'ip': ip})
                messages.success(request, f'Welcome back, {user.first_name or user.username}!')
                return redirect('banking:dashboard')
        else:
            ip = get_client_ip(request)
            username = request.POST.get('username', '')
            audit_log(request, 'LOGIN_FAILED', f'Failed login for: {username}', {'ip': ip})
            messages.error(request, 'Invalid username or password.')
    else:
        form = SecureLoginForm(request)

    return render(request, 'banking/login.html', {'form': form})


# ─── 2FA VERIFICATION ─────────────────────────────────────────────────────────

@never_cache
def two_factor_verify(request):
    user_pk = request.session.get('2fa_user_pk')
    if not user_pk:
        return redirect('banking:login')

    user = get_object_or_404(User, pk=user_pk)

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code', '').strip()
        verified = False

        # Try TOTP first (Google Authenticator)
        if user.totp_secret and verify_totp(user, otp_code):
            verified = True
        # Then try email OTP
        elif verify_otp(user, otp_code, 'LOGIN'):
            verified = True

        if verified:
            request.session.pop('2fa_user_pk', None)
            login(request, user, backend='django.contrib.auth.backends.ModelBackend')
            user.last_login_ip = get_client_ip(request)
            user.save(update_fields=['last_login_ip'])
            request.session['last_activity'] = timezone.now().timestamp()
            audit_log(request, 'OTP_VERIFIED', f'2FA verified for {user.username}')
            messages.success(request, f'Welcome back, {user.first_name or user.username}!')
            return redirect('banking:dashboard')
        else:
            messages.error(request, 'Invalid verification code. Please try again.')

    masked = mask_phone(user.phone) if user.phone else ''
    return render(request, 'banking/two_factor.html', {
        'masked_email': user.email[:3] + '***@' + user.email.split('@')[1],
        'masked_phone': masked,
        'has_totp': bool(user.totp_secret),
    })


# ─── LOGOUT ───────────────────────────────────────────────────────────────────

@login_required
def user_logout(request):
    audit_log(request, 'LOGOUT', f'User logged out: {request.user.username}')
    logout(request)
    messages.info(request, 'You have been securely logged out.')
    return redirect('banking:login')


# ─── DASHBOARD ────────────────────────────────────────────────────────────────

@login_required
@never_cache
def dashboard(request):
    user = request.user
    accounts = Account.objects.filter(user=user, status='ACTIVE')
    primary_account = get_user_primary_account(user)

    recent_transactions = []
    total_balance = Decimal('0.00')

    for acc in accounts:
        total_balance += acc.balance

    if primary_account:
        recent_transactions = Transaction.objects.filter(
            account__user=user
        ).select_related('account').order_by('-created_at')[:10]

    # Stats
    today = timezone.now().date()
    today_spent = Transaction.objects.filter(
        account__user=user,
        created_at__date=today,
        transaction_type__in=['WITHDRAWAL', 'TRANSFER_OUT', 'BILL_PAYMENT',
                               'RECHARGE', 'CARD_PAYMENT', 'DONATION'],
        status='COMPLETED',
    ).aggregate(t=Sum('amount'))['t'] or Decimal('0')

    context = {
        'accounts': accounts,
        'primary_account': primary_account,
        'total_balance': total_balance,
        'recent_transactions': recent_transactions,
        'today_spent': today_spent,
        'active_loans': LoanApplication.objects.filter(
            user=user, status__in=['APPROVED', 'DISBURSED']).count(),
        'active_savings': SavingsPlan.objects.filter(
            account__user=user, status='ACTIVE').count(),
    }
    return render(request, 'banking/dashboard.html', context)


# ─── TRANSACTION HISTORY ──────────────────────────────────────────────────────

@login_required
def transaction_history(request):
    transactions = Transaction.objects.filter(
        account__user=request.user
    ).select_related('account').order_by('-created_at')

    # Filters
    t_type = request.GET.get('type')
    status = request.GET.get('status')
    date_from = request.GET.get('from')
    date_to = request.GET.get('to')

    if t_type:
        transactions = transactions.filter(transaction_type=t_type)
    if status:
        transactions = transactions.filter(status=status)
    if date_from:
        transactions = transactions.filter(created_at__date__gte=date_from)
    if date_to:
        transactions = transactions.filter(created_at__date__lte=date_to)

    paginator = Paginator(transactions, 20)
    page = paginator.get_page(request.GET.get('page', 1))

    return render(request, 'banking/transaction_history.html', {
        'page_obj': page,
        'transaction_types': Transaction.TRANSACTION_TYPES,
    })


# ─── DEPOSIT ──────────────────────────────────────────────────────────────────

@login_required
@never_cache
def deposit(request):
    if request.method == 'POST':
        form = DepositForm(request.user, request.POST)
        if form.is_valid():
            account = form.cleaned_data['account']
            amount = form.cleaned_data['amount']
            payment_method = form.cleaned_data['payment_method']
            note = form.cleaned_data.get('note', '')

            # Card validation
            if payment_method == 'CARD':
                card_num = form.cleaned_data.get('card_number', '').replace(' ', '')
                if not luhn_check(card_num):
                    messages.error(request, 'Invalid card number. Please check and try again.')
                    return render(request, 'banking/deposit.html', {'form': form})

                expiry = form.cleaned_data.get('card_expiry', '')
                try:
                    exp_month, exp_year = [int(x) for x in expiry.split('/')]
                    exp_year += 2000
                    now = timezone.now()
                    if exp_year < now.year or (exp_year == now.year and exp_month < now.month):
                        messages.error(request, 'Card has expired.')
                        return render(request, 'banking/deposit.html', {'form': form})
                except (ValueError, AttributeError):
                    messages.error(request, 'Invalid expiry date format.')
                    return render(request, 'banking/deposit.html', {'form': form})

            # Store pending transaction in session, send OTP
            request.session['pending_deposit'] = {
                'account_id': account.id,
                'amount': str(amount),
                'payment_method': payment_method,
                'note': note,
            }
            otp_obj = send_otp(request.user, 'TRANSACTION', 'EMAIL')
            audit_log(request, 'OTP_SENT', f'OTP sent for deposit ৳{amount}',
                      {'account': account.account_number, 'amount': str(amount)})
            messages.info(request, f'OTP sent to {request.user.email[:3]}***. Enter it to confirm deposit.')
            return redirect('banking:confirm_transaction', transaction_type='deposit')

    else:
        form = DepositForm(request.user)

    return render(request, 'banking/deposit.html', {'form': form})


# ─── WITHDRAW ─────────────────────────────────────────────────────────────────

@login_required
@never_cache
def withdraw(request):
    if request.method == 'POST':
        form = WithdrawForm(request.user, request.POST)
        if form.is_valid():
            account = form.cleaned_data['account']
            amount = form.cleaned_data['amount']

            # Check balance
            if not account.can_debit(amount):
                messages.error(request, f'Insufficient balance. Available: ৳{account.balance:,.2f}')
                return render(request, 'banking/withdraw.html', {'form': form})

            # Check transaction limits
            ok, reason = check_transaction_limits(account, float(amount))
            if not ok:
                messages.error(request, reason)
                return render(request, 'banking/withdraw.html', {'form': form})

            request.session['pending_withdraw'] = {
                'account_id': account.id,
                'amount': str(amount),
                'method': form.cleaned_data['withdrawal_method'],
                'note': form.cleaned_data.get('note', ''),
            }
            send_otp(request.user, 'TRANSACTION', 'EMAIL')
            messages.info(request, 'OTP sent to your email. Confirm to proceed.')
            return redirect('banking:confirm_transaction', transaction_type='withdraw')
    else:
        form = WithdrawForm(request.user)

    return render(request, 'banking/withdraw.html', {'form': form})


# ─── PAYMENT (Transfer / Card) ────────────────────────────────────────────────

@login_required
@never_cache
def payment(request):
    if request.method == 'POST':
        form = CardPaymentForm(request.user, request.POST)
        if form.is_valid():
            account = form.cleaned_data['from_account']
            amount = form.cleaned_data['amount']
            recipient_type = form.cleaned_data['recipient_type']

            # Card validation
            if recipient_type == 'CARD':
                card_num = form.cleaned_data.get('card_number', '').replace(' ', '')
                if not luhn_check(card_num):
                    messages.error(request, 'Invalid recipient card number.')
                    return render(request, 'banking/payment.html', {'form': form})

                expiry = form.cleaned_data.get('expiry_date', '')
                try:
                    exp_month, exp_year = [int(x) for x in expiry.split('/')]
                    exp_year += 2000
                    now = timezone.now()
                    if exp_year < now.year or (exp_year == now.year and exp_month < now.month):
                        messages.error(request, 'Recipient card has expired.')
                        return render(request, 'banking/payment.html', {'form': form})
                except Exception:
                    messages.error(request, 'Invalid expiry format. Use MM/YY.')
                    return render(request, 'banking/payment.html', {'form': form})

            if not account.can_debit(amount):
                messages.error(request, f'Insufficient balance. Available: ৳{account.balance:,.2f}')
                return render(request, 'banking/payment.html', {'form': form})

            ok, reason = check_transaction_limits(account, float(amount))
            if not ok:
                messages.error(request, reason)
                return render(request, 'banking/payment.html', {'form': form})

            request.session['pending_payment'] = {
                'account_id': account.id,
                'amount': str(amount),
                'recipient_type': recipient_type,
                'recipient_account': form.cleaned_data.get('recipient_account', ''),
                'recipient_name': form.cleaned_data.get('recipient_name', '') or form.cleaned_data.get('cardholder_name', ''),
                'recipient_bank': form.cleaned_data.get('recipient_bank', ''),
                'note': form.cleaned_data.get('note', ''),
            }
            send_otp(request.user, 'TRANSACTION', 'EMAIL')
            messages.info(request, 'OTP sent to your email to authorize this payment.')
            return redirect('banking:confirm_transaction', transaction_type='payment')
    else:
        form = CardPaymentForm(request.user)

    return render(request, 'banking/payment.html', {'form': form})


# ─── OTP CONFIRM TRANSACTION ──────────────────────────────────────────────────

@login_required
@never_cache
def confirm_transaction(request, transaction_type):
    """OTP confirmation page for all financial transactions."""
    session_key = f'pending_{transaction_type}'
    pending = request.session.get(session_key)

    if not pending:
        messages.error(request, 'No pending transaction found.')
        return redirect('banking:dashboard')

    if request.method == 'POST':
        otp_code = request.POST.get('otp_code', '').strip()

        # Verify OTP (email) or TOTP
        verified = False
        if request.user.two_factor_enabled and request.user.totp_secret:
            if verify_totp(request.user, otp_code):
                verified = True
        if not verified:
            verified = verify_otp(request.user, otp_code, 'TRANSACTION')

        if not verified:
            messages.error(request, 'Invalid or expired OTP. Please try again.')
            return render(request, 'banking/confirm_otp.html', {
                'transaction_type': transaction_type,
                'amount': pending.get('amount'),
            })

        # Execute the transaction
        try:
            result = _execute_transaction(request, transaction_type, pending)
            request.session.pop(session_key, None)
            messages.success(request, result['message'])
            audit_log(request, 'TRANSACTION', result['description'],
                      {'ref': result.get('ref', ''), 'amount': pending.get('amount')})
            return redirect('banking:dashboard')
        except Exception as e:
            logger.error(f"Transaction execution error: {e}")
            messages.error(request, f'Transaction failed: {str(e)}')

    return render(request, 'banking/confirm_otp.html', {
        'transaction_type': transaction_type,
        'amount': pending.get('amount'),
        'has_totp': bool(request.user.totp_secret and request.user.two_factor_enabled),
    })


def _execute_transaction(request, transaction_type, pending):
    """Execute a validated, OTP-confirmed transaction atomically."""
    with db_transaction.atomic():
        account = Account.objects.select_for_update().get(pk=pending['account_id'])
        amount = Decimal(pending['amount'])
        ip = get_client_ip(request)

        if transaction_type == 'deposit':
            balance_before = account.balance
            account.balance += amount
            account.save()
            txn = Transaction.objects.create(
                account=account,
                transaction_type='DEPOSIT',
                amount=amount,
                balance_before=balance_before,
                balance_after=account.balance,
                payment_method=pending.get('payment_method', 'ACCOUNT'),
                description=f"Deposit via {pending.get('payment_method', 'unknown')}",
                note=pending.get('note', ''),
                ip_address=ip,
                status='COMPLETED',
                completed_at=timezone.now(),
            )
            return {
                'message': f'৳{amount:,.2f} deposited successfully! Ref: {txn.reference_number}',
                'description': f'Deposit ৳{amount} to {account.account_number}',
                'ref': txn.reference_number,
            }

        elif transaction_type == 'withdraw':
            if not account.can_debit(amount):
                raise ValueError('Insufficient balance')
            balance_before = account.balance
            account.balance -= amount
            account.save()
            txn = Transaction.objects.create(
                account=account,
                transaction_type='WITHDRAWAL',
                amount=amount,
                balance_before=balance_before,
                balance_after=account.balance,
                description=f"Withdrawal via {pending.get('method', 'branch')}",
                note=pending.get('note', ''),
                ip_address=ip,
                status='COMPLETED',
                completed_at=timezone.now(),
            )
            return {
                'message': f'৳{amount:,.2f} withdrawn successfully! Ref: {txn.reference_number}',
                'description': f'Withdrawal ৳{amount} from {account.account_number}',
                'ref': txn.reference_number,
            }

        elif transaction_type == 'payment':
            if not account.can_debit(amount):
                raise ValueError('Insufficient balance')
            balance_before = account.balance
            account.balance -= amount
            account.save()
            txn = Transaction.objects.create(
                account=account,
                transaction_type='TRANSFER_OUT',
                amount=amount,
                balance_before=balance_before,
                balance_after=account.balance,
                recipient_account_number=pending.get('recipient_account', ''),
                recipient_name=pending.get('recipient_name', ''),
                recipient_bank=pending.get('recipient_bank', ''),
                payment_method='CARD' if pending.get('recipient_type') == 'CARD' else 'BANK_TRANSFER',
                description=f"Payment to {pending.get('recipient_name', 'N/A')}",
                note=pending.get('note', ''),
                ip_address=ip,
                status='COMPLETED',
                completed_at=timezone.now(),
            )
            # Credit recipient if internal account
            try:
                recipient_acc = Account.objects.get(
                    account_number=pending.get('recipient_account', ''),
                    status='ACTIVE'
                )
                rb = recipient_acc.balance
                recipient_acc.balance += amount
                recipient_acc.save()
                Transaction.objects.create(
                    account=recipient_acc,
                    transaction_type='TRANSFER_IN',
                    amount=amount,
                    balance_before=rb,
                    balance_after=recipient_acc.balance,
                    recipient_name=request.user.get_full_name(),
                    description=f"Transfer received from {account.account_number}",
                    ip_address=ip,
                    status='COMPLETED',
                    completed_at=timezone.now(),
                )
            except Account.DoesNotExist:
                pass  # External transfer — no internal credit
            return {
                'message': f'৳{amount:,.2f} paid successfully! Ref: {txn.reference_number}',
                'description': f'Payment ৳{amount} from {account.account_number}',
                'ref': txn.reference_number,
            }

        elif transaction_type == 'billpayment':
            if not account.can_debit(amount):
                raise ValueError('Insufficient balance')
            balance_before = account.balance
            account.balance -= amount
            account.save()
            txn = Transaction.objects.create(
                account=account,
                transaction_type='BILL_PAYMENT',
                amount=amount,
                balance_before=balance_before,
                balance_after=account.balance,
                description=f"Bill payment: {pending.get('biller_name', '')}",
                note=pending.get('consumer_id', ''),
                ip_address=ip,
                status='COMPLETED',
                completed_at=timezone.now(),
            )
            BillPayment.objects.create(
                account=account,
                biller_type=pending.get('biller_type', 'OTHER'),
                biller_name=pending.get('biller_name', ''),
                consumer_id=pending.get('consumer_id', ''),
                amount=amount,
                transaction=txn,
                billing_month=pending.get('billing_month', ''),
            )
            return {
                'message': f'Bill paid! ৳{amount:,.2f} to {pending.get("biller_name")}. Ref: {txn.reference_number}',
                'description': f'Bill payment ৳{amount} - {pending.get("biller_name")}',
                'ref': txn.reference_number,
            }

        elif transaction_type == 'recharge':
            if not account.can_debit(amount):
                raise ValueError('Insufficient balance')
            balance_before = account.balance
            account.balance -= amount
            account.save()
            txn = Transaction.objects.create(
                account=account,
                transaction_type='RECHARGE',
                amount=amount,
                balance_before=balance_before,
                balance_after=account.balance,
                description=f"Recharge {pending.get('mobile_number')} - {pending.get('operator')}",
                ip_address=ip,
                status='COMPLETED',
                completed_at=timezone.now(),
            )
            MobileRecharge.objects.create(
                account=account,
                mobile_number=pending.get('mobile_number', ''),
                operator=pending.get('operator', ''),
                recharge_type=pending.get('recharge_type', 'PREPAID'),
                amount=amount,
                transaction=txn,
            )
            return {
                'message': f'৳{amount:,.2f} recharged to {pending.get("mobile_number")}! Ref: {txn.reference_number}',
                'description': f'Recharge {pending.get("mobile_number")} ৳{amount}',
                'ref': txn.reference_number,
            }

        elif transaction_type == 'donation':
            if not account.can_debit(amount):
                raise ValueError('Insufficient balance')
            balance_before = account.balance
            account.balance -= amount
            account.save()
            txn = Transaction.objects.create(
                account=account,
                transaction_type='DONATION',
                amount=amount,
                balance_before=balance_before,
                balance_after=account.balance,
                description=f"Donation to {pending.get('organization_name', '')}",
                ip_address=ip,
                status='COMPLETED',
                completed_at=timezone.now(),
            )
            Donation.objects.create(
                account=account,
                organization_name=pending.get('organization_name', ''),
                organization_type=pending.get('organization_type', ''),
                amount=amount,
                message=pending.get('message', ''),
                is_anonymous=pending.get('is_anonymous', False),
                transaction=txn,
            )
            return {
                'message': f'Thank you! ৳{amount:,.2f} donated to {pending.get("organization_name")}. Ref: {txn.reference_number}',
                'description': f'Donation ৳{amount} to {pending.get("organization_name")}',
                'ref': txn.reference_number,
            }

        else:
            raise ValueError(f'Unknown transaction type: {transaction_type}')


# ─── BILL PAYMENT ─────────────────────────────────────────────────────────────

@login_required
@never_cache
def bill_payment(request):
    if request.method == 'POST':
        form = BillPaymentForm(request.user, request.POST)
        if form.is_valid():
            account = form.cleaned_data['account']
            amount = form.cleaned_data['amount']
            if not account.can_debit(amount):
                messages.error(request, f'Insufficient balance. Available: ৳{account.balance:,.2f}')
                return render(request, 'banking/billpayment.html', {'form': form})
            ok, reason = check_transaction_limits(account, float(amount))
            if not ok:
                messages.error(request, reason)
                return render(request, 'banking/billpayment.html', {'form': form})
            request.session['pending_billpayment'] = {
                'account_id': account.id,
                'amount': str(amount),
                'biller_type': form.cleaned_data['biller_type'],
                'biller_name': form.cleaned_data['biller_name'],
                'consumer_id': form.cleaned_data['consumer_id'],
                'billing_month': form.cleaned_data.get('billing_month', ''),
            }
            send_otp(request.user, 'TRANSACTION', 'EMAIL')
            messages.info(request, 'OTP sent to confirm bill payment.')
            return redirect('banking:confirm_transaction', transaction_type='billpayment')
    else:
        form = BillPaymentForm(request.user)
    return render(request, 'banking/billpayment.html', {'form': form})


# ─── MOBILE RECHARGE ──────────────────────────────────────────────────────────

@login_required
@never_cache
def recharge(request):
    if request.method == 'POST':
        form = RechargeForm(request.user, request.POST)
        if form.is_valid():
            account = form.cleaned_data['account']
            amount = form.cleaned_data['amount']
            if not account.can_debit(amount):
                messages.error(request, f'Insufficient balance.')
                return render(request, 'banking/recharge.html', {'form': form})
            request.session['pending_recharge'] = {
                'account_id': account.id,
                'amount': str(amount),
                'mobile_number': form.cleaned_data['mobile_number'],
                'operator': form.cleaned_data['operator'],
                'recharge_type': form.cleaned_data['recharge_type'],
            }
            send_otp(request.user, 'TRANSACTION', 'EMAIL')
            messages.info(request, 'OTP sent to confirm recharge.')
            return redirect('banking:confirm_transaction', transaction_type='recharge')
    else:
        form = RechargeForm(request.user)
    return render(request, 'banking/recharge.html', {'form': form})


# ─── DONATION ─────────────────────────────────────────────────────────────────

@login_required
@never_cache
def donation(request):
    if request.method == 'POST':
        form = DonationForm(request.user, request.POST)
        if form.is_valid():
            account = form.cleaned_data['account']
            amount = form.cleaned_data['amount']
            if not account.can_debit(amount):
                messages.error(request, 'Insufficient balance.')
                return render(request, 'banking/donation.html', {'form': form})
            request.session['pending_donation'] = {
                'account_id': account.id,
                'amount': str(amount),
                'organization_name': form.cleaned_data['organization_name'],
                'organization_type': form.cleaned_data.get('organization_type', ''),
                'message': form.cleaned_data.get('message', ''),
                'is_anonymous': form.cleaned_data.get('is_anonymous', False),
            }
            send_otp(request.user, 'TRANSACTION', 'EMAIL')
            messages.info(request, 'OTP sent to confirm donation.')
            return redirect('banking:confirm_transaction', transaction_type='donation')
    else:
        form = DonationForm(request.user)
    return render(request, 'banking/donation.html', {'form': form})


# ─── LOAN ─────────────────────────────────────────────────────────────────────

@login_required
@never_cache
def loan(request):
    user_loans = LoanApplication.objects.filter(user=request.user).order_by('-applied_at')

    if request.method == 'POST':
        form = LoanApplicationForm(request.POST)
        if form.is_valid():
            primary_account = get_user_primary_account(request.user)
            if not primary_account:
                messages.error(request, 'You need an active account to apply for a loan.')
                return render(request, 'banking/loan.html', {'form': form, 'loans': user_loans})

            loan_app = form.save(commit=False)
            loan_app.user = request.user
            loan_app.account = primary_account
            loan_app.status = 'SUBMITTED'
            loan_app.save()

            audit_log(request, 'ACCOUNT_ACTION',
                      f'Loan application submitted: ৳{loan_app.requested_amount}',
                      {'loan_type': loan_app.loan_type, 'amount': str(loan_app.requested_amount)})
            messages.success(request,
                f'Loan application submitted! ID: {str(loan_app.application_id)[:8].upper()}. '
                'We will review within 2-3 business days.')
            return redirect('banking:loan')
    else:
        form = LoanApplicationForm()

    return render(request, 'banking/loan.html', {'form': form, 'loans': user_loans})


# ─── SAVINGS ──────────────────────────────────────────────────────────────────

@login_required
@never_cache
def savings(request):
    user_plans = SavingsPlan.objects.filter(
        account__user=request.user
    ).select_related('account').order_by('-created_at')

    INTEREST_RATES = {'FD': Decimal('7.50'), 'RD': Decimal('6.50'), 'DPS': Decimal('8.00')}

    if request.method == 'POST':
        form = SavingsPlanForm(request.POST)
        if form.is_valid():
            primary_account = get_user_primary_account(request.user)
            if not primary_account:
                messages.error(request, 'You need an active account.')
                return render(request, 'banking/savings.html', {'form': form, 'plans': user_plans})

            amount = form.cleaned_data['principal_amount']
            if primary_account.balance < amount:
                messages.error(request, f'Insufficient balance. Available: ৳{primary_account.balance:,.2f}')
                return render(request, 'banking/savings.html', {'form': form, 'plans': user_plans})

            plan_type = form.cleaned_data['plan_type']
            tenure = form.cleaned_data['tenure_months']
            rate = INTEREST_RATES.get(plan_type, Decimal('6.00'))
            start = timezone.now().date()
            maturity = start.replace(month=start.month + tenure % 12,
                                     year=start.year + tenure // 12) if tenure < 12 else \
                       start.replace(year=start.year + tenure // 12)

            # Simple interest maturity
            maturity_amount = amount * (1 + rate / 100 * tenure / 12)

            with db_transaction.atomic():
                acc = Account.objects.select_for_update().get(pk=primary_account.pk)
                bal_before = acc.balance
                acc.balance -= amount
                acc.save()

                plan = form.save(commit=False)
                plan.account = acc
                plan.interest_rate = rate
                plan.start_date = start
                plan.maturity_date = maturity
                plan.maturity_amount = maturity_amount
                plan.save()

                Transaction.objects.create(
                    account=acc,
                    transaction_type='CHARGE',
                    amount=amount,
                    balance_before=bal_before,
                    balance_after=acc.balance,
                    description=f'{plan_type} plan created - {tenure} months',
                    status='COMPLETED',
                    completed_at=timezone.now(),
                )

            messages.success(request,
                f'{plan_type} plan created! ৳{amount:,.2f} invested at {rate}% p.a. '
                f'Matures on {maturity}.')
            return redirect('banking:savings')
    else:
        form = SavingsPlanForm()

    return render(request, 'banking/savings.html', {
        'form': form, 'plans': user_plans,
        'interest_rates': INTEREST_RATES,
    })


# ─── 2FA SETUP ────────────────────────────────────────────────────────────────

@login_required
def setup_2fa(request):
    user = request.user

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'enable_totp':
            secret = request.session.get('totp_setup_secret')
            if not secret:
                secret = generate_totp_secret()
                request.session['totp_setup_secret'] = secret

            form = TOTPSetupForm(request.POST)
            if form.is_valid():
                token = form.cleaned_data['token']
                import pyotp
                totp = pyotp.TOTP(secret)
                if totp.verify(token, valid_window=1):
                    user.totp_secret = secret
                    user.two_factor_enabled = True
                    user.save()
                    request.session.pop('totp_setup_secret', None)
                    audit_log(request, 'ACCOUNT_ACTION', 'TOTP 2FA enabled')
                    messages.success(request, '✅ Google Authenticator 2FA enabled successfully!')
                    return redirect('banking:profile')
                else:
                    messages.error(request, 'Invalid token. Please scan the QR code again.')

        elif action == 'enable_email':
            user.two_factor_enabled = True
            user.totp_secret = ''
            user.save()
            audit_log(request, 'ACCOUNT_ACTION', 'Email OTP 2FA enabled')
            messages.success(request, '✅ Email OTP 2FA enabled!')
            return redirect('banking:profile')

        elif action == 'disable_2fa':
            otp_code = request.POST.get('otp_code', '')
            if verify_otp(user, otp_code, 'TRANSACTION') or verify_totp(user, otp_code):
                user.two_factor_enabled = False
                user.totp_secret = ''
                user.save()
                audit_log(request, 'ACCOUNT_ACTION', '2FA disabled')
                messages.success(request, '2FA has been disabled.')
                return redirect('banking:profile')
            else:
                messages.error(request, 'Invalid OTP. 2FA not disabled.')

    # Generate TOTP secret + QR for setup
    secret = request.session.get('totp_setup_secret') or generate_totp_secret()
    request.session['totp_setup_secret'] = secret
    qr_b64 = get_totp_qr_base64(user, secret)
    form = TOTPSetupForm()

    return render(request, 'banking/setup_2fa.html', {
        'form': form,
        'qr_code': qr_b64,
        'totp_secret': secret,
        'user': user,
    })


# ─── PROFILE ──────────────────────────────────────────────────────────────────

@login_required
def profile(request):
    user = request.user
    accounts = Account.objects.filter(user=user)
    cards = Card.objects.filter(account__user=user)

    if request.method == 'POST':
        action = request.POST.get('action')

        if action == 'change_password':
            form = ChangePasswordForm(request.POST)
            if form.is_valid():
                if user.check_password(form.cleaned_data['current_password']):
                    user.set_password(form.cleaned_data['new_password'])
                    user.save()
                    update_session_auth_hash(request, user)
                    audit_log(request, 'PASSWORD_CHANGE', 'Password changed successfully')
                    messages.success(request, 'Password changed successfully.')
                else:
                    messages.error(request, 'Current password is incorrect.')

        elif action == 'update_profile':
            user.first_name = request.POST.get('first_name', user.first_name)
            user.last_name = request.POST.get('last_name', user.last_name)
            user.address = request.POST.get('address', user.address)
            user.city = request.POST.get('city', user.city)
            user.save()
            audit_log(request, 'PROFILE_UPDATE', 'Profile updated')
            messages.success(request, 'Profile updated successfully.')

    return render(request, 'banking/profile.html', {
        'user': user,
        'accounts': accounts,
        'cards': cards,
        'password_form': ChangePasswordForm(),
    })


# ─── RESEND OTP ───────────────────────────────────────────────────────────────

@login_required
def resend_otp(request):
    send_otp(request.user, 'TRANSACTION', 'EMAIL')
    messages.info(request, 'A new OTP has been sent to your email.')
    return redirect(request.META.get('HTTP_REFERER', 'banking:dashboard'))


def resend_otp_email(request):
    user_pk = request.session.get('pending_verify_user')
    if user_pk:
        try:
            user = User.objects.get(pk=user_pk)
            send_otp(user, 'EMAIL_VERIFY', 'EMAIL')
            messages.info(request, 'OTP resent to your email.')
        except User.DoesNotExist:
            pass
    return redirect('banking:verify_email')


# ─── LOCKED OUT ───────────────────────────────────────────────────────────────

def locked_out(request):
    return render(request, 'banking/locked_out.html', status=403)


# ─── API: Account Balance (AJAX) ──────────────────────────────────────────────

@login_required
def api_account_balance(request, account_id):
    try:
        account = Account.objects.get(pk=account_id, user=request.user)
        return JsonResponse({
            'balance': str(account.balance),
            'account_number': account.masked_number,
            'currency': account.currency,
        })
    except Account.DoesNotExist:
        return JsonResponse({'error': 'Account not found'}, status=404)
