"""
X Bank — Admin Panel Views
Full CRUD + management for all banking entities.
Staff/superuser access only.
"""
import logging
from decimal import Decimal
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.db.models import Sum, Count, Q
from django.utils import timezone
from django.http import JsonResponse
from django.core.paginator import Paginator
from django.db import transaction as db_transaction
from django.views.decorators.http import require_POST

from .models import (
    User, Account, Card, Transaction, OTPVerification,
    LoanApplication, SavingsPlan, BillPayment, MobileRecharge,
    Donation, AuditLog
)

logger = logging.getLogger('banking')


def is_admin(user):
    return user.is_authenticated and (user.is_staff or user.is_superuser)


admin_required = user_passes_test(is_admin, login_url='/login/')


def admin_context(request):
    """Shared context injected into every admin view."""
    return {
        'pending_loan_count': LoanApplication.objects.filter(status='SUBMITTED').count(),
        'pending_kyc_count': User.objects.filter(is_kyc_verified=False, is_active=True).exclude(
            id_number='').count(),
    }


# ─── DASHBOARD ───────────────────────────────────────────────────────────────

@login_required
@admin_required
def dashboard(request):
    ctx = admin_context(request)

    ctx.update({
        'total_users': User.objects.count(),
        'total_balance': Account.objects.aggregate(t=Sum('balance'))['t'] or Decimal('0'),
        'total_transactions': Transaction.objects.count(),
        'total_loans': LoanApplication.objects.count(),
        'verified_users': User.objects.filter(is_kyc_verified=True).count(),
        'total_savings': SavingsPlan.objects.filter(status='ACTIVE').count(),
        'total_recharges': MobileRecharge.objects.count(),
        'total_donations': Donation.objects.aggregate(t=Sum('amount'))['t'] or Decimal('0'),
        'recent_transactions': Transaction.objects.select_related('account__user').order_by('-created_at')[:10],
        'recent_users': User.objects.order_by('-date_joined')[:8],
        'pending_loans': LoanApplication.objects.filter(status='SUBMITTED').select_related('user').order_by('-applied_at')[:6],
    })
    return render(request, 'admin_panel/dashboard.html', ctx)


# ─── USERS ───────────────────────────────────────────────────────────────────

@login_required
@admin_required
def users(request):
    qs = User.objects.order_by('-date_joined')
    q = request.GET.get('q', '')
    status_filter = request.GET.get('status', '')
    kyc_filter = request.GET.get('kyc', '')

    if q:
        qs = qs.filter(
            Q(username__icontains=q) | Q(email__icontains=q) |
            Q(first_name__icontains=q) | Q(last_name__icontains=q) |
            Q(phone__icontains=q)
        )
    if status_filter == 'active':
        qs = qs.filter(is_active=True)
    elif status_filter == 'inactive':
        qs = qs.filter(is_active=False)
    if kyc_filter == 'verified':
        qs = qs.filter(is_kyc_verified=True)
    elif kyc_filter == 'unverified':
        qs = qs.filter(is_kyc_verified=False)

    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get('page', 1))

    ctx = admin_context(request)
    ctx.update({'page_obj': page, 'q': q, 'status_filter': status_filter, 'kyc_filter': kyc_filter})
    return render(request, 'admin_panel/users.html', ctx)


@login_required
@admin_required
def user_detail(request, user_id):
    u = get_object_or_404(User, pk=user_id)
    accounts = Account.objects.filter(user=u)
    transactions = Transaction.objects.filter(account__user=u).order_by('-created_at')[:20]
    loans = LoanApplication.objects.filter(user=u).order_by('-applied_at')
    audit = AuditLog.objects.filter(user=u).order_by('-created_at')[:30]

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'toggle_active':
            u.is_active = not u.is_active
            u.save()
            messages.success(request, f'User {"activated" if u.is_active else "deactivated"}.')
        elif action == 'verify_kyc':
            u.is_kyc_verified = True
            u.save()
            messages.success(request, 'KYC verified successfully.')
        elif action == 'revoke_kyc':
            u.is_kyc_verified = False
            u.save()
            messages.success(request, 'KYC revoked.')
        elif action == 'make_staff':
            u.is_staff = True
            u.save()
            messages.success(request, 'User promoted to staff.')
        elif action == 'revoke_staff':
            u.is_staff = False
            u.save()
            messages.success(request, 'Staff access revoked.')
        elif action == 'reset_2fa':
            u.two_factor_enabled = False
            u.totp_secret = ''
            u.save()
            messages.success(request, '2FA reset for user.')
        return redirect('admin_panel:user_detail', user_id=user_id)

    ctx = admin_context(request)
    ctx.update({
        'u': u, 'accounts': accounts, 'transactions': transactions,
        'loans': loans, 'audit': audit,
        'total_balance': accounts.aggregate(t=Sum('balance'))['t'] or Decimal('0'),
    })
    return render(request, 'admin_panel/user_detail.html', ctx)


# ─── KYC PENDING ─────────────────────────────────────────────────────────────

@login_required
@admin_required
def kyc_pending(request):
    qs = User.objects.filter(is_kyc_verified=False, is_active=True).exclude(id_number='').order_by('-date_joined')
    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get('page', 1))
    ctx = admin_context(request)
    ctx['page_obj'] = page
    return render(request, 'admin_panel/kyc_pending.html', ctx)


# ─── ACCOUNTS ────────────────────────────────────────────────────────────────

@login_required
@admin_required
def accounts(request):
    qs = Account.objects.select_related('user').order_by('-opened_at')
    q = request.GET.get('q', '')
    status_f = request.GET.get('status', '')
    type_f = request.GET.get('type', '')

    if q:
        qs = qs.filter(
            Q(account_number__icontains=q) | Q(user__username__icontains=q) |
            Q(user__email__icontains=q)
        )
    if status_f:
        qs = qs.filter(status=status_f)
    if type_f:
        qs = qs.filter(account_type=type_f)

    total_balance = qs.aggregate(t=Sum('balance'))['t'] or Decimal('0')
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page', 1))

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'q': q, 'status_f': status_f, 'type_f': type_f,
        'total_balance': total_balance,
        'account_statuses': Account.STATUS_CHOICES,
        'account_types': Account.ACCOUNT_TYPES,
    })
    return render(request, 'admin_panel/accounts.html', ctx)


@login_required
@admin_required
def account_detail(request, account_id):
    acc = get_object_or_404(Account, pk=account_id)
    transactions = Transaction.objects.filter(account=acc).order_by('-created_at')[:30]

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'freeze':
            acc.status = 'FROZEN'
            acc.save()
            messages.success(request, 'Account frozen.')
        elif action == 'activate':
            acc.status = 'ACTIVE'
            acc.save()
            messages.success(request, 'Account activated.')
        elif action == 'close':
            acc.status = 'CLOSED'
            acc.save()
            messages.success(request, 'Account closed.')
        elif action == 'adjust_balance':
            try:
                new_bal = Decimal(request.POST.get('new_balance', acc.balance))
                reason = request.POST.get('reason', 'Admin adjustment')
                with db_transaction.atomic():
                    old_bal = acc.balance
                    acc.balance = new_bal
                    acc.save()
                    diff = new_bal - old_bal
                    txn_type = 'DEPOSIT' if diff >= 0 else 'WITHDRAWAL'
                    Transaction.objects.create(
                        account=acc,
                        transaction_type=txn_type,
                        amount=abs(diff),
                        balance_before=old_bal,
                        balance_after=new_bal,
                        description=f'Admin adjustment: {reason}',
                        status='COMPLETED',
                        completed_at=timezone.now(),
                    )
                messages.success(request, f'Balance adjusted from ৳{old_bal:,.2f} to ৳{new_bal:,.2f}.')
            except Exception as e:
                messages.error(request, f'Error: {e}')
        return redirect('admin_panel:account_detail', account_id=account_id)

    ctx = admin_context(request)
    ctx.update({'acc': acc, 'transactions': transactions})
    return render(request, 'admin_panel/account_detail.html', ctx)


# ─── TRANSACTIONS ────────────────────────────────────────────────────────────

@login_required
@admin_required
def transactions(request):
    qs = Transaction.objects.select_related('account__user').order_by('-created_at')
    q = request.GET.get('q', '')
    status_f = request.GET.get('status', '')
    type_f = request.GET.get('type', '')
    date_from = request.GET.get('from', '')
    date_to = request.GET.get('to', '')

    if q:
        qs = qs.filter(
            Q(reference_number__icontains=q) | Q(account__account_number__icontains=q) |
            Q(recipient_name__icontains=q) | Q(recipient_account_number__icontains=q)
        )
    if status_f:
        qs = qs.filter(status=status_f)
    if type_f:
        qs = qs.filter(transaction_type=type_f)
    if date_from:
        qs = qs.filter(created_at__date__gte=date_from)
    if date_to:
        qs = qs.filter(created_at__date__lte=date_to)

    total_amount = qs.aggregate(t=Sum('amount'))['t'] or Decimal('0')
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page', 1))

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'q': q, 'status_f': status_f, 'type_f': type_f,
        'date_from': date_from, 'date_to': date_to,
        'total_amount': total_amount,
        'transaction_types': Transaction.TRANSACTION_TYPES,
        'status_choices': Transaction.STATUS_CHOICES,
    })
    return render(request, 'admin_panel/transactions.html', ctx)


@login_required
@admin_required
def transaction_detail(request, txn_id):
    txn = get_object_or_404(Transaction, pk=txn_id)

    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'reverse' and txn.status == 'COMPLETED':
            try:
                with db_transaction.atomic():
                    acc = Account.objects.select_for_update().get(pk=txn.account_id)
                    old_bal = acc.balance
                    if txn.transaction_type in ['DEPOSIT', 'TRANSFER_IN', 'INTEREST']:
                        acc.balance -= txn.amount
                    else:
                        acc.balance += txn.amount
                    acc.save()
                    txn.status = 'REVERSED'
                    txn.save()
                    Transaction.objects.create(
                        account=acc,
                        transaction_type='CHARGE',
                        amount=txn.amount,
                        balance_before=old_bal,
                        balance_after=acc.balance,
                        description=f'Reversal of {txn.reference_number}',
                        status='COMPLETED',
                        completed_at=timezone.now(),
                    )
                messages.success(request, f'Transaction {txn.reference_number} reversed.')
            except Exception as e:
                messages.error(request, f'Reversal failed: {e}')
        return redirect('admin_panel:transaction_detail', txn_id=txn_id)

    ctx = admin_context(request)
    ctx['txn'] = txn
    return render(request, 'admin_panel/transaction_detail.html', ctx)


# ─── LOANS ───────────────────────────────────────────────────────────────────

@login_required
@admin_required
def loans(request):
    qs = LoanApplication.objects.select_related('user', 'account').order_by('-applied_at')
    status_f = request.GET.get('status', '')
    type_f = request.GET.get('type', '')
    q = request.GET.get('q', '')

    if status_f:
        qs = qs.filter(status=status_f)
    if type_f:
        qs = qs.filter(loan_type=type_f)
    if q:
        qs = qs.filter(Q(user__username__icontains=q) | Q(user__email__icontains=q))

    paginator = Paginator(qs, 20)
    page = paginator.get_page(request.GET.get('page', 1))

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'q': q, 'status_f': status_f, 'type_f': type_f,
        'loan_statuses': LoanApplication.STATUS_CHOICES,
        'loan_types': LoanApplication.LOAN_TYPES,
        'pending_count': LoanApplication.objects.filter(status='SUBMITTED').count(),
    })
    return render(request, 'admin_panel/loans.html', ctx)


@login_required
@admin_required
def loan_detail(request, loan_id):
    loan = get_object_or_404(LoanApplication, pk=loan_id)

    if request.method == 'POST':
        action = request.POST.get('action')
        now = timezone.now()

        if action == 'approve':
            approved_amount = request.POST.get('approved_amount', loan.requested_amount)
            loan.status = 'APPROVED'
            loan.approved_amount = Decimal(str(approved_amount))
            loan.reviewed_at = now
            loan.monthly_installment = loan.calculate_emi()
            loan.save()
            messages.success(request, f'Loan approved for ৳{loan.approved_amount:,.2f}.')

        elif action == 'reject':
            reason = request.POST.get('rejection_reason', '')
            loan.status = 'REJECTED'
            loan.rejection_reason = reason
            loan.reviewed_at = now
            loan.save()
            messages.success(request, 'Loan application rejected.')

        elif action == 'disburse':
            if loan.status == 'APPROVED':
                try:
                    with db_transaction.atomic():
                        acc = Account.objects.select_for_update().get(pk=loan.account_id)
                        old_bal = acc.balance
                        acc.balance += loan.approved_amount
                        acc.save()
                        Transaction.objects.create(
                            account=acc,
                            transaction_type='LOAN_DISBURSEMENT',
                            amount=loan.approved_amount,
                            balance_before=old_bal,
                            balance_after=acc.balance,
                            description=f'Loan disbursement — {loan.get_loan_type_display()}',
                            status='COMPLETED',
                            completed_at=now,
                        )
                        loan.status = 'DISBURSED'
                        loan.disbursed_at = now
                        loan.save()
                    messages.success(request, f'৳{loan.approved_amount:,.2f} disbursed to {acc.account_number}.')
                except Exception as e:
                    messages.error(request, f'Disbursement failed: {e}')
            else:
                messages.error(request, 'Loan must be APPROVED before disbursement.')

        elif action == 'close':
            loan.status = 'CLOSED'
            loan.save()
            messages.success(request, 'Loan closed.')

        return redirect('admin_panel:loan_detail', loan_id=loan_id)

    ctx = admin_context(request)
    ctx['loan'] = loan
    return render(request, 'admin_panel/loan_detail.html', ctx)


# ─── SAVINGS ─────────────────────────────────────────────────────────────────

@login_required
@admin_required
def savings(request):
    qs = SavingsPlan.objects.select_related('account__user').order_by('-created_at')
    status_f = request.GET.get('status', '')
    type_f = request.GET.get('type', '')
    if status_f:
        qs = qs.filter(status=status_f)
    if type_f:
        qs = qs.filter(plan_type=type_f)

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page', 1))

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'status_f': status_f, 'type_f': type_f,
        'plan_statuses': SavingsPlan.STATUS_CHOICES,
        'plan_types': SavingsPlan.PLAN_TYPES,
        'total_invested': qs.aggregate(t=Sum('principal_amount'))['t'] or Decimal('0'),
    })
    return render(request, 'admin_panel/savings.html', ctx)


# ─── CARDS ───────────────────────────────────────────────────────────────────

@login_required
@admin_required
def cards(request):
    qs = Card.objects.select_related('account__user').order_by('-issued_at')
    status_f = request.GET.get('status', '')
    q = request.GET.get('q', '')

    if status_f:
        qs = qs.filter(status=status_f)
    if q:
        qs = qs.filter(
            Q(cardholder_name__icontains=q) | Q(account__account_number__icontains=q)
        )

    if request.method == 'POST':
        card_id = request.POST.get('card_id')
        action = request.POST.get('action')
        card = get_object_or_404(Card, pk=card_id)
        if action == 'block':
            card.status = 'BLOCKED'
            card.save()
            messages.success(request, 'Card blocked.')
        elif action == 'activate':
            card.status = 'ACTIVE'
            card.save()
            messages.success(request, 'Card activated.')
        return redirect('admin_panel:cards')

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page', 1))

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'status_f': status_f, 'q': q,
        'card_statuses': Card.STATUS_CHOICES,
    })
    return render(request, 'admin_panel/cards.html', ctx)


# ─── BILL PAYMENTS ───────────────────────────────────────────────────────────

@login_required
@admin_required
def bill_payments(request):
    qs = BillPayment.objects.select_related('account__user').order_by('-paid_at')
    type_f = request.GET.get('type', '')
    q = request.GET.get('q', '')
    if type_f:
        qs = qs.filter(biller_type=type_f)
    if q:
        qs = qs.filter(Q(biller_name__icontains=q) | Q(consumer_id__icontains=q))

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page', 1))
    total = qs.aggregate(t=Sum('amount'))['t'] or Decimal('0')

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'type_f': type_f, 'q': q, 'total': total,
        'biller_types': BillPayment.BILLER_TYPES,
    })
    return render(request, 'admin_panel/bill_payments.html', ctx)


# ─── MOBILE RECHARGES ────────────────────────────────────────────────────────

@login_required
@admin_required
def recharges(request):
    qs = MobileRecharge.objects.select_related('account__user').order_by('-recharged_at')
    op_f = request.GET.get('operator', '')
    q = request.GET.get('q', '')
    if op_f:
        qs = qs.filter(operator=op_f)
    if q:
        qs = qs.filter(mobile_number__icontains=q)

    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page', 1))
    total = qs.aggregate(t=Sum('amount'))['t'] or Decimal('0')

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'op_f': op_f, 'q': q, 'total': total,
        'operators': MobileRecharge.OPERATOR_CHOICES,
    })
    return render(request, 'admin_panel/recharges.html', ctx)


# ─── DONATIONS ───────────────────────────────────────────────────────────────

@login_required
@admin_required
def donations(request):
    qs = Donation.objects.select_related('account__user').order_by('-donated_at')
    paginator = Paginator(qs, 25)
    page = paginator.get_page(request.GET.get('page', 1))
    total = qs.aggregate(t=Sum('amount'))['t'] or Decimal('0')

    ctx = admin_context(request)
    ctx.update({'page_obj': page, 'total': total})
    return render(request, 'admin_panel/donations.html', ctx)


# ─── AUDIT LOGS ──────────────────────────────────────────────────────────────

@login_required
@admin_required
def audit_logs(request):
    qs = AuditLog.objects.select_related('user').order_by('-created_at')
    action_f = request.GET.get('action', '')
    q = request.GET.get('q', '')
    if action_f:
        qs = qs.filter(action=action_f)
    if q:
        qs = qs.filter(
            Q(user__username__icontains=q) | Q(ip_address__icontains=q) |
            Q(description__icontains=q)
        )

    paginator = Paginator(qs, 30)
    page = paginator.get_page(request.GET.get('page', 1))

    ctx = admin_context(request)
    ctx.update({
        'page_obj': page, 'action_f': action_f, 'q': q,
        'action_types': AuditLog.ACTION_TYPES,
    })
    return render(request, 'admin_panel/audit_logs.html', ctx)
