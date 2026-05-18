"""
X Bank - Database Models
Covers: Users, Accounts, Transactions, Cards, OTP, Loans, Savings, Bills, Donations
"""
import uuid
import random
import string
from decimal import Decimal
from django.db import models
from django.contrib.auth.models import AbstractUser
from django.utils import timezone
from django.core.validators import MinValueValidator, RegexValidator


def generate_account_number():
    """Generate a unique 10-digit account number."""
    return ''.join([str(random.randint(0, 9)) for _ in range(10)])


def generate_card_number():
    """Generate a 16-digit card number (Luhn compliant format)."""
    prefix = '4'  # Visa-like
    body = ''.join([str(random.randint(0, 9)) for _ in range(14)])
    return prefix + body + str(random.randint(0, 9))


def generate_otp():
    """Generate a 6-digit OTP."""
    return ''.join([str(random.randint(0, 9)) for _ in range(6)])


class User(AbstractUser):
    """Extended User model for banking customers."""
    
    GENDER_CHOICES = [('M', 'Male'), ('F', 'Female'), ('O', 'Other')]
    ID_TYPE_CHOICES = [
        ('NID', 'National ID'),
        ('PASSPORT', 'Passport'),
        ('DRIVING', 'Driving License'),
    ]

    # Personal info
    phone = models.CharField(max_length=14, unique=True, null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    gender = models.CharField(max_length=1, choices=GENDER_CHOICES, blank=True)
    address = models.TextField(blank=True)
    city = models.CharField(max_length=100, blank=True)
    postal_code = models.CharField(max_length=20, blank=True)
    country = models.CharField(max_length=100, default='Bangladesh')
    profile_photo = models.ImageField(upload_to='profiles/', null=True, blank=True)

    # Identity verification
    id_type = models.CharField(max_length=20, choices=ID_TYPE_CHOICES, blank=True)
    id_number = models.CharField(max_length=50, blank=True)
    id_document = models.FileField(upload_to='kyc/', null=True, blank=True)

    # Security
    is_email_verified = models.BooleanField(default=False)
    is_phone_verified = models.BooleanField(default=False)
    is_kyc_verified = models.BooleanField(default=False)
    two_factor_enabled = models.BooleanField(default=False)
    totp_secret = models.CharField(max_length=64, blank=True)  # For TOTP 2FA

    # Tracking
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    failed_login_attempts = models.PositiveIntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'

    def __str__(self):
        return f"{self.get_full_name()} ({self.username})"

    @property
    def full_name(self):
        return self.get_full_name() or self.username


class Account(models.Model):
    """Bank account for a user."""

    ACCOUNT_TYPES = [
        ('SAVINGS', 'Savings Account'),
        ('CURRENT', 'Current Account'),
        ('SALARY', 'Salary Account'),
        ('STUDENT', 'Student Account'),
    ]
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('FROZEN', 'Frozen'),
        ('CLOSED', 'Closed'),
        ('PENDING', 'Pending Activation'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='accounts')
    account_number = models.CharField(max_length=20, unique=True, default=generate_account_number)
    account_type = models.CharField(max_length=20, choices=ACCOUNT_TYPES, default='SAVINGS')
    balance = models.DecimalField(max_digits=15, decimal_places=2, default=Decimal('0.00'),
                                  validators=[MinValueValidator(Decimal('0.00'))])
    currency = models.CharField(max_length=3, default='BDT')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('4.50'))
    overdraft_limit = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal('0.00'))
    is_primary = models.BooleanField(default=False)
    opened_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'accounts'
        ordering = ['-opened_at']

    def __str__(self):
        return f"{self.account_number} ({self.account_type}) - {self.user.username}"

    @property
    def masked_number(self):
        return f"****{self.account_number[-4:]}"

    def can_debit(self, amount):
        return self.balance + self.overdraft_limit >= Decimal(str(amount))


class Card(models.Model):
    """Debit/Credit card linked to an account."""

    CARD_TYPES = [('DEBIT', 'Debit Card'), ('CREDIT', 'Credit Card'), ('PREPAID', 'Prepaid Card')]
    NETWORK_CHOICES = [('VISA', 'Visa'), ('MASTERCARD', 'Mastercard'), ('AMEX', 'American Express')]
    STATUS_CHOICES = [('ACTIVE', 'Active'), ('BLOCKED', 'Blocked'), ('EXPIRED', 'Expired')]

    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='cards')
    card_number = models.CharField(max_length=19, unique=True, default=generate_card_number)
    card_type = models.CharField(max_length=10, choices=CARD_TYPES, default='DEBIT')
    network = models.CharField(max_length=20, choices=NETWORK_CHOICES, default='VISA')
    cardholder_name = models.CharField(max_length=100)
    expiry_month = models.PositiveSmallIntegerField()
    expiry_year = models.PositiveSmallIntegerField()
    cvv_hash = models.CharField(max_length=256)  # Store hashed CVV only
    credit_limit = models.DecimalField(max_digits=12, decimal_places=2, default=Decimal('0.00'))
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    daily_limit = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('50000.00'))
    issued_at = models.DateTimeField(auto_now_add=True)
    pin_hash = models.CharField(max_length=256, blank=True)  # Hashed PIN

    class Meta:
        db_table = 'cards'

    def __str__(self):
        return f"**** **** **** {self.card_number[-4:]} ({self.card_type})"

    @property
    def masked_number(self):
        n = self.card_number.replace(' ', '')
        return f"{n[:4]} **** **** {n[-4:]}"

    @property
    def expiry_display(self):
        return f"{self.expiry_month:02d}/{str(self.expiry_year)[-2:]}"

    @property
    def is_expired(self):
        now = timezone.now()
        return (now.year > self.expiry_year or
                (now.year == self.expiry_year and now.month > self.expiry_month))


class Transaction(models.Model):
    """All financial transactions."""

    TRANSACTION_TYPES = [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('TRANSFER_OUT', 'Transfer Out'),
        ('TRANSFER_IN', 'Transfer In'),
        ('BILL_PAYMENT', 'Bill Payment'),
        ('RECHARGE', 'Mobile Recharge'),
        ('LOAN_DISBURSEMENT', 'Loan Disbursement'),
        ('LOAN_REPAYMENT', 'Loan Repayment'),
        ('DONATION', 'Donation'),
        ('CARD_PAYMENT', 'Card Payment'),
        ('INTEREST', 'Interest Credit'),
        ('CHARGE', 'Bank Charge'),
    ]
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('REVERSED', 'Reversed'),
    ]
    PAYMENT_METHODS = [
        ('ACCOUNT', 'Account Balance'),
        ('CARD', 'Debit/Credit Card'),
        ('BANK_TRANSFER', 'Bank Transfer'),
        ('MOBILE', 'Mobile Banking'),
    ]

    transaction_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    reference_number = models.CharField(max_length=20, unique=True, blank=True)
    account = models.ForeignKey(Account, on_delete=models.PROTECT, related_name='transactions')
    transaction_type = models.CharField(max_length=30, choices=TRANSACTION_TYPES)
    amount = models.DecimalField(max_digits=15, decimal_places=2,
                                 validators=[MinValueValidator(Decimal('0.01'))])
    balance_before = models.DecimalField(max_digits=15, decimal_places=2)
    balance_after = models.DecimalField(max_digits=15, decimal_places=2)
    currency = models.CharField(max_length=3, default='BDT')
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='PENDING')
    payment_method = models.CharField(max_length=20, choices=PAYMENT_METHODS, default='ACCOUNT')

    # Related entities
    recipient_account_number = models.CharField(max_length=20, blank=True)
    recipient_name = models.CharField(max_length=200, blank=True)
    recipient_bank = models.CharField(max_length=200, blank=True)
    card = models.ForeignKey(Card, on_delete=models.SET_NULL, null=True, blank=True)

    # Metadata
    description = models.CharField(max_length=500, blank=True)
    note = models.TextField(blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    fee = models.DecimalField(max_digits=10, decimal_places=2, default=Decimal('0.00'))

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    completed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'transactions'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['account', '-created_at']),
            models.Index(fields=['transaction_type', 'status']),
            models.Index(fields=['reference_number']),
        ]

    def save(self, *args, **kwargs):
        if not self.reference_number:
            self.reference_number = 'XB' + ''.join(
                random.choices(string.ascii_uppercase + string.digits, k=12))
        super().save(*args, **kwargs)

    def __str__(self):
        return f"{self.reference_number} - {self.transaction_type} {self.amount}"


class OTPVerification(models.Model):
    """OTP for 2FA and transaction verification."""

    PURPOSE_CHOICES = [
        ('LOGIN', 'Login 2FA'),
        ('TRANSACTION', 'Transaction Verification'),
        ('PASSWORD_RESET', 'Password Reset'),
        ('EMAIL_VERIFY', 'Email Verification'),
        ('PHONE_VERIFY', 'Phone Verification'),
        ('CARD_ACTIVATE', 'Card Activation'),
    ]
    CHANNEL_CHOICES = [
        ('EMAIL', 'Email'),
        ('SMS', 'SMS'),
        ('TOTP', 'Authenticator App'),
    ]

    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='otps')
    otp_code = models.CharField(max_length=10)
    purpose = models.CharField(max_length=30, choices=PURPOSE_CHOICES)
    channel = models.CharField(max_length=10, choices=CHANNEL_CHOICES, default='EMAIL')
    session_key = models.CharField(max_length=100, blank=True)  # Link to session
    is_used = models.BooleanField(default=False)
    attempts = models.PositiveSmallIntegerField(default=0)
    max_attempts = models.PositiveSmallIntegerField(default=3)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'otp_verifications'
        ordering = ['-created_at']

    def save(self, *args, **kwargs):
        if not self.expires_at:
            self.expires_at = timezone.now() + timezone.timedelta(minutes=5)
        super().save(*args, **kwargs)

    @property
    def is_valid(self):
        return (not self.is_used and
                self.attempts < self.max_attempts and
                timezone.now() < self.expires_at)

    def verify(self, code):
        self.attempts += 1
        if self.is_valid and self.otp_code == code:
            self.is_used = True
            self.used_at = timezone.now()
            self.save()
            return True
        self.save()
        return False

    def __str__(self):
        return f"OTP for {self.user.username} - {self.purpose}"


class LoanApplication(models.Model):
    """Loan applications and active loans."""

    LOAN_TYPES = [
        ('PERSONAL', 'Personal Loan'),
        ('HOME', 'Home Loan'),
        ('CAR', 'Car Loan'),
        ('EDUCATION', 'Education Loan'),
        ('BUSINESS', 'Business Loan'),
    ]
    STATUS_CHOICES = [
        ('DRAFT', 'Draft'),
        ('SUBMITTED', 'Submitted'),
        ('UNDER_REVIEW', 'Under Review'),
        ('APPROVED', 'Approved'),
        ('REJECTED', 'Rejected'),
        ('DISBURSED', 'Disbursed'),
        ('CLOSED', 'Closed'),
    ]

    application_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='loans')
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='loans')
    loan_type = models.CharField(max_length=20, choices=LOAN_TYPES)
    requested_amount = models.DecimalField(max_digits=15, decimal_places=2)
    approved_amount = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2, default=Decimal('12.00'))
    tenure_months = models.PositiveIntegerField()
    monthly_installment = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    purpose = models.TextField()
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='SUBMITTED')
    employment_type = models.CharField(max_length=50, blank=True)
    monthly_income = models.DecimalField(max_digits=12, decimal_places=2, null=True, blank=True)
    collateral = models.TextField(blank=True)
    rejection_reason = models.TextField(blank=True)
    applied_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)
    disbursed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'loan_applications'
        ordering = ['-applied_at']

    def __str__(self):
        return f"Loan #{str(self.application_id)[:8]} - {self.user.username} ({self.loan_type})"

    def calculate_emi(self):
        """Calculate Equated Monthly Installment."""
        if self.approved_amount and self.interest_rate and self.tenure_months:
            P = float(self.approved_amount)
            r = float(self.interest_rate) / 100 / 12
            n = self.tenure_months
            if r == 0:
                return Decimal(str(P / n))
            emi = P * r * (1 + r) ** n / ((1 + r) ** n - 1)
            return Decimal(str(round(emi, 2)))
        return None


class SavingsPlan(models.Model):
    """Fixed deposits and savings plans."""

    PLAN_TYPES = [
        ('FD', 'Fixed Deposit'),
        ('RD', 'Recurring Deposit'),
        ('DPS', 'Deposit Pension Scheme'),
    ]
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('MATURED', 'Matured'),
        ('WITHDRAWN', 'Withdrawn'),
        ('CANCELLED', 'Cancelled'),
    ]

    plan_id = models.UUIDField(default=uuid.uuid4, unique=True, editable=False)
    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='saving_plans')
    plan_type = models.CharField(max_length=10, choices=PLAN_TYPES)
    principal_amount = models.DecimalField(max_digits=15, decimal_places=2)
    interest_rate = models.DecimalField(max_digits=5, decimal_places=2)
    tenure_months = models.PositiveIntegerField()
    maturity_amount = models.DecimalField(max_digits=15, decimal_places=2, null=True, blank=True)
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='ACTIVE')
    start_date = models.DateField()
    maturity_date = models.DateField()
    auto_renew = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'savings_plans'
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.plan_type} - {self.account.account_number} - {self.principal_amount} BDT"


class BillPayment(models.Model):
    """Utility bill payments."""

    BILLER_TYPES = [
        ('ELECTRICITY', 'Electricity'),
        ('GAS', 'Gas'),
        ('WATER', 'Water'),
        ('INTERNET', 'Internet'),
        ('TV', 'Cable/Satellite TV'),
        ('PHONE', 'Phone'),
        ('INSURANCE', 'Insurance'),
        ('TAX', 'Tax'),
        ('OTHER', 'Other'),
    ]

    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='bill_payments')
    biller_type = models.CharField(max_length=20, choices=BILLER_TYPES)
    biller_name = models.CharField(max_length=200)
    consumer_id = models.CharField(max_length=100, help_text='Bill number / Consumer ID')
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    transaction = models.OneToOneField(Transaction, on_delete=models.SET_NULL, null=True, blank=True)
    billing_month = models.CharField(max_length=20, blank=True)
    paid_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'bill_payments'
        ordering = ['-paid_at']

    def __str__(self):
        return f"{self.biller_name} - {self.amount} BDT"


class MobileRecharge(models.Model):
    """Mobile top-up records."""

    OPERATOR_CHOICES = [
        ('GRAMEENPHONE', 'Grameenphone'),
        ('ROBI', 'Robi'),
        ('BANGLALINK', 'Banglalink'),
        ('AIRTEL', 'Airtel'),
        ('TELETALK', 'Teletalk'),
    ]
    RECHARGE_TYPES = [('PREPAID', 'Prepaid'), ('POSTPAID', 'Postpaid')]

    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='recharges')
    mobile_number = models.CharField(max_length=15)
    operator = models.CharField(max_length=30, choices=OPERATOR_CHOICES)
    recharge_type = models.CharField(max_length=10, choices=RECHARGE_TYPES, default='PREPAID')
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    transaction = models.OneToOneField(Transaction, on_delete=models.SET_NULL, null=True, blank=True)
    operator_reference = models.CharField(max_length=100, blank=True)
    recharged_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'mobile_recharges'
        ordering = ['-recharged_at']

    def __str__(self):
        return f"{self.mobile_number} - {self.operator} - {self.amount} BDT"


class Donation(models.Model):
    """Charitable donations."""

    account = models.ForeignKey(Account, on_delete=models.CASCADE, related_name='donations')
    organization_name = models.CharField(max_length=300)
    organization_type = models.CharField(max_length=100, blank=True)
    amount = models.DecimalField(max_digits=12, decimal_places=2)
    message = models.TextField(blank=True)
    is_anonymous = models.BooleanField(default=False)
    transaction = models.OneToOneField(Transaction, on_delete=models.SET_NULL, null=True, blank=True)
    donated_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'donations'
        ordering = ['-donated_at']

    def __str__(self):
        return f"Donation to {self.organization_name} - {self.amount} BDT"


class AuditLog(models.Model):
    """Security audit trail for all sensitive operations."""

    ACTION_TYPES = [
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('LOGIN_FAILED', 'Failed Login'),
        ('PASSWORD_CHANGE', 'Password Change'),
        ('PROFILE_UPDATE', 'Profile Update'),
        ('TRANSACTION', 'Transaction'),
        ('CARD_ACTION', 'Card Action'),
        ('OTP_SENT', 'OTP Sent'),
        ('OTP_VERIFIED', 'OTP Verified'),
        ('ACCOUNT_ACTION', 'Account Action'),
        ('SUSPICIOUS', 'Suspicious Activity'),
    ]

    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, blank=True)
    action = models.CharField(max_length=30, choices=ACTION_TYPES)
    description = models.TextField()
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    metadata = models.JSONField(default=dict, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'audit_logs'
        ordering = ['-created_at']
        indexes = [models.Index(fields=['user', '-created_at'])]

    def __str__(self):
        return f"{self.action} - {self.user} - {self.created_at}"
