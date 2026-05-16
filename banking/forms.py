"""
X Bank - Forms
Secure forms for registration, login, transactions, and card operations.
"""
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from django.core.validators import RegexValidator
from django.utils import timezone
from decimal import Decimal
from .models import User, Account, Card, LoanApplication, SavingsPlan


# ─── AUTH FORMS ───────────────────────────────────────────────────────────────

class RegistrationForm(UserCreationForm):
    """Secure user registration form."""

    first_name = forms.CharField(max_length=100, required=True,
                                  widget=forms.TextInput(attrs={'placeholder': 'First Name'}))
    last_name = forms.CharField(max_length=100, required=True,
                                 widget=forms.TextInput(attrs={'placeholder': 'Last Name'}))
    email = forms.EmailField(required=True,
                              widget=forms.EmailInput(attrs={'placeholder': 'Email Address'}))
    phone = forms.CharField(
        max_length=15, required=True,
        validators=[RegexValidator(r'^\+?8?8?01[3-9]\d{8}$', 'Enter a valid Bangladeshi phone number.')],
        widget=forms.TextInput(attrs={'placeholder': '+8801XXXXXXXXX'})
    )
    date_of_birth = forms.DateField(
        widget=forms.DateInput(attrs={'type': 'date', 'max': '2007-01-01'}),
        required=True
    )
    gender = forms.ChoiceField(choices=[('', 'Select Gender')] + list(User.GENDER_CHOICES))
    address = forms.CharField(widget=forms.Textarea(attrs={'rows': 2, 'placeholder': 'Full Address'}))
    city = forms.CharField(max_length=100)
    id_type = forms.ChoiceField(choices=[('', 'Select ID Type')] + list(User.ID_TYPE_CHOICES))
    id_number = forms.CharField(max_length=50, widget=forms.TextInput(attrs={'placeholder': 'ID Number'}))
    account_type = forms.ChoiceField(choices=Account.ACCOUNT_TYPES)
    terms = forms.BooleanField(required=True, label='I agree to Terms & Conditions')

    class Meta:
        model = User
        fields = ['username', 'first_name', 'last_name', 'email', 'phone',
                  'date_of_birth', 'gender', 'address', 'city',
                  'id_type', 'id_number', 'password1', 'password2']

    def clean_email(self):
        email = self.cleaned_data.get('email')
        if User.objects.filter(email=email).exists():
            raise forms.ValidationError('This email address is already registered.')
        return email

    def clean_date_of_birth(self):
        dob = self.cleaned_data.get('date_of_birth')
        if dob:
            age = (timezone.now().date() - dob).days // 365
            if age < 18:
                raise forms.ValidationError('You must be at least 18 years old.')
        return dob

    def clean_username(self):
        username = self.cleaned_data.get('username')
        if len(username) < 5:
            raise forms.ValidationError('Username must be at least 5 characters.')
        return username


class SecureLoginForm(AuthenticationForm):
    """Login form with additional security."""

    username = forms.CharField(
        widget=forms.TextInput(attrs={'placeholder': 'User ID / Username', 'autocomplete': 'off'})
    )
    password = forms.CharField(
        widget=forms.PasswordInput(attrs={'placeholder': 'Password', 'autocomplete': 'off'})
    )
    remember_me = forms.BooleanField(required=False, label='Remember me for 7 days')


class OTPVerifyForm(forms.Form):
    """OTP verification form."""
    otp_code = forms.CharField(
        max_length=6, min_length=6,
        widget=forms.TextInput(attrs={
            'placeholder': '6-digit OTP',
            'autocomplete': 'off',
            'inputmode': 'numeric',
            'maxlength': '6',
        }),
        validators=[RegexValidator(r'^\d{6}$', 'OTP must be exactly 6 digits.')]
    )


class TOTPSetupForm(forms.Form):
    """Form to verify TOTP token during 2FA setup."""
    token = forms.CharField(
        max_length=6, min_length=6,
        widget=forms.TextInput(attrs={'placeholder': '6-digit code from authenticator app', 'inputmode': 'numeric'}),
        validators=[RegexValidator(r'^\d{6}$', 'Token must be 6 digits.')]
    )


class ChangePasswordForm(forms.Form):
    """Password change form."""
    current_password = forms.CharField(widget=forms.PasswordInput())
    new_password = forms.CharField(
        widget=forms.PasswordInput(),
        min_length=8,
        help_text='Minimum 8 chars, include uppercase, number, and symbol.'
    )
    confirm_password = forms.CharField(widget=forms.PasswordInput())

    def clean(self):
        cleaned = super().clean()
        if cleaned.get('new_password') != cleaned.get('confirm_password'):
            raise forms.ValidationError('Passwords do not match.')
        return cleaned


# ─── TRANSACTION FORMS ────────────────────────────────────────────────────────

class DepositForm(forms.Form):
    """Deposit form."""
    account = forms.ModelChoiceField(queryset=Account.objects.none(), empty_label='Select Account')
    amount = forms.DecimalField(
        max_digits=12, decimal_places=2,
        min_value=Decimal('10.00'), max_value=Decimal('500000.00'),
        widget=forms.NumberInput(attrs={'placeholder': 'Enter amount', 'step': '0.01'})
    )
    payment_method = forms.ChoiceField(choices=[
        ('CARD', 'Debit/Credit Card'),
        ('BANK_TRANSFER', 'Bank Transfer'),
        ('MOBILE', 'Mobile Banking (bKash/Nagad)'),
    ])
    note = forms.CharField(
        max_length=200, required=False,
        widget=forms.TextInput(attrs={'placeholder': 'Reference note (optional)'})
    )
    # Card payment fields
    card_number = forms.CharField(
        max_length=19, required=False,
        widget=forms.TextInput(attrs={'placeholder': '1234 5678 9012 3456', 'inputmode': 'numeric'})
    )
    card_name = forms.CharField(max_length=100, required=False,
                                 widget=forms.TextInput(attrs={'placeholder': 'Name on card'}))
    card_expiry = forms.CharField(max_length=5, required=False,
                                   widget=forms.TextInput(attrs={'placeholder': 'MM/YY'}))
    card_cvv = forms.CharField(max_length=4, required=False,
                                widget=forms.PasswordInput(attrs={'placeholder': 'CVV', 'maxlength': '4'}))

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['account'].queryset = Account.objects.filter(
            user=user, status='ACTIVE'
        )

    def clean(self):
        cleaned = super().clean()
        method = cleaned.get('payment_method')
        if method == 'CARD':
            if not cleaned.get('card_number'):
                self.add_error('card_number', 'Card number is required.')
            if not cleaned.get('card_cvv'):
                self.add_error('card_cvv', 'CVV is required.')
            if not cleaned.get('card_expiry'):
                self.add_error('card_expiry', 'Expiry date is required.')
            # Validate card number format
            card_num = cleaned.get('card_number', '').replace(' ', '')
            if card_num and (not card_num.isdigit() or len(card_num) != 16):
                self.add_error('card_number', 'Invalid card number.')
        return cleaned


class WithdrawForm(forms.Form):
    """Withdrawal form."""
    account = forms.ModelChoiceField(queryset=Account.objects.none())
    amount = forms.DecimalField(
        max_digits=12, decimal_places=2,
        min_value=Decimal('10.00'),
        widget=forms.NumberInput(attrs={'placeholder': 'Amount to withdraw', 'step': '0.01'})
    )
    withdrawal_method = forms.ChoiceField(choices=[
        ('ATM', 'ATM Withdrawal'),
        ('BRANCH', 'Branch Counter'),
        ('ONLINE', 'Online Transfer'),
    ])
    note = forms.CharField(max_length=200, required=False,
                            widget=forms.TextInput(attrs={'placeholder': 'Note (optional)'}))

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['account'].queryset = Account.objects.filter(
            user=user, status='ACTIVE'
        )


class TransferForm(forms.Form):
    """Fund transfer form."""
    from_account = forms.ModelChoiceField(queryset=Account.objects.none(), label='From Account')
    recipient_account = forms.CharField(
        max_length=20,
        widget=forms.TextInput(attrs={'placeholder': 'Recipient Account Number', 'inputmode': 'numeric'})
    )
    recipient_name = forms.CharField(max_length=200,
                                      widget=forms.TextInput(attrs={'placeholder': 'Recipient Name'}))
    recipient_bank = forms.CharField(max_length=200, required=False,
                                      widget=forms.TextInput(attrs={'placeholder': 'Recipient Bank (for inter-bank)'}))
    amount = forms.DecimalField(
        max_digits=12, decimal_places=2, min_value=Decimal('10.00'),
        widget=forms.NumberInput(attrs={'placeholder': 'Amount', 'step': '0.01'})
    )
    note = forms.CharField(max_length=500, required=False,
                            widget=forms.TextInput(attrs={'placeholder': 'Transfer note'}))

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['from_account'].queryset = Account.objects.filter(
            user=user, status='ACTIVE'
        )

    def clean_recipient_account(self):
        acc = self.cleaned_data.get('recipient_account')
        if not acc.isdigit():
            raise forms.ValidationError('Account number must contain only digits.')
        if len(acc) < 8 or len(acc) > 20:
            raise forms.ValidationError('Invalid account number length.')
        return acc


class CardPaymentForm(forms.Form):
    """Card-based payment form."""
    from_account = forms.ModelChoiceField(queryset=Account.objects.none(), label='Debit From')
    recipient_type = forms.ChoiceField(choices=[
        ('ACCOUNT', 'Bank Account'),
        ('CARD', 'Card Number'),
    ])
    # Bank transfer fields
    recipient_account = forms.CharField(max_length=20, required=False,
                                         widget=forms.TextInput(attrs={'placeholder': 'Account Number'}))
    recipient_name = forms.CharField(max_length=200, required=False,
                                      widget=forms.TextInput(attrs={'placeholder': 'Recipient Name'}))
    recipient_bank = forms.CharField(max_length=200, required=False)
    # Card fields
    card_number = forms.CharField(max_length=19, required=False,
                                   widget=forms.TextInput(attrs={'placeholder': '1234 5678 9012 3456'}))
    cardholder_name = forms.CharField(max_length=100, required=False,
                                       widget=forms.TextInput(attrs={'placeholder': 'Name on card'}))
    expiry_date = forms.CharField(max_length=5, required=False,
                                   widget=forms.TextInput(attrs={'placeholder': 'MM/YY'}))
    cvv = forms.CharField(max_length=4, required=False,
                           widget=forms.PasswordInput(attrs={'placeholder': 'CVV'}))
    amount = forms.DecimalField(
        max_digits=12, decimal_places=2, min_value=Decimal('10.00'),
        widget=forms.NumberInput(attrs={'placeholder': 'Amount', 'step': '0.01'})
    )
    note = forms.CharField(max_length=500, required=False,
                            widget=forms.TextInput(attrs={'placeholder': 'Payment note'}))

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['from_account'].queryset = Account.objects.filter(
            user=user, status='ACTIVE'
        )


class BillPaymentForm(forms.Form):
    """Bill payment form."""
    from banking.models import BillPayment

    account = forms.ModelChoiceField(queryset=Account.objects.none())
    biller_type = forms.ChoiceField(choices=BillPayment.BILLER_TYPES)
    biller_name = forms.CharField(max_length=200,
                                   widget=forms.TextInput(attrs={'placeholder': 'Service Provider Name'}))
    consumer_id = forms.CharField(max_length=100,
                                   widget=forms.TextInput(attrs={'placeholder': 'Bill/Consumer ID'}))
    amount = forms.DecimalField(
        max_digits=12, decimal_places=2, min_value=Decimal('10.00'),
        widget=forms.NumberInput(attrs={'placeholder': 'Bill Amount', 'step': '0.01'})
    )
    billing_month = forms.CharField(max_length=20, required=False,
                                     widget=forms.TextInput(attrs={'placeholder': 'e.g. January 2025'}))

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['account'].queryset = Account.objects.filter(user=user, status='ACTIVE')


class RechargeForm(forms.Form):
    """Mobile recharge form."""
    from banking.models import MobileRecharge

    account = forms.ModelChoiceField(queryset=Account.objects.none())
    mobile_number = forms.CharField(
        max_length=15,
        validators=[RegexValidator(r'^01[3-9]\d{8}$', 'Enter a valid Bangladeshi mobile number.')],
        widget=forms.TextInput(attrs={'placeholder': '01XXXXXXXXX', 'inputmode': 'tel'})
    )
    operator = forms.ChoiceField(choices=MobileRecharge.OPERATOR_CHOICES)
    recharge_type = forms.ChoiceField(choices=MobileRecharge.RECHARGE_TYPES)
    amount = forms.DecimalField(
        max_digits=8, decimal_places=2,
        min_value=Decimal('10.00'), max_value=Decimal('2000.00'),
        widget=forms.NumberInput(attrs={'placeholder': 'Recharge Amount', 'step': '1'})
    )

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['account'].queryset = Account.objects.filter(user=user, status='ACTIVE')


class DonationForm(forms.Form):
    """Charitable donation form."""
    account = forms.ModelChoiceField(queryset=Account.objects.none())
    organization_name = forms.CharField(max_length=300,
                                         widget=forms.TextInput(attrs={'placeholder': 'Organization Name'}))
    organization_type = forms.ChoiceField(choices=[
        ('', 'Select Type'),
        ('NGO', 'NGO / Non-profit'),
        ('RELIGIOUS', 'Religious Organization'),
        ('EDUCATIONAL', 'Educational Institution'),
        ('HEALTHCARE', 'Healthcare'),
        ('DISASTER', 'Disaster Relief'),
        ('ANIMAL', 'Animal Welfare'),
        ('ENVIRONMENT', 'Environmental'),
        ('OTHER', 'Other'),
    ], required=False)
    amount = forms.DecimalField(
        max_digits=12, decimal_places=2, min_value=Decimal('10.00'),
        widget=forms.NumberInput(attrs={'placeholder': 'Donation Amount', 'step': '0.01'})
    )
    message = forms.CharField(max_length=500, required=False,
                               widget=forms.Textarea(attrs={'rows': 2, 'placeholder': 'Message (optional)'}))
    is_anonymous = forms.BooleanField(required=False, label='Make this donation anonymous')

    def __init__(self, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['account'].queryset = Account.objects.filter(user=user, status='ACTIVE')


class LoanApplicationForm(forms.ModelForm):
    """Loan application form."""

    class Meta:
        model = LoanApplication
        fields = ['loan_type', 'requested_amount', 'tenure_months', 'purpose',
                  'employment_type', 'monthly_income', 'collateral']
        widgets = {
            'requested_amount': forms.NumberInput(attrs={'placeholder': 'Loan amount in BDT', 'step': '1000'}),
            'tenure_months': forms.NumberInput(attrs={'placeholder': 'Loan tenure in months', 'min': '3', 'max': '360'}),
            'purpose': forms.Textarea(attrs={'rows': 3, 'placeholder': 'Purpose of the loan'}),
            'monthly_income': forms.NumberInput(attrs={'placeholder': 'Your monthly income', 'step': '100'}),
            'collateral': forms.Textarea(attrs={'rows': 2, 'placeholder': 'Any collateral (optional)'}),
        }

    def clean_requested_amount(self):
        amount = self.cleaned_data.get('requested_amount')
        if amount and (amount < 10000 or amount > 10000000):
            raise forms.ValidationError('Loan amount must be between ৳10,000 and ৳1,00,00,000.')
        return amount


class SavingsPlanForm(forms.ModelForm):
    """Create a savings/FD plan."""

    class Meta:
        model = SavingsPlan
        fields = ['plan_type', 'principal_amount', 'tenure_months', 'auto_renew']
        widgets = {
            'principal_amount': forms.NumberInput(attrs={'placeholder': 'Amount to invest', 'step': '1000', 'min': '1000'}),
            'tenure_months': forms.NumberInput(attrs={'placeholder': 'Duration in months', 'min': '1', 'max': '120'}),
        }

    def clean_principal_amount(self):
        amount = self.cleaned_data.get('principal_amount')
        if amount and amount < 1000:
            raise forms.ValidationError('Minimum investment is ৳1,000.')
        return amount
