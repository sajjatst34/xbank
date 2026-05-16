from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from django.utils.html import format_html
from .models import (
    User, Account, Card, Transaction, OTPVerification,
    LoanApplication, SavingsPlan, BillPayment, MobileRecharge,
    Donation, AuditLog
)

admin.site.site_header = "X Bank Administration"
admin.site.site_title = "X Bank Admin"
admin.site.index_title = "Banking Management Portal"


@admin.register(User)
class CustomUserAdmin(UserAdmin):
    list_display = ('username', 'get_full_name', 'email', 'phone',
                    'is_email_verified', 'is_kyc_verified', 'two_factor_enabled', 'date_joined')
    list_filter = ('is_email_verified', 'is_kyc_verified', 'two_factor_enabled',
                   'is_active', 'is_staff', 'gender')
    search_fields = ('username', 'email', 'phone', 'first_name', 'last_name')
    ordering = ('-date_joined',)
    readonly_fields = ('date_joined', 'last_login', 'last_login_ip', 'created_at', 'updated_at')

    fieldsets = UserAdmin.fieldsets + (
        ('Personal Info', {
            'fields': ('phone', 'date_of_birth', 'gender', 'address', 'city', 'postal_code', 'country')
        }),
        ('Identity', {
            'fields': ('id_type', 'id_number', 'id_document', 'profile_photo')
        }),
        ('Verification & Security', {
            'fields': ('is_email_verified', 'is_phone_verified', 'is_kyc_verified',
                       'two_factor_enabled', 'last_login_ip', 'failed_login_attempts')
        }),
    )


@admin.register(Account)
class AccountAdmin(admin.ModelAdmin):
    list_display = ('account_number', 'user', 'account_type', 'balance_display',
                    'currency', 'status', 'is_primary', 'opened_at')
    list_filter = ('account_type', 'status', 'currency', 'is_primary')
    search_fields = ('account_number', 'user__username', 'user__email')
    readonly_fields = ('account_number', 'opened_at', 'updated_at')
    ordering = ('-opened_at',)

    def balance_display(self, obj):
        color = 'green' if obj.balance > 0 else 'red'
        return format_html(
            '<span style="color: {};">৳{:,.2f}</span>', color, obj.balance
        )
    balance_display.short_description = 'Balance'


@admin.register(Transaction)
class TransactionAdmin(admin.ModelAdmin):
    list_display = ('reference_number', 'account', 'transaction_type', 'amount_display',
                    'status', 'payment_method', 'created_at')
    list_filter = ('transaction_type', 'status', 'payment_method', 'currency')
    search_fields = ('reference_number', 'account__account_number',
                     'recipient_account_number', 'recipient_name')
    readonly_fields = ('transaction_id', 'reference_number', 'balance_before',
                       'balance_after', 'created_at', 'updated_at', 'completed_at')
    ordering = ('-created_at',)
    date_hierarchy = 'created_at'

    def amount_display(self, obj):
        color = 'green' if obj.transaction_type in ['DEPOSIT', 'TRANSFER_IN'] else 'red'
        return format_html('<span style="color: {};">৳{:,.2f}</span>', color, obj.amount)
    amount_display.short_description = 'Amount'


@admin.register(Card)
class CardAdmin(admin.ModelAdmin):
    list_display = ('masked_number', 'account', 'card_type', 'network',
                    'cardholder_name', 'expiry_display', 'status')
    list_filter = ('card_type', 'network', 'status')
    search_fields = ('card_number', 'cardholder_name', 'account__account_number')
    readonly_fields = ('card_number', 'cvv_hash', 'pin_hash', 'issued_at')


@admin.register(OTPVerification)
class OTPAdmin(admin.ModelAdmin):
    list_display = ('user', 'purpose', 'channel', 'is_used', 'attempts', 'created_at', 'expires_at')
    list_filter = ('purpose', 'channel', 'is_used')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('otp_code', 'created_at', 'used_at')
    ordering = ('-created_at',)


@admin.register(LoanApplication)
class LoanAdmin(admin.ModelAdmin):
    list_display = ('application_id_short', 'user', 'loan_type', 'requested_amount',
                    'status', 'applied_at')
    list_filter = ('loan_type', 'status')
    search_fields = ('user__username', 'user__email')
    readonly_fields = ('application_id', 'applied_at', 'reviewed_at', 'disbursed_at')
    ordering = ('-applied_at',)

    def application_id_short(self, obj):
        return str(obj.application_id)[:8].upper()
    application_id_short.short_description = 'App ID'

    actions = ['approve_loans', 'reject_loans']

    def approve_loans(self, request, queryset):
        from django.utils import timezone
        updated = queryset.filter(status='SUBMITTED').update(
            status='APPROVED', reviewed_at=timezone.now()
        )
        self.message_user(request, f'{updated} loan(s) approved.')
    approve_loans.short_description = 'Approve selected loan applications'

    def reject_loans(self, request, queryset):
        from django.utils import timezone
        updated = queryset.filter(status='SUBMITTED').update(
            status='REJECTED', reviewed_at=timezone.now()
        )
        self.message_user(request, f'{updated} loan(s) rejected.')
    reject_loans.short_description = 'Reject selected loan applications'


@admin.register(SavingsPlan)
class SavingsAdmin(admin.ModelAdmin):
    list_display = ('plan_id_short', 'account', 'plan_type', 'principal_amount',
                    'interest_rate', 'tenure_months', 'status', 'maturity_date')
    list_filter = ('plan_type', 'status')
    readonly_fields = ('plan_id', 'created_at')

    def plan_id_short(self, obj):
        return str(obj.plan_id)[:8].upper()
    plan_id_short.short_description = 'Plan ID'


@admin.register(BillPayment)
class BillPaymentAdmin(admin.ModelAdmin):
    list_display = ('biller_name', 'biller_type', 'account', 'amount', 'consumer_id', 'paid_at')
    list_filter = ('biller_type',)
    search_fields = ('biller_name', 'consumer_id', 'account__account_number')
    ordering = ('-paid_at',)


@admin.register(MobileRecharge)
class RechargeAdmin(admin.ModelAdmin):
    list_display = ('mobile_number', 'operator', 'recharge_type', 'amount', 'account', 'recharged_at')
    list_filter = ('operator', 'recharge_type')
    search_fields = ('mobile_number', 'account__account_number')
    ordering = ('-recharged_at',)


@admin.register(Donation)
class DonationAdmin(admin.ModelAdmin):
    list_display = ('organization_name', 'organization_type', 'amount',
                    'is_anonymous', 'account', 'donated_at')
    list_filter = ('organization_type', 'is_anonymous')
    search_fields = ('organization_name',)
    ordering = ('-donated_at',)


@admin.register(AuditLog)
class AuditLogAdmin(admin.ModelAdmin):
    list_display = ('action', 'user', 'description_short', 'ip_address', 'created_at')
    list_filter = ('action',)
    search_fields = ('user__username', 'description', 'ip_address')
    readonly_fields = ('user', 'action', 'description', 'ip_address',
                       'user_agent', 'metadata', 'created_at')
    ordering = ('-created_at',)

    def description_short(self, obj):
        return obj.description[:80] + '...' if len(obj.description) > 80 else obj.description
    description_short.short_description = 'Description'

    def has_add_permission(self, request):
        return False

    def has_change_permission(self, request, obj=None):
        return False
