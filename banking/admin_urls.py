from django.urls import path
from . import admin_views

app_name = 'admin_panel'

urlpatterns = [
    path('', admin_views.dashboard, name='dashboard'),
    path('users/', admin_views.users, name='users'),
    path('users/<int:user_id>/', admin_views.user_detail, name='user_detail'),
    path('kyc/', admin_views.kyc_pending, name='kyc_pending'),
    path('accounts/', admin_views.accounts, name='accounts'),
    path('accounts/<int:account_id>/', admin_views.account_detail, name='account_detail'),
    path('transactions/', admin_views.transactions, name='transactions'),
    path('transactions/<int:txn_id>/', admin_views.transaction_detail, name='transaction_detail'),
    path('loans/', admin_views.loans, name='loans'),
    path('loans/<int:loan_id>/', admin_views.loan_detail, name='loan_detail'),
    path('savings/', admin_views.savings, name='savings'),
    path('cards/', admin_views.cards, name='cards'),
    path('bill-payments/', admin_views.bill_payments, name='bill_payments'),
    path('recharges/', admin_views.recharges, name='recharges'),
    path('donations/', admin_views.donations, name='donations'),
    path('audit-logs/', admin_views.audit_logs, name='audit_logs'),
]
