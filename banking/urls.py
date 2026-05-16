from django.urls import path
from . import views

app_name = 'banking'

urlpatterns = [
    # Public
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('verify-email/', views.verify_email, name='verify_email'),
    path('resend-otp-email/', views.resend_otp_email, name='resend_otp_email'),
    path('login/', views.user_login, name='login'),
    path('2fa/', views.two_factor_verify, name='two_factor_verify'),
    path('logout/', views.user_logout, name='logout'),
    path('locked/', views.locked_out, name='locked_out'),

    # Authenticated - Dashboard
    path('dashboard/', views.dashboard, name='dashboard'),
    path('transactions/', views.transaction_history, name='transaction_history'),
    path('profile/', views.profile, name='profile'),
    path('2fa/setup/', views.setup_2fa, name='setup_2fa'),

    # Banking Operations
    path('deposit/', views.deposit, name='deposit'),
    path('withdraw/', views.withdraw, name='withdraw'),
    path('payment/', views.payment, name='payment'),
    path('bill-payment/', views.bill_payment, name='bill_payment'),
    path('recharge/', views.recharge, name='recharge'),
    path('donation/', views.donation, name='donation'),
    path('loan/', views.loan, name='loan'),
    path('savings/', views.savings, name='savings'),

    # OTP / Confirm
    path('confirm/<str:transaction_type>/', views.confirm_transaction, name='confirm_transaction'),
    path('resend-otp/', views.resend_otp, name='resend_otp'),

    # API
    path('api/account/<int:account_id>/balance/', views.api_account_balance, name='api_account_balance'),
]