# apps/authentication/urls.py
from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

app_name = 'authentication'

urlpatterns = [
    # Registration & Login
    path('register/', views.UserRegistrationView.as_view(), name='register'),
    path('login/', views.UserLoginView.as_view(), name='login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # Profile Management
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    path('change-password/', views.ChangePasswordView.as_view(), name='change_password'),
    path('login-history/', views.LoginHistoryView.as_view(), name='login_history'),
    
    # Phone Verification
    path('phone/request-verification/', views.PhoneVerificationRequestView.as_view(), name='phone_request_verification'),
    path('phone/verify/', views.PhoneVerificationView.as_view(), name='phone_verify'),
    
    # Email Verification
    path('email/verify/', views.EmailVerificationView.as_view(), name='email_verify'),
    path('email/resend-verification/', views.ResendEmailVerificationView.as_view(), name='resend_email_verification'),
    
    # Password Reset
    path('password-reset/', views.PasswordResetView.as_view(), name='password_reset'),
    path('password-reset-confirm/', views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    
    # Utility endpoints
    path('check-email/', views.check_email_availability, name='check_email'),
    path('check-phone/', views.check_phone_availability, name='check_phone'),

   
]