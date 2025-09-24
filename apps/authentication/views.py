# apps/authentication/views.py - FIXED VERSION
from rest_framework import status, generics, permissions
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from drf_spectacular.utils import extend_schema, extend_schema_view
from django.contrib.auth import login
from django.utils import timezone
from django.core.mail import send_mail
from django.conf import settings
from django.template.loader import render_to_string
from datetime import timedelta
import secrets
import string
import logging
logger = logging.getLogger(__name__)

from .models import (
    User, PhoneVerification, EmailVerification, 
    PasswordReset, UserLoginLog
)
from .serializers import (
    UserRegistrationSerializer, UserLoginSerializer, UserProfileSerializer,
    PhoneVerificationRequestSerializer, PhoneVerificationSerializer, 
    EmailVerificationSerializer, PasswordResetSerializer, 
    PasswordResetConfirmSerializer, UserProfileUpdateSerializer,
    ChangePasswordSerializer, UserLoginLogSerializer
)
from apps.common.permissions import IsOwnerOrReadOnly
from apps.common.utils import get_client_ip, send_sms

@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="User Registration",
        description="Register a new user account with email and phone verification",
        tags=["Authentication"]
    )
)
class UserRegistrationView(generics.CreateAPIView):
    """User registration endpoint - FIXED VERSION"""
    
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        """Create new user and handle verification flow properly"""
        serializer = self.get_serializer(data=request.data)
        
        # FIXED: Better error handling for validation
        if not serializer.is_valid():
            errors = {}
            for field, error_list in serializer.errors.items():
                if isinstance(error_list, list):
                    errors[field] = error_list
                else:
                    errors[field] = [str(error_list)]
            
            return Response({
                'success': False,
                'errors': errors,
                'message': 'Please correct the errors below and try again.'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = serializer.save()
            
            # Send verification messages
            phone_verification = None
            email_verification = None
            
            # Send email verification (always)
            email_verification = self.send_email_verification(user)
            
            # Send phone verification only if phone number exists
            if user.phone_number:
                phone_verification = self.send_phone_verification(user)

            # Log registration
            UserLoginLog.objects.create(
                user=user,
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                success=True
            )

            # FIXED: Don't generate tokens yet - user needs to verify first
            return Response({
                'success': True,
                'message': 'Registration successful! Please check your email for verification instructions.',
                'user_id': str(user.id),
                'email': user.email,
                'requires_verification': True,
                'verification_info': {
                    'email_verification_sent': email_verification is not None,
                    'phone_verification_sent': phone_verification is not None,
                    'email_expires_at': email_verification.expires_at.isoformat() if email_verification else None,
                    'phone_expires_at': phone_verification.expires_at.isoformat() if phone_verification else None
                },
                'next_step': 'Please check your email and click the verification link to activate your account.'
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            logger.error(f"Registration error: {e}")
            return Response({
                'success': False,
                'message': 'Registration failed. Please try again.',
                'error': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def send_phone_verification(self, user):
        """Send phone verification code via SMS"""
        try:
            verification = PhoneVerification.generate_code(user, user.phone_number)
            
            # Send SMS
            message = f"Your BusiMap verification code is: {verification.verification_code}. Valid for 10 minutes."
            sms_sent = send_sms(user.phone_number, message)
            
            if sms_sent:
                logger.info(f"SMS verification sent to {user.phone_number}")
            else:
                logger.error(f"Failed to send SMS to {user.phone_number}")
                
            return verification
        except Exception as e:
            logger.error(f"Error in phone verification process for {user.phone_number}: {e}")
            return None

    def send_email_verification(self, user):
        """Send email verification token"""
        try:
            verification = EmailVerification.generate_token(user, user.email)
            
            # Create verification URL
            verification_url = f"{settings.FRONTEND_URL}/verify-email/{verification.verification_token}"
            
            # Use the utility function
            from apps.common.utils import send_email_verification as send_verification_email
            
            email_sent = send_verification_email(user, verification_url)
            
            if email_sent:
                logger.info(f"Email verification sent to {user.email}")
                return verification
            else:
                logger.error(f"Failed to send email verification to {user.email}")
                return None
                
        except Exception as e:
            logger.error(f"Error in email verification process for {user.email}: {e}")
            return None


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="User Login",
        description="Login with email/phone and password",
        tags=["Authentication"]
    )
)
class UserLoginView(generics.GenericAPIView):
    """User login endpoint - FIXED VERSION"""
    
    serializer_class = UserLoginSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Authenticate user and return tokens with proper verification checks"""
        serializer = self.get_serializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors,
                'message': 'Please check your credentials and try again.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        user = serializer.validated_data['user']
        
        # FIXED: Check if user needs verification
        if not user.email_verified:
            return Response({
                'success': False,
                'message': 'Please verify your email address before logging in.',
                'requires_verification': True,
                'verification_type': 'email',
                'user_id': str(user.id),
                'email': user.email,
                'next_step': 'Check your email for verification instructions.'
            }, status=status.HTTP_403_FORBIDDEN)

        # Generate JWT tokens only after verification
        refresh = RefreshToken.for_user(user)
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        # Log successful login
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )

        # FIXED: Determine redirect URL based on user type
        redirect_url = self.get_redirect_url(user)

        return Response({
            'success': True,
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': UserProfileSerializer(user).data,
            'verification_status': {
                'email_verified': user.email_verified,
                'phone_verified': user.phone_verified,
                'fully_verified': user.is_verified
            },
            'redirect_url': redirect_url,
            'message': f'Welcome back, {user.first_name}!'
        })

    def get_redirect_url(self, user):
        """Determine redirect URL based on user type"""
        if user.user_type == 'business_owner':
            return '/business-dashboard'
        elif user.user_type == 'admin':
            return '/admin-dashboard'
        else:  # customer
            return '/dashboard'


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="Verify Email",
        description="Verify email with token from email link",
        tags=["Authentication"]
    )
)
class EmailVerificationView(generics.GenericAPIView):
    """Email verification endpoint - FIXED VERSION"""
    
    serializer_class = EmailVerificationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Verify email with token and generate login tokens"""
        serializer = self.get_serializer(data=request.data)
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors,
                'message': 'Invalid verification token.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        verification = serializer.validated_data['verification']
        user = verification.user

        # Mark as verified
        verification.is_verified = True
        verification.verified_at = timezone.now()
        verification.save()
        
        user.email_verified = True
        user.save(update_fields=['email_verified'])

        # FIXED: Generate tokens after successful verification
        refresh = RefreshToken.for_user(user)
        
        # Update last login
        user.last_login = timezone.now()
        user.save(update_fields=['last_login'])

        # Log successful verification/login
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )

        # Determine redirect URL based on user type
        redirect_url = self.get_redirect_url(user)

        return Response({
            'success': True,
            'message': 'Email verified successfully! You are now logged in.',
            'access_token': str(refresh.access_token),
            'refresh_token': str(refresh),
            'user': UserProfileSerializer(user).data,
            'redirect_url': redirect_url,
            'verification_complete': True
        })

    def get_redirect_url(self, user):
        """Determine redirect URL based on user type"""
        if user.user_type == 'business_owner':
            return '/business-dashboard'
        elif user.user_type == 'admin':
            return '/admin-dashboard'
        else:  # customer
            return '/dashboard'


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="Verify Phone Number",
        description="Verify phone number with SMS code",
        tags=["Authentication"]
    )
)
class PhoneVerificationView(generics.GenericAPIView):
    """Phone number verification endpoint - FIXED VERSION"""
    
    serializer_class = PhoneVerificationSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Verify phone number with code"""
        serializer = self.get_serializer(data=request.data, context={'user': request.user})
        
        if not serializer.is_valid():
            return Response({
                'success': False,
                'errors': serializer.errors,
                'message': 'Invalid verification code.'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        verification = serializer.validated_data['verification']
        user = request.user

        # Increment attempts
        verification.increment_attempts()
        
        # Mark as verified
        verification.is_verified = True
        verification.verified_at = timezone.now()
        verification.save()
        
        user.phone_verified = True
        user.save(update_fields=['phone_verified'])

        return Response({
            'success': True,
            'message': 'Phone number verified successfully!',
            'phone_verified': True,
            'user_fully_verified': user.is_verified,
            'user': UserProfileSerializer(user).data
        })


# FIXED: Add better error handling for existing users
@csrf_exempt
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def check_email_availability(request):
    """Check if email is available for registration"""
    email = request.data.get('email', '').lower().strip()
    if not email:
        return Response({
            'success': False,
            'error': 'Email is required'
        }, status=400)
    
    exists = User.objects.filter(email=email).exists()
    
    if exists:
        # FIXED: Provide helpful message for existing users
        user = User.objects.get(email=email)
        if not user.email_verified:
            return Response({
                'success': False,
                'available': False,
                'message': 'This email is registered but not verified. Please check your email for verification instructions.',
                'requires_verification': True,
                'user_id': str(user.id)
            })
        else:
            return Response({
                'success': False,
                'available': False,
                'message': 'This email is already registered. Please use the login page.',
                'should_login': True
            })
    
    return Response({
        'success': True,
        'available': True,
        'message': 'Email is available for registration.'
    })


@csrf_exempt
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def check_phone_availability(request):
    """Check if phone number is available for registration"""
    phone_number = request.data.get('phone_number', '').strip()
    if not phone_number:
        return Response({
            'success': True,
            'available': True,
            'message': 'Phone number is optional.'
        })
    
    exists = User.objects.filter(phone_number=phone_number).exists()
    
    if exists:
        return Response({
            'success': False,
            'available': False,
            'message': 'This phone number is already registered. Please use a different number or login if this is your account.'
        })
    
    return Response({
        'success': True,
        'available': True,
        'message': 'Phone number is available.'
    })


# Keep all other views the same...
@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    get=extend_schema(
        summary="Get User Profile",
        description="Get current user profile information",
        tags=["Authentication"]
    ),
    put=extend_schema(
        summary="Update User Profile",
        description="Update current user profile",
        tags=["Authentication"]
    ),
    patch=extend_schema(
        summary="Partial Update User Profile", 
        description="Partially update current user profile",
        tags=["Authentication"]
    )
)
class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile management"""
    
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]

    def get_object(self):
        return self.request.user

    def get_serializer_class(self):
        if self.request.method in ['PUT', 'PATCH']:
            return UserProfileUpdateSerializer
        return UserProfileSerializer


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="Request Phone Verification",
        description="Request a new phone verification code",
        tags=["Authentication"]
    )
)
class PhoneVerificationRequestView(generics.GenericAPIView):
    """Request phone verification code"""
    
    serializer_class = PhoneVerificationRequestSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Send phone verification code"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        phone_number = serializer.validated_data['phone_number']
        user = request.user

        # Check if phone number belongs to user
        if user.phone_number != phone_number:
            return Response({
                'error': 'Phone number does not match your account'
            }, status=status.HTTP_400_BAD_REQUEST)

        # Check if already verified
        if user.phone_verified:
            return Response({
                'message': 'Phone number is already verified'
            })

        # Generate and send verification code
        verification = PhoneVerification.generate_code(user, phone_number)
        
        # Send SMS
        message = f"Your BusiMap verification code is: {verification.verification_code}. Valid for 10 minutes."
        sms_sent = send_sms(phone_number, message)

        return Response({
            'message': 'Verification code sent successfully' if sms_sent else 'Verification code generated',
            'expires_at': verification.expires_at,
            'attempts_remaining': verification.max_attempts - verification.attempts
        })


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="Resend Email Verification",
        description="Resend email verification token",
        tags=["Authentication"]
    )
)
class ResendEmailVerificationView(generics.GenericAPIView):
    """Resend email verification"""
    
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Resend email verification"""
        # FIXED: Allow resending for unverified users
        email = request.data.get('email')
        user_id = request.data.get('user_id')
        
        if not email and not user_id:
            return Response({
                'success': False,
                'error': 'Email or user ID is required'
            }, status=400)

        try:
            if email:
                user = User.objects.get(email=email.lower().strip())
            else:
                user = User.objects.get(id=user_id)
        except User.DoesNotExist:
            return Response({
                'success': False,
                'error': 'User not found'
            }, status=404)

        if user.email_verified:
            return Response({
                'success': False,
                'message': 'Email is already verified'
            })

        # Generate new verification token
        verification = EmailVerification.generate_token(user, user.email)
        
        # Send email
        verification_url = f"{settings.FRONTEND_URL}/verify-email/{verification.verification_token}"
        
        subject = 'Verify your BusiMap account'
        html_message = render_to_string('emails/email_verification.html', {
            'user': user,
            'verification_url': verification_url,
            'expires_hours': 24
        })
        
        try:
            send_mail(
                subject=subject,
                message=f'Please verify your email by visiting: {verification_url}',
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False
            )
            
            return Response({
                'success': True,
                'message': 'Verification email sent successfully',
                'expires_at': verification.expires_at
            })
        except Exception as e:
            return Response({
                'success': False,
                'error': 'Failed to send verification email'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Keep all other views (PasswordReset, ChangePassword, etc.) the same...

@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="Request Password Reset",
        description="Request password reset via email",
        tags=["Authentication"]
    )
)
class PasswordResetView(generics.GenericAPIView):
    serializer_class = PasswordResetSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        email = serializer.validated_data['email'].lower()
        try:
            user = User.objects.get(email__iexact=email)
        except User.DoesNotExist:
            # To avoid revealing user existence
            return Response({'message': 'If this email exists, a reset link has been sent'}, status=200)

        reset = PasswordReset.generate_token(
            user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            expires_in_hours=24
        )

        reset_url = f"{settings.FRONTEND_URL}/reset-password/{reset.reset_token}"

        # Send email
        subject = "Reset your BusiMap password"
        html_message = render_to_string('emails/password_reset.html', {
            'user': user,
            'reset_url': reset_url,
            'expires_hours': 24
        })

        try:
            send_mail(
                subject=subject,
                message=f"Reset your password: {reset_url}",
                from_email=settings.DEFAULT_FROM_EMAIL,
                recipient_list=[user.email],
                html_message=html_message,
                fail_silently=False
            )
            logger.info(f"Password reset email sent to {user.email}")
            return Response({'message': 'Password reset email sent successfully'})
        except Exception as e:
            logger.error(f"Failed to send password reset email to {user.email}: {e}")
            return Response({'error': 'Failed to send password reset email'}, status=500)


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="Confirm Password Reset",
        description="Reset password using token",
        tags=["Authentication"]
    )
)
class PasswordResetConfirmView(generics.GenericAPIView):
    serializer_class = PasswordResetConfirmSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        reset = serializer.validated_data['reset']
        new_password = serializer.validated_data['new_password']

        if reset.is_used:
            return Response({'error': 'This reset token has already been used'}, status=400)

        # Update password
        user = reset.user
        user.set_password(new_password)
        user.save()

        # Mark token as used
        reset.is_used = True
        reset.used_at = timezone.now()
        reset.save()

        # Log password change
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )

        logger.info(f"Password reset successful for user: {user.email}")
        return Response({'message': 'Password reset successful'})


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    post=extend_schema(
        summary="Change Password",
        description="Change current password",
        tags=["Authentication"]
    )
)
class ChangePasswordView(generics.GenericAPIView):
    """Change password endpoint"""
    
    serializer_class = ChangePasswordSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Change user password"""
        serializer = self.get_serializer(data=request.data, context={'user': request.user})
        serializer.is_valid(raise_exception=True)
        
        user = request.user
        new_password = serializer.validated_data['new_password']
        
        user.set_password(new_password)
        user.save()

        # Log password change
        UserLoginLog.objects.create(
            user=user,
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            success=True
        )

        return Response({
            'message': 'Password changed successfully'
        })


@method_decorator(csrf_exempt, name='dispatch')
@extend_schema_view(
    get=extend_schema(
        summary="Get Login History",
        description="Get user's login history",
        tags=["Authentication"]
    )
)
class LoginHistoryView(generics.ListAPIView):
    """User login history"""
    
    serializer_class = UserLoginLogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        return UserLoginLog.objects.filter(user=self.request.user)[:20]


@csrf_exempt
@api_view(['GET'])
@permission_classes([permissions.AllowAny])
def test_configuration(request):
    """Test endpoint to check configuration"""
    from apps.common.utils import test_email_sms_configuration
    
    config = test_email_sms_configuration()
    
    return Response({
        'message': 'Configuration test completed',
        'configuration': config,
        'environment_variables': {
            'EMAIL_HOST': bool(settings.EMAIL_HOST),
            'EMAIL_HOST_USER': bool(settings.EMAIL_HOST_USER),
            'TWILIO_ACCOUNT_SID': bool(settings.TWILIO_ACCOUNT_SID),
            'FRONTEND_URL': getattr(settings, 'FRONTEND_URL', 'NOT SET'),
        }
    })