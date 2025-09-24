# apps/authentication/serializers.py
from rest_framework import serializers
from django.contrib.auth import authenticate
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.utils import timezone
from .models import (
    User, UserProfile, PhoneVerification, 
    EmailVerification, PasswordReset, UserLoginLog
)
import re



class UserRegistrationSerializer(serializers.ModelSerializer):
    """User registration serializer with validation"""
    
    password = serializers.CharField(write_only=True, validators=[validate_password])
    confirm_password = serializers.CharField(write_only=True)

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'email', 'phone_number',
            'password', 'confirm_password', 'preferred_language',
            'location_province', 'location_district', 'user_type'
        ]

    def validate_email(self, value):
        """Validate email is unique and format"""
        if User.objects.filter(email__iexact=value).exists():
            raise serializers.ValidationError("A user with this email already exists.")
        return value.lower()

    def validate_phone_number(self, value):
        """Validate Rwanda phone number format if provided"""
        if value and value.strip():  # Only validate if phone number is provided and not empty
            # Enhanced Rwanda phone patterns
            rwanda_phone_patterns = [
                r'^\+250[7][0-9]{8}$',  # +2507XXXXXXXX
                r'^250[7][0-9]{8}$',    # 2507XXXXXXXX
                r'^0[7][0-9]{8}$',      # 07XXXXXXXX
            ]
            
            # Check if any pattern matches
            if not any(re.match(pattern, value) for pattern in rwanda_phone_patterns):
                raise serializers.ValidationError(
                    "Phone number must be in Rwanda format: +2507XXXXXXXX, 2507XXXXXXXX, or 07XXXXXXXX"
                )
            
            # Only check for uniqueness if the phone number is not empty
            if value.strip() and User.objects.filter(phone_number=value).exists():
                raise serializers.ValidationError("A user with this phone number already exists.")
        
        # Return None if empty string to ensure proper handling
        return value if value and value.strip() else None

    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords don't match"})
        
        # Ensure phone_number is properly handled before validation
        phone_number = attrs.get('phone_number')
        if phone_number == '' or phone_number is None:
            attrs['phone_number'] = None
        
        attrs.pop('confirm_password')
        return attrs

    def create(self, validated_data):
        """Create user with encrypted password"""
        password = validated_data.pop('password')
        
        # Ensure phone_number is properly handled
        phone_number = validated_data.get('phone_number')
        if phone_number == '' or phone_number is None:
            validated_data['phone_number'] = None
        
        user = User.objects.create_user(password=password, **validated_data)
        return user


class UserLoginSerializer(serializers.Serializer):
    """User login serializer with enhanced validation"""
    
    username = serializers.CharField(required=True)  # Can be email or phone
    password = serializers.CharField(write_only=True)

    def validate(self, attrs):
        """Validate login credentials"""
        username = attrs.get('username')
        password = attrs.get('password')

        if not username:
            raise serializers.ValidationError("Username (email or phone) is required")

        # Determine if username is email or phone
        is_email = '@' in username
        is_phone = any(char.isdigit() for char in username) and len(username) >= 9

        # Check if user exists and is active
        try:
            if is_email:
                user_obj = User.objects.get(email__iexact=username)
            elif is_phone:
                # Normalize phone number for lookup
                normalized_phone = self._normalize_phone_number(username)
                user_obj = User.objects.get(phone_number=normalized_phone)
            else:
                raise serializers.ValidationError("Please enter a valid email or phone number")
                
            if not user_obj.is_active:
                raise serializers.ValidationError("User account is disabled")
                
            if user_obj.is_locked:
                remaining_time = user_obj.locked_until - timezone.now()
                minutes = int(remaining_time.total_seconds() / 60)
                raise serializers.ValidationError(
                    f"Account is temporarily locked. Please try again in {minutes} minutes."
                )
                
        except User.DoesNotExist:
            raise serializers.ValidationError("Invalid credentials")

        # Authenticate user using the manager's get_by_natural_key method
        user = authenticate(username=username, password=password)

        if not user:
            # Record failed attempt
            user_obj.record_login_attempt(
                success=False, 
                ip_address=self.context.get('ip_address'),
                user_agent=self.context.get('user_agent'),
                failure_reason='invalid_credentials'
            )
            raise serializers.ValidationError("Invalid credentials")

        # Record successful login
        user.record_login_attempt(
            success=True,
            ip_address=self.context.get('ip_address'),
            user_agent=self.context.get('user_agent')
        )

        attrs['user'] = user
        return attrs

    def _normalize_phone_number(self, phone_number):
        """Normalize phone number to standard format"""
        if not phone_number:
            return None
            
        # Remove any non-digit characters except leading +
        cleaned = re.sub(r'(?!^\+)\D', '', phone_number)
        
        # Convert to standard format
        if cleaned.startswith('0'):
            return '+250' + cleaned[1:]
        elif cleaned.startswith('250'):
            return '+' + cleaned
        elif cleaned.startswith('7'):
            return '+250' + cleaned
        elif cleaned.startswith('+250'):
            return cleaned
            
        return phone_number


class UserProfileSerializer(serializers.ModelSerializer):
    """User profile serializer"""
    
    profile = serializers.SerializerMethodField()
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    is_verified = serializers.BooleanField(read_only=True)
    has_phone_number = serializers.BooleanField(read_only=True)  # REMOVE THE SOURCE PARAMETER

    class Meta:
        model = User
        fields = [
            'id', 'email', 'phone_number', 'first_name', 'last_name',
            'full_name', 'profile_picture', 'date_of_birth',
            'location_province', 'location_district', 'location_sector', 'location_cell',
            'current_latitude', 'current_longitude',
            'user_type', 'preferred_language', 'notifications_enabled',
            'location_sharing_enabled', 'email_verified', 'phone_verified',
            'is_verified', 'has_phone_number', 'date_joined', 'profile'
        ]
        read_only_fields = [
            'id', 'email', 'phone_number', 'date_joined', 
            'email_verified', 'phone_verified', 'is_verified', 'has_phone_number'
        ]

    def get_profile(self, obj):
        """Get extended profile information"""
        try:
            profile = obj.profile
            return {
                'bio': profile.bio,
                'favorite_business_categories': profile.favorite_business_categories,
                'dietary_preferences': profile.dietary_preferences,
                'transportation_preferences': profile.transportation_preferences,
                'profile_visibility': profile.profile_visibility,
                'total_searches': profile.total_searches,
                'total_business_visits': profile.total_business_visits,
                'email_notifications': profile.email_notifications,
                'sms_notifications': profile.sms_notifications,
                'push_notifications': profile.push_notifications,
            }
        except UserProfile.DoesNotExist:
            return None


class PhoneVerificationRequestSerializer(serializers.Serializer):
    """Request phone verification code"""
    
    phone_number = serializers.CharField(max_length=20)

    def validate_phone_number(self, value):
        """Validate Rwanda phone number format"""
        if not value:
            raise serializers.ValidationError("Phone number is required")
            
        # Enhanced Rwanda phone patterns
        rwanda_phone_patterns = [
            r'^\+250[7][0-9]{8}$',  # +2507XXXXXXXX
            r'^250[7][0-9]{8}$',    # 2507XXXXXXXX
            r'^0[7][0-9]{8}$',      # 07XXXXXXXX
        ]
        
        if not any(re.match(pattern, value) for pattern in rwanda_phone_patterns):
            raise serializers.ValidationError(
                "Phone number must be in Rwanda format: +2507XXXXXXXX, 2507XXXXXXXX, or 07XXXXXXXX"
            )
        return value


class PhoneVerificationSerializer(serializers.Serializer):
    """Phone verification serializer"""
    
    verification_code = serializers.CharField(max_length=10)
    phone_number = serializers.CharField(max_length=20, required=False)

    def validate_verification_code(self, value):
        """Validate verification code format"""
        if not value.isdigit() or len(value) != 6:
            raise serializers.ValidationError("Verification code must be 6 digits")
        return value

    def validate(self, attrs):
        """Additional validation for verification"""
        user = self.context.get('user')
        code = attrs.get('verification_code')
        phone_number = attrs.get('phone_number')

        if not user:
            raise serializers.ValidationError("User context required")

        # Use provided phone number or user's phone number
        target_phone = phone_number or user.phone_number
        
        if not target_phone:
            raise serializers.ValidationError("Phone number is required for verification")

        try:
            verification = PhoneVerification.objects.get(
                user=user,
                phone_number=target_phone,
                verification_code=code,
                is_verified=False
            )

            if verification.is_expired:
                raise serializers.ValidationError("Verification code has expired")
                
            if verification.attempts_exceeded:
                raise serializers.ValidationError("Maximum verification attempts exceeded")

        except PhoneVerification.DoesNotExist:
            # Increment attempts if verification exists but code is wrong
            try:
                verification = PhoneVerification.objects.get(
                    user=user,
                    phone_number=target_phone,
                    is_verified=False
                )
                verification.increment_attempts()
            except PhoneVerification.DoesNotExist:
                pass
                
            raise serializers.ValidationError("Invalid verification code")

        attrs['verification'] = verification
        return attrs


class EmailVerificationSerializer(serializers.Serializer):
    """Email verification serializer"""
    
    token = serializers.CharField(max_length=100)

    def validate(self, attrs):
        """Validate email verification token"""
        token = attrs.get('token')

        try:
            verification = EmailVerification.objects.select_related('user').get(
                verification_token=token,
                is_verified=False,
                expires_at__gt=timezone.now()  # Check expiration
            )
        except EmailVerification.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired verification token")

        attrs['verification'] = verification
        return attrs


class PasswordResetSerializer(serializers.Serializer):
    """Password reset request serializer"""
    
    email = serializers.EmailField()

    def validate_email(self, value):
        """Check if email exists"""
        try:
            user = User.objects.get(email__iexact=value, is_active=True)
        except User.DoesNotExist:
            raise serializers.ValidationError("No active user found with this email address")
        return value.lower()


class PasswordResetConfirmSerializer(serializers.Serializer):
    new_password = serializers.CharField(validators=[validate_password])
    confirm_password = serializers.CharField()
    token = serializers.CharField()

    def validate(self, attrs):
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords don't match"})

        token = attrs.get('token')

        try:
            reset = PasswordReset.objects.select_related('user').get(
                reset_token=token, 
                is_used=False,
                expires_at__gt=timezone.now()  # Check expiration
            )
        except PasswordReset.DoesNotExist:
            raise serializers.ValidationError("Invalid or expired reset token")

        attrs['reset'] = reset
        return attrs


class UserProfileUpdateSerializer(serializers.ModelSerializer):
    """Serializer for updating user profile"""
    
    profile = serializers.JSONField(required=False, write_only=True)

    class Meta:
        model = User
        fields = [
            'first_name', 'last_name', 'profile_picture', 'date_of_birth',
            'location_province', 'location_district', 'location_sector', 'location_cell',
            'current_latitude', 'current_longitude',
            'preferred_language', 'notifications_enabled', 'location_sharing_enabled',
            'profile'
        ]

    def validate_profile(self, value):
        """Ensure profile data is properly formatted"""
        if isinstance(value, str):
            import json
            try:
                value = json.loads(value)
            except json.JSONDecodeError:
                raise serializers.ValidationError("Invalid JSON format for profile data")
        
        if value is not None and not isinstance(value, dict):
            raise serializers.ValidationError("Profile data must be a dictionary")
        
        return value

    def update(self, instance, validated_data):
        """Update user and profile data"""
        profile_data = validated_data.pop('profile', {})
        
        # Update user fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()

        # Update profile fields
        if profile_data and hasattr(instance, 'profile'):
            profile = instance.profile
            for attr, value in profile_data.items():
                if hasattr(profile, attr):
                    setattr(profile, attr, value)
            profile.save()

        return instance


class ChangePasswordSerializer(serializers.Serializer):
    """Change password serializer"""
    
    current_password = serializers.CharField()
    new_password = serializers.CharField(validators=[validate_password])
    confirm_password = serializers.CharField()

    def validate_current_password(self, value):
        """Validate current password"""
        user = self.context['user']
        if not user.check_password(value):
            raise serializers.ValidationError("Current password is incorrect")
        return value

    def validate(self, attrs):
        """Validate password confirmation"""
        if attrs['new_password'] != attrs['confirm_password']:
            raise serializers.ValidationError({"password": "Passwords don't match"})
        return attrs


class UserLoginLogSerializer(serializers.ModelSerializer):
    """Serializer for user login logs"""
    
    user_email = serializers.EmailField(source='user.email', read_only=True)
    user_full_name = serializers.CharField(source='user.get_full_name', read_only=True)

    class Meta:
        model = UserLoginLog
        fields = [
            'user_email', 'user_full_name', 'ip_address', 'user_agent', 'success', 
            'failure_reason', 'created_at'
        ]
        read_only_fields = ['created_at']


class AddPhoneNumberSerializer(serializers.Serializer):
    """Serializer for adding phone number to existing user"""
    
    phone_number = serializers.CharField(max_length=20)

    def validate_phone_number(self, value):
        """Validate Rwanda phone number format"""
        if not value:
            raise serializers.ValidationError("Phone number is required")
            
        # Enhanced Rwanda phone patterns
        rwanda_phone_patterns = [
            r'^\+250[7][0-9]{8}$',  # +2507XXXXXXXX
            r'^250[7][0-9]{8}$',    # 2507XXXXXXXX
            r'^0[7][0-9]{8}$',      # 07XXXXXXXX
        ]
        
        if not any(re.match(pattern, value) for pattern in rwanda_phone_patterns):
            raise serializers.ValidationError(
                "Phone number must be in Rwanda format: +2507XXXXXXXX, 2507XXXXXXXX, or 07XXXXXXXX"
            )
        
        if User.objects.filter(phone_number=value).exists():
            raise serializers.ValidationError("A user with this phone number already exists.")
        
        return value


class UserMinimalSerializer(serializers.ModelSerializer):
    """Minimal user serializer for public profiles"""
    
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'full_name', 'profile_picture', 'user_type',
            'location_province', 'location_district'
        ]
        read_only_fields = fields


class UserRegistrationResponseSerializer(serializers.ModelSerializer):
    """Serializer for registration response (excludes sensitive fields)"""
    
    full_name = serializers.CharField(source='get_full_name', read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'email', 'phone_number', 'first_name', 'last_name', 'full_name',
            'user_type', 'preferred_language', 'email_verified', 'phone_verified',
            'date_joined'
        ]
        read_only_fields = fields


class VerifyPhoneResponseSerializer(serializers.Serializer):
    """Serializer for phone verification response"""
    
    success = serializers.BooleanField()
    message = serializers.CharField()
    user = UserProfileSerializer(read_only=True, required=False)


class VerifyEmailResponseSerializer(serializers.Serializer):
    """Serializer for email verification response"""
    
    success = serializers.BooleanField()
    message = serializers.CharField()
    user = UserProfileSerializer(read_only=True, required=False)