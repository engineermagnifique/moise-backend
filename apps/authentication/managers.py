# apps/authentication/managers.py

from django.contrib.auth.models import BaseUserManager
from django.core.exceptions import ValidationError
from django.utils import timezone
import re
from django.db import models 



class UserManager(BaseUserManager):
    """Custom user manager for the User model"""
    
    def create_user(self, email, password=None, **extra_fields):
        """Create and return a regular user with enhanced validation"""
        if not email:
            raise ValueError('Email address is required')
            
        email = self.normalize_email(email)
        
        # Validate email format
        if not self._validate_email_format(email):
            raise ValueError('Invalid email address format')
        
        # Handle phone_number properly - set to None if empty or invalid
        phone_number = extra_fields.get('phone_number')
        if phone_number:
            if not self._validate_rwanda_phone(phone_number):
                raise ValueError('Invalid Rwanda phone number format. Expected format: +2507XXXXXXXX, 2507XXXXXXXX, or 07XXXXXXXX')
            # Normalize phone number
            extra_fields['phone_number'] = self._normalize_phone_number(phone_number)
        else:
            # Ensure phone_number is None if not provided
            extra_fields['phone_number'] = None
        
        # Ensure user_type is set, default to 'customer'
        extra_fields.setdefault('user_type', 'customer')
        extra_fields.setdefault('is_active', True)
        
        user = self.model(email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        """Create and return a superuser with enhanced security defaults"""
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('user_type', 'admin')
        extra_fields.setdefault('email_verified', True)
        extra_fields.setdefault('phone_verified', True)
        extra_fields.setdefault('is_active', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True')

        return self.create_user(email, password, **extra_fields)

    def get_by_natural_key(self, username):
        """Allow login with either email or phone number with improved error handling"""
        # Normalize the username (strip whitespace, etc.)
        username = username.strip().lower() if username else username
        
        if not username:
            raise self.model.DoesNotExist("Username cannot be empty")
            
        # Try email first (case-insensitive)
        try:
            return self.get(email__iexact=username)
        except self.model.DoesNotExist:
            # Try phone number (normalize first)
            try:
                normalized_phone = self._normalize_phone_number(username)
                if normalized_phone:
                    return self.get(phone_number=normalized_phone)
                else:
                    raise self.model.DoesNotExist()
            except self.model.DoesNotExist:
                # Raise a more specific error
                raise self.model.DoesNotExist(
                    f"User with email/phone '{username}' does not exist. "
                    f"Please check your credentials or contact support."
                )

    def _validate_email_format(self, email):
        """Validate email format using regex"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(email_pattern, email))

    def _validate_rwanda_phone(self, phone_number):
        """Validate Rwanda phone number format with enhanced patterns"""
        if not phone_number:
            return False
            
        # Allow various formats and normalize
        rwanda_phone_patterns = [
            r'^\+250[7][0-9]{8}$',  # +2507XXXXXXXX
            r'^250[7][0-9]{8}$',    # 2507XXXXXXXX
            r'^0[7][0-9]{8}$',      # 07XXXXXXXX
        ]
        
        for pattern in rwanda_phone_patterns:
            if re.match(pattern, phone_number):
                return True
        return False

    def _normalize_phone_number(self, phone_number):
        """Normalize phone number to standard format (+2507XXXXXXXX)"""
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
            
        return None

    def verify_user_email(self, user_id, verification_token):
        """Verify user's email using token with enhanced error handling"""
        from .models import EmailVerification
        
        try:
            verification = EmailVerification.objects.select_related('user').get(
                user_id=user_id,
                verification_token=verification_token,
                is_verified=False
            )
            
            # Check if token is expired
            if verification.is_expired:
                raise ValidationError("Email verification token has expired")
            
            user = verification.user
            user.email_verified = True
            user.save(update_fields=['email_verified', 'updated_at'])
            
            verification.is_verified = True
            verification.verified_at = timezone.now()
            verification.save(update_fields=['is_verified', 'verified_at'])
            
            return user
            
        except EmailVerification.DoesNotExist:
            raise ValidationError("Invalid email verification token")
        except Exception as e:
            raise ValidationError(f"Email verification failed: {str(e)}")

    def verify_user_phone(self, user_id, verification_code):
        """Verify user's phone using SMS code with enhanced security"""
        from .models import PhoneVerification
        
        try:
            verification = PhoneVerification.objects.select_related('user').get(
                user_id=user_id,
                verification_code=verification_code,
                is_verified=False
            )
            
            # Check if code is expired
            if verification.is_expired:
                raise ValidationError("Phone verification code has expired")
            
            # Check if attempts exceeded
            if verification.attempts_exceeded:
                raise ValidationError("Maximum verification attempts exceeded")
            
            user = verification.user
            user.phone_verified = True
            user.save(update_fields=['phone_verified', 'updated_at'])
            
            verification.is_verified = True
            verification.verified_at = timezone.now()
            verification.save(update_fields=['is_verified', 'verified_at'])
            
            return user
            
        except PhoneVerification.DoesNotExist:
            # Increment attempts counter for security
            try:
                verification = PhoneVerification.objects.get(
                    user_id=user_id,
                    is_verified=False
                )
                verification.increment_attempts()
                remaining_attempts = verification.attempts_remaining
                
                if remaining_attempts > 0:
                    raise ValidationError(f"Invalid verification code. {remaining_attempts} attempts remaining.")
                else:
                    raise ValidationError("Maximum verification attempts exceeded. Please request a new code.")
                    
            except PhoneVerification.DoesNotExist:
                raise ValidationError("Invalid verification code or user")
        except Exception as e:
            raise ValidationError(f"Phone verification failed: {str(e)}")

    def get_or_create_user(self, email, **extra_fields):
        """Safe get or create method with validation"""
        try:
            return self.get(email=email), False
        except self.model.DoesNotExist:
            return self.create_user(email, **extra_fields), True

    def get_active_users(self):
        """Get all active users"""
        return self.filter(is_active=True)

    def get_users_by_type(self, user_type):
        """Get users by type with validation"""
        valid_types = ['customer', 'business_owner', 'admin', 'staff']
        if user_type not in valid_types:
            raise ValueError(f"Invalid user type. Must be one of: {valid_types}")
        
        return self.filter(user_type=user_type, is_active=True)

    def get_verified_users(self):
        """Get users with verified email addresses"""
        return self.filter(email_verified=True, is_active=True)

    def search_users(self, search_term):
        """Search users by name, email, or phone number"""
        return self.filter(
            models.Q(first_name__icontains=search_term) |
            models.Q(last_name__icontains=search_term) |
            models.Q(email__icontains=search_term) |
            models.Q(phone_number__icontains=search_term),
            is_active=True
        )

    def get_users_by_location(self, province=None, district=None, sector=None):
        """Get users by location filters"""
        queryset = self.filter(is_active=True)
        
        if province:
            queryset = queryset.filter(location_province__iexact=province)
        if district:
            queryset = queryset.filter(location_district__iexact=district)
        if sector:
            queryset = queryset.filter(location_sector__iexact=sector)
            
        return queryset

    def create_user_with_profile(self, email, password=None, **extra_fields):
        """Create user along with profile in a transaction"""
        from django.db import transaction
        
        with transaction.atomic():
            user = self.create_user(email, password, **extra_fields)
            # Profile is automatically created by signal
            return user

    def bulk_create_users(self, user_data_list):
        """Bulk create users with validation"""
        users = []
        for user_data in user_data_list:
            email = user_data.pop('email')
            password = user_data.pop('password', None)
            user = self.model(email=email, **user_data)
            if password:
                user.set_password(password)
            users.append(user)
        
        return self.bulk_create(users)

    def deactivate_user(self, user_id):
        """Deactivate a user account"""
        try:
            user = self.get(id=user_id)
            user.is_active = False
            user.save(update_fields=['is_active', 'updated_at'])
            return user
        except self.model.DoesNotExist:
            raise ValidationError("User not found")

    def activate_user(self, user_id):
        """Activate a user account"""
        try:
            user = self.get(id=user_id)
            user.is_active = True
            user.save(update_fields=['is_active', 'updated_at'])
            return user
        except self.model.DoesNotExist:
            raise ValidationError("User not found")

    def get_statistics(self):
        """Get user statistics"""
        from django.db.models import Count, Q
        
        return {
            'total_users': self.count(),
            'active_users': self.filter(is_active=True).count(),
            'verified_users': self.filter(email_verified=True).count(),
            'business_owners': self.filter(user_type='business_owner').count(),
            'customers': self.filter(user_type='customer').count(),
            'admins': self.filter(user_type='admin').count(),
            'users_by_province': self.filter(is_active=True).exclude(
                location_province=''
            ).values('location_province').annotate(count=Count('id'))
        }