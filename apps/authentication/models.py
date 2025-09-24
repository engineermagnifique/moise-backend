# apps/authentication/models.py
import uuid
import re
import secrets
from datetime import timedelta

from django.contrib.auth.models import AbstractBaseUser, PermissionsMixin
from django.db import models
from django.utils import timezone
from django.core.validators import RegexValidator
from django.db.models.signals import post_save
from django.dispatch import receiver

from .managers import UserManager


class User(AbstractBaseUser, PermissionsMixin):
    """Custom User model with enhanced features for BusiMap Rwanda"""
    
    USER_TYPES = [
        ('customer', 'Customer'),
        ('business_owner', 'Business Owner'),
        ('admin', 'Administrator'),
        ('staff', 'Staff'),
    ]
    
    LANGUAGE_CHOICES = [
        ('en', 'English'),
        ('rw', 'Kinyarwanda'),  
        ('fr', 'Français'),
    ]
    
    # Phone number validator for Rwanda
    phone_regex = RegexValidator(
        regex=r'^(\+250|250|0)[7][0-9]{8}$',
        message="Phone number must be a valid Rwanda format: +2507XXXXXXXX, 2507XXXXXXXX, or 07XXXXXXXX"
    )
    
    # Primary Fields
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    email = models.EmailField(unique=True, db_index=True)
    phone_number = models.CharField(
        validators=[phone_regex], 
        max_length=20, 
        unique=True, 
        db_index=True,
        null=True,
        blank=True,
        help_text="Rwanda phone number format: +2507XXXXXXXX, 2507XXXXXXXX, or 07XXXXXXXX"
    )
    
    # Personal Information
    first_name = models.CharField(max_length=150)
    last_name = models.CharField(max_length=150)
    profile_picture = models.ImageField(upload_to='users/profiles/', null=True, blank=True)
    date_of_birth = models.DateField(null=True, blank=True)
    
    # Location Information
    location_province = models.CharField(max_length=100, blank=True)
    location_district = models.CharField(max_length=100, blank=True)
    location_sector = models.CharField(max_length=100, blank=True)
    location_cell = models.CharField(max_length=100, blank=True)
    current_latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    current_longitude = models.DecimalField(max_digits=11, decimal_places=8, null=True, blank=True)
    
    # Preferences
    user_type = models.CharField(max_length=20, choices=USER_TYPES, default='customer')
    preferred_language = models.CharField(max_length=5, choices=LANGUAGE_CHOICES, default='en')
    notifications_enabled = models.BooleanField(default=True)
    location_sharing_enabled = models.BooleanField(default=True)
    
    # Verification Status
    email_verified = models.BooleanField(default=False)
    phone_verified = models.BooleanField(default=False)
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_superuser = models.BooleanField(default=False)
    
    # Security fields
    failed_login_attempts = models.PositiveIntegerField(default=0)
    locked_until = models.DateTimeField(null=True, blank=True)
    
    # Timestamps
    date_joined = models.DateTimeField(default=timezone.now)
    last_login = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    objects = UserManager()

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['first_name', 'last_name']

    class Meta:
        db_table = 'users'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        indexes = [
            models.Index(fields=['email']),
            models.Index(fields=['phone_number']),
            models.Index(fields=['location_province', 'location_district']),
            models.Index(fields=['user_type']),
            models.Index(fields=['is_active']),
            models.Index(fields=['email_verified', 'phone_verified']),
            models.Index(fields=['is_staff', 'is_superuser']),
        ]

    def __str__(self):
        return f"{self.get_full_name()} ({self.email})"

    def get_full_name(self):
        return f"{self.first_name} {self.last_name}".strip()

    def get_short_name(self):
        return self.first_name

    @property
    def is_business_owner(self):
        return self.user_type == 'business_owner'

    @property
    def is_verified(self):
        """Check if user is verified - phone verification not required if no phone number"""
        if self.phone_number:
            return self.email_verified and self.phone_verified
        return self.email_verified

    @property
    def has_phone_number(self):
        """Check if user has a phone number"""
        return bool(self.phone_number)

    @property
    def is_locked(self):
        return self.locked_until and self.locked_until > timezone.now()

    def clean(self):
        """Custom validation"""
        super().clean()
        if self.phone_number:
            # Normalize phone number before saving
            self.phone_number = self._normalize_phone_number(self.phone_number)

    def save(self, *args, **kwargs):
        """Override save to ensure proper validation"""
        self.clean()
        # Ensure phone_number is None if empty string
        if self.phone_number == '':
            self.phone_number = None
        super().save(*args, **kwargs)

    def lock_account(self, minutes=30):
        """Lock user account for specified minutes"""
        self.locked_until = timezone.now() + timedelta(minutes=minutes)
        self.failed_login_attempts += 1
        self.save(update_fields=['locked_until', 'failed_login_attempts'])

    def unlock_account(self):
        """Unlock user account"""
        self.locked_until = None
        self.failed_login_attempts = 0
        self.save(update_fields=['locked_until', 'failed_login_attempts'])

    def record_login_attempt(self, success=True, ip_address=None, user_agent=None, failure_reason=''):
        """Record login attempt"""
        UserLoginLog.objects.create(
            user=self,
            ip_address=ip_address,
            user_agent=user_agent or '',
            success=success,
            failure_reason=failure_reason
        )
        
        if not success:
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= 5:
                self.lock_account()
            else:
                self.save(update_fields=['failed_login_attempts'])
        else:
            self.failed_login_attempts = 0
            self.locked_until = None
            self.last_login = timezone.now()
            self.save(update_fields=['failed_login_attempts', 'locked_until', 'last_login'])

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
            
        return phone_number


class UserProfile(models.Model):
    """Extended user profile with additional information"""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='profile')
    bio = models.TextField(max_length=500, blank=True)
    
    # Preferences for AI recommendations
    favorite_business_categories = models.JSONField(default=list)
    dietary_preferences = models.JSONField(default=list)
    transportation_preferences = models.JSONField(default=list)
    
    # Privacy Settings
    profile_visibility = models.CharField(
        max_length=20,
        choices=[('public', 'Public'), ('private', 'Private')],
        default='public'
    )
    
    # Analytics
    total_searches = models.PositiveIntegerField(default=0)
    total_business_visits = models.PositiveIntegerField(default=0)
    
    # Notification preferences
    email_notifications = models.BooleanField(default=True)
    sms_notifications = models.BooleanField(default=True)
    push_notifications = models.BooleanField(default=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'user_profiles'
        verbose_name = 'User Profile'
        verbose_name_plural = 'User Profiles'

    def __str__(self):
        return f"Profile for {self.user.get_full_name()}"


class PhoneVerification(models.Model):
    """Phone number verification model"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='phone_verifications')
    phone_number = models.CharField(max_length=20)
    verification_code = models.CharField(max_length=10)
    is_verified = models.BooleanField(default=False)
    attempts = models.PositiveIntegerField(default=0)
    max_attempts = models.PositiveIntegerField(default=5)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'phone_verifications'
        unique_together = ['user', 'phone_number']
        ordering = ['-created_at']
        verbose_name = 'Phone Verification'
        verbose_name_plural = 'Phone Verifications'

    def __str__(self):
        return f"Phone verification for {self.user.email} - {self.phone_number}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @property
    def attempts_remaining(self):
        return max(0, self.max_attempts - self.attempts)

    @property
    def attempts_exceeded(self):
        return self.attempts >= self.max_attempts

    def increment_attempts(self):
        self.attempts += 1
        self.save(update_fields=['attempts'])

    @classmethod
    def generate_code(cls, user, phone_number, expires_in_minutes=10):
        """Generate new verification code using update_or_create"""
        # Generate new code
        code = ''.join(secrets.choice('0123456789') for _ in range(6))
        
        # Use update_or_create to handle existing records
        verification, created = cls.objects.update_or_create(
            user=user,
            phone_number=phone_number,
            defaults={
                'verification_code': code,
                'is_verified': False,
                'attempts': 0,
                'expires_at': timezone.now() + timedelta(minutes=expires_in_minutes),
                'verified_at': None
            }
        )
        
        return verification


class EmailVerification(models.Model):
    """Email verification model"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='email_verifications')
    email = models.EmailField()
    verification_token = models.CharField(max_length=100, unique=True)
    is_verified = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    verified_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        db_table = 'email_verifications'
        ordering = ['-created_at']
        verbose_name = 'Email Verification'
        verbose_name_plural = 'Email Verifications'

    def __str__(self):
        return f"Email verification for {self.user.email}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def generate_token(cls, user, email, expires_in_hours=24):
        """Generate new verification token"""
        # Invalidate existing tokens
        cls.objects.filter(user=user, email=email, is_verified=False).update(
            is_verified=True  # Mark as used
        )
        
        # Generate new token
        token = secrets.token_urlsafe(32)
        
        return cls.objects.create(
            user=user,
            email=email,
            verification_token=token,
            expires_at=timezone.now() + timedelta(hours=expires_in_hours)
        )


class PasswordReset(models.Model):
    """Password reset model"""
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='password_resets')
    reset_token = models.CharField(max_length=100, unique=True)
    is_used = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    expires_at = models.DateTimeField()
    used_at = models.DateTimeField(null=True, blank=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    
    class Meta:
        db_table = 'password_resets'
        ordering = ['-created_at']
        verbose_name = 'Password Reset'
        verbose_name_plural = 'Password Resets'

    def __str__(self):
        return f"Password reset for {self.user.email}"

    @property
    def is_expired(self):
        return timezone.now() > self.expires_at

    @classmethod
    def generate_token(cls, user, ip_address=None, user_agent=None, expires_in_hours=1):
        """Generate new reset token"""
        # Invalidate existing tokens
        cls.objects.filter(user=user, is_used=False).update(is_used=True)
        
        # Generate new token
        token = secrets.token_urlsafe(32)
        
        return cls.objects.create(
            user=user,
            reset_token=token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=timezone.now() + timedelta(hours=expires_in_hours)
        )


class UserLoginLog(models.Model):
    """Track user login attempts and sessions"""
    
    FAILURE_REASONS = [
        ('invalid_credentials', 'Invalid Credentials'),
        ('account_locked', 'Account Locked'),
        ('unverified_account', 'Unverified Account'),
        ('inactive_account', 'Inactive Account'),
        ('other', 'Other'),
    ]
    
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='login_logs')
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    success = models.BooleanField(default=True)
    failure_reason = models.CharField(max_length=100, choices=FAILURE_REASONS, blank=True)
    session_key = models.CharField(max_length=40, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        db_table = 'user_login_logs'
        ordering = ['-created_at']
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['ip_address']),
            models.Index(fields=['success']),
        ]
        verbose_name = 'User Login Log'
        verbose_name_plural = 'User Login Logs'

    def __str__(self):
        status = "Success" if self.success else f"Failed: {self.failure_reason}"
        return f"Login {status} for {self.user.email} from {self.ip_address}"


# Signals
@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    """Create user profile when new user is created"""
    if created:
        UserProfile.objects.create(user=instance)


@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    """Save user profile when user is saved"""
    if hasattr(instance, 'profile'):
        instance.profile.save()