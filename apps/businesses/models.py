# apps/businesses/models.py
import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils import timezone
from decimal import Decimal

User = get_user_model()

class BusinessCategory(models.Model):
    """Business categories with multilingual support"""
    
    category_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=100, unique=True)
    name_kinyarwanda = models.CharField(max_length=100, blank=True)
    name_french = models.CharField(max_length=100, blank=True)
    
    description = models.TextField(blank=True)
    description_kinyarwanda = models.TextField(blank=True)
    description_french = models.TextField(blank=True)
    
    parent_category = models.ForeignKey('self', null=True, blank=True, on_delete=models.CASCADE)
    icon = models.CharField(max_length=50, blank=True)  # Icon name/class
    color_code = models.CharField(max_length=7, default='#6366f1')  # Hex color
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'business_categories'
        verbose_name_plural = 'Business Categories'

    def __str__(self):
        return self.name

class Business(models.Model):
    """Core business model with comprehensive information"""
    
    VERIFICATION_CHOICES = [
        ('pending', 'Pending'),
        ('verified', 'Verified'), 
        ('rejected', 'Rejected'),
    ]
    
    PRICE_RANGE_CHOICES = [
        ('low', 'Low ($)'),
        ('medium', 'Medium ($$)'),
        ('high', 'High ($$$)'),
        ('premium', 'Premium ($$$$)'),
    ]
    
    business_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name='owned_businesses')
    
    # Basic Information
    business_name = models.CharField(max_length=200, db_index=True)
    business_name_kinyarwanda = models.CharField(max_length=200, blank=True)
    description = models.TextField()
    description_kinyarwanda = models.TextField(blank=True)
    
    category = models.ForeignKey(BusinessCategory, on_delete=models.SET_NULL, null=True)
    subcategories = models.ManyToManyField(BusinessCategory, related_name='subcategory_businesses', blank=True)
    
    # Location Information
    province = models.CharField(max_length=100)
    district = models.CharField(max_length=100)
    sector = models.CharField(max_length=100)
    cell = models.CharField(max_length=100, blank=True)
    address = models.TextField()
    latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    longitude = models.DecimalField(max_digits=11, decimal_places=8, null=True, blank=True)
    
    # Contact Information
    phone_number = models.CharField(max_length=20)
    secondary_phone = models.CharField(max_length=20, blank=True)
    email = models.EmailField(blank=True)
    website = models.URLField(blank=True)
    
    # Business Details
    business_hours = models.JSONField(default=dict)  # Store opening hours
    price_range = models.CharField(max_length=10, choices=PRICE_RANGE_CHOICES, default='medium')
    amenities = models.JSONField(default=list)  # wifi, parking, etc.
    services_offered = models.JSONField(default=list)
    payment_methods = models.JSONField(default=list)  # cash, mobile_money, etc.
    
    # Media
    logo = models.ImageField(upload_to='businesses/logos/', null=True, blank=True)
    cover_image = models.ImageField(upload_to='businesses/covers/', null=True, blank=True)
    
    # Verification & Status
    verification_status = models.CharField(max_length=10, choices=VERIFICATION_CHOICES, default='pending')
    verification_date = models.DateTimeField(null=True, blank=True)
    verified_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, 
                                   related_name='verified_businesses')
    
    is_active = models.BooleanField(default=True)
    is_featured = models.BooleanField(default=False)
    
    # SEO & Discovery
    search_keywords = models.JSONField(default=list)
    meta_description = models.TextField(blank=True)
    
    # Analytics
    view_count = models.PositiveIntegerField(default=0)
    contact_clicks = models.PositiveIntegerField(default=0)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_active = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'businesses'
        indexes = [
            models.Index(fields=['business_name']),
            models.Index(fields=['category']),
            models.Index(fields=['province', 'district']),
            models.Index(fields=['verification_status']),
            models.Index(fields=['is_active']),
            models.Index(fields=['latitude', 'longitude']),
            models.Index(fields=['created_at']),
        ]

    def __str__(self):
        return self.business_name

    @property
    def average_rating(self):
        """Calculate average rating from reviews"""
        avg = self.reviews.aggregate(models.Avg('rating_score'))['rating_score__avg']
        return round(avg, 1) if avg else 0.0

    @property
    def total_reviews(self):
        """Get total number of reviews"""
        return self.reviews.count()

    def increment_view_count(self):
        """Increment view count atomically"""
        Business.objects.filter(pk=self.pk).update(view_count=models.F('view_count') + 1)

class BusinessImage(models.Model):
    """Additional business images"""
    
    image_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name='images')
    image = models.ImageField(upload_to='businesses/gallery/')
    caption = models.CharField(max_length=200, blank=True)
    is_primary = models.BooleanField(default=False)
    uploaded_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'business_images'

class Review(models.Model):
    """Business reviews and ratings"""
    
    review_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name='reviews')
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE)
    
    rating_score = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)]
    )
    review_text = models.TextField(blank=True)
    
    # Review categories
    service_rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)], null=True, blank=True
    )
    quality_rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)], null=True, blank=True
    )
    value_rating = models.IntegerField(
        validators=[MinValueValidator(1), MaxValueValidator(5)], null=True, blank=True
    )
    
    # Verification
    is_verified_purchase = models.BooleanField(default=False)
    is_anonymous = models.BooleanField(default=False)
    
    # Interaction
    helpful_votes = models.PositiveIntegerField(default=0)
    reported_count = models.PositiveIntegerField(default=0)
    
    # Business Response
    business_response = models.TextField(blank=True)
    response_date = models.DateTimeField(null=True, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'reviews'
        unique_together = ['business', 'reviewer']  # One review per user per business
        indexes = [
            models.Index(fields=['business', 'rating_score']),
            models.Index(fields=['created_at']),
        ]

class BusinessHours(models.Model):
    """Detailed business operating hours"""
    
    WEEKDAYS = [
        ('monday', 'Monday'),
        ('tuesday', 'Tuesday'), 
        ('wednesday', 'Wednesday'),
        ('thursday', 'Thursday'),
        ('friday', 'Friday'),
        ('saturday', 'Saturday'),
        ('sunday', 'Sunday'),
    ]
    
    business = models.ForeignKey(Business, on_delete=models.CASCADE, related_name='operating_hours')
    day_of_week = models.CharField(max_length=10, choices=WEEKDAYS)
    opening_time = models.TimeField()
    closing_time = models.TimeField()
    is_closed = models.BooleanField(default=False)
    
    # Special hours (holidays, etc.)
    is_special_day = models.BooleanField(default=False)
    special_date = models.DateField(null=True, blank=True)
    special_note = models.CharField(max_length=200, blank=True)

    class Meta:
        db_table = 'business_hours'
        unique_together = ['business', 'day_of_week', 'special_date']

class BusinessClaim(models.Model):
    """Business ownership claims"""
    
    CLAIM_STATUS = [
        ('pending', 'Pending'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    
    claim_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(Business, on_delete=models.CASCADE)
    claimant = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Verification documents
    proof_documents = models.JSONField(default=list)  # Store document URLs
    business_license = models.ImageField(upload_to='claims/licenses/', null=True, blank=True)
    identification = models.ImageField(upload_to='claims/ids/', null=True, blank=True)
    
    claim_reason = models.TextField()
    status = models.CharField(max_length=10, choices=CLAIM_STATUS, default='pending')
    
    # Admin review
    reviewed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, 
                                   related_name='reviewed_claims')
    review_notes = models.TextField(blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)
    reviewed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'business_claims'

class BusinessAnalytics(models.Model):
    """Business analytics and insights"""
    
    business = models.OneToOneField(Business, on_delete=models.CASCADE, related_name='analytics')
    
    # View Analytics
    total_views = models.PositiveIntegerField(default=0)
    unique_viewers = models.PositiveIntegerField(default=0)
    views_this_month = models.PositiveIntegerField(default=0)
    views_this_week = models.PositiveIntegerField(default=0)
    
    # Search Analytics
    search_appearances = models.PositiveIntegerField(default=0)
    search_clicks = models.PositiveIntegerField(default=0)
    top_search_keywords = models.JSONField(default=list)
    
    # Engagement Analytics
    contact_clicks = models.PositiveIntegerField(default=0)
    direction_requests = models.PositiveIntegerField(default=0)
    website_clicks = models.PositiveIntegerField(default=0)
    
    # Review Analytics
    review_velocity = models.FloatField(default=0.0)  # Reviews per month
    rating_trend = models.JSONField(default=list)  # Historical rating changes
    
    # Conversion Metrics
    view_to_contact_rate = models.FloatField(default=0.0)
    search_to_view_rate = models.FloatField(default=0.0)
    
    # Peak Times
    peak_hours = models.JSONField(default=list)
    peak_days = models.JSONField(default=list)
    
    last_updated = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'business_analytics'