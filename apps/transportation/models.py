# apps/transportation/models.py
import uuid
from django.db import models
from django.contrib.auth import get_user_model
from apps.common.models import TimestampedModel

User = get_user_model()

class VehicleType(TimestampedModel):
    """Vehicle type model for different transportation options"""
    
    VEHICLE_CATEGORIES = [
        ('motorcycle', 'Motorcycle'),
        ('car', 'Car'),
        ('van', 'Van'),
        ('bus', 'Bus'),
    ]
    
    vehicle_type_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=20, choices=VEHICLE_CATEGORIES, unique=True)
    description = models.TextField(blank=True)
    base_fare = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    per_km_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    per_minute_rate = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    minimum_fare = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    capacity = models.PositiveIntegerField(default=1)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'vehicle_types'
        verbose_name = 'Vehicle Type'
        verbose_name_plural = 'Vehicle Types'
    
    def __str__(self):
        return self.get_name_display()

class Driver(TimestampedModel):
    """Driver profile and information"""
    
    driver_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='driver_profile')
    
    # Driver Information
    license_number = models.CharField(max_length=50, unique=True)
    license_expiry = models.DateField()
    vehicle_type = models.ForeignKey(VehicleType, on_delete=models.PROTECT, related_name='drivers')
    vehicle_model = models.CharField(max_length=100)
    vehicle_plate = models.CharField(max_length=20)
    vehicle_color = models.CharField(max_length=50)
    
    # Location
    current_latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    current_longitude = models.DecimalField(max_digits=11, decimal_places=8, null=True, blank=True)
    location_updated_at = models.DateTimeField(null=True, blank=True)
    
    # Status
    is_online = models.BooleanField(default=False)
    is_available = models.BooleanField(default=True)
    is_verified = models.BooleanField(default=False)
    
    # Ratings and Reviews
    average_rating = models.DecimalField(max_digits=3, decimal_places=2, default=0.0)
    total_rides = models.PositiveIntegerField(default=0)
    total_earnings = models.DecimalField(max_digits=10, decimal_places=2, default=0.0)
    
    # Documents
    license_image = models.ImageField(upload_to='drivers/licenses/', null=True, blank=True)
    vehicle_image = models.ImageField(upload_to='drivers/vehicles/', null=True, blank=True)
    insurance_document = models.ImageField(upload_to='drivers/insurance/', null=True, blank=True)
    
    class Meta:
        db_table = 'drivers'
        verbose_name = 'Driver'
        verbose_name_plural = 'Drivers'

    def __str__(self):
        return f"{self.user.get_full_name()} - {self.vehicle_type.name}"

class Ride(TimestampedModel):
    """Ride requests and bookings"""
    
    RIDE_STATUS = [
        ('pending', 'Pending'),
        ('accepted', 'Accepted'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('cancelled', 'Cancelled'),
    ]
    
    ride_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    passenger = models.ForeignKey(User, on_delete=models.CASCADE, related_name='rides_as_passenger')
    driver = models.ForeignKey(User, on_delete=models.CASCADE, related_name='rides_as_driver', null=True, blank=True)
    
    # Pickup and Dropoff
    pickup_latitude = models.DecimalField(max_digits=10, decimal_places=8)
    pickup_longitude = models.DecimalField(max_digits=11, decimal_places=8)
    pickup_address = models.TextField()
    dropoff_latitude = models.DecimalField(max_digits=10, decimal_places=8)
    dropoff_longitude = models.DecimalField(max_digits=11, decimal_places=8)
    dropoff_address = models.TextField()
    
    # Ride Details
    vehicle_type = models.ForeignKey(VehicleType, on_delete=models.PROTECT, related_name='rides')
    status = models.CharField(max_length=20, choices=RIDE_STATUS, default='pending')
    distance_km = models.DecimalField(max_digits=8, decimal_places=2, null=True, blank=True)
    duration_minutes = models.PositiveIntegerField(null=True, blank=True)
    
    # Fare Information
    estimated_fare = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    actual_fare = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
    currency = models.CharField(max_length=3, default='RWF')
    
    # Timestamps
    requested_at = models.DateTimeField(auto_now_add=True)
    accepted_at = models.DateTimeField(null=True, blank=True)
    started_at = models.DateTimeField(null=True, blank=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    cancelled_at = models.DateTimeField(null=True, blank=True)
    
    # Additional Information
    special_instructions = models.TextField(blank=True)
    passenger_count = models.PositiveIntegerField(default=1)
    
    class Meta:
        db_table = 'rides'
        verbose_name = 'Ride'
        verbose_name_plural = 'Rides'
        indexes = [
            models.Index(fields=['passenger', 'status']),
            models.Index(fields=['driver', 'status']),
            models.Index(fields=['status', 'requested_at']),
        ]

    def __str__(self):
        return f"Ride {self.ride_id} - {self.passenger.get_full_name()}"

class FareCalculation(TimestampedModel):
    """Fare calculation records"""
    
    calculation_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    
    # Route Information
    pickup_latitude = models.DecimalField(max_digits=10, decimal_places=8)
    pickup_longitude = models.DecimalField(max_digits=11, decimal_places=8)
    dropoff_latitude = models.DecimalField(max_digits=10, decimal_places=8)
    dropoff_longitude = models.DecimalField(max_digits=11, decimal_places=8)
    distance_km = models.DecimalField(max_digits=8, decimal_places=2)
    duration_minutes = models.PositiveIntegerField()
    
    # Fare Details
    base_fare = models.DecimalField(max_digits=10, decimal_places=2)
    distance_fare = models.DecimalField(max_digits=10, decimal_places=2)
    time_fare = models.DecimalField(max_digits=10, decimal_places=2)
    total_fare = models.DecimalField(max_digits=10, decimal_places=2)
    currency = models.CharField(max_length=3, default='RWF')
    
    # Vehicle Type
    vehicle_type = models.ForeignKey(VehicleType, on_delete=models.PROTECT, related_name='fare_calculations')
    
    # Metadata
    calculation_method = models.CharField(max_length=50, default='standard')
    surge_multiplier = models.DecimalField(max_digits=3, decimal_places=2, default=1.0)
    
    class Meta:
        db_table = 'fare_calculations'
        verbose_name = 'Fare Calculation'
        verbose_name_plural = 'Fare Calculations'

    def __str__(self):
        return f"Fare Calculation {self.calculation_id} - {self.total_fare} {self.currency}"

class RideReview(TimestampedModel):
    """Ride reviews and ratings"""
    
    review_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    ride = models.OneToOneField(Ride, on_delete=models.CASCADE, related_name='review')
    reviewer = models.ForeignKey(User, on_delete=models.CASCADE)
    
    # Ratings
    driver_rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    vehicle_rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    overall_rating = models.IntegerField(choices=[(i, i) for i in range(1, 6)])
    
    # Review Text
    review_text = models.TextField(blank=True)
    
    # Specific Feedback
    was_on_time = models.BooleanField(default=True)
    was_polite = models.BooleanField(default=True)
    vehicle_clean = models.BooleanField(default=True)
    safe_driving = models.BooleanField(default=True)
    
    class Meta:
        db_table = 'ride_reviews'
        verbose_name = 'Ride Review'
        verbose_name_plural = 'Ride Reviews'

    def __str__(self):
        return f"Review for Ride {self.ride.ride_id} - {self.overall_rating} stars"