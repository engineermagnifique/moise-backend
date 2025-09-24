# apps/transportation/serializers.py
from rest_framework import serializers
from .models import Ride, Driver, FareCalculation, RideReview, VehicleType

class VehicleTypeSerializer(serializers.ModelSerializer):
    """Vehicle type serializer"""
    
    class Meta:
        model = VehicleType
        fields = [
            'vehicle_type_id', 'name', 'description', 'base_fare',
            'per_km_rate', 'per_minute_rate', 'minimum_fare', 'capacity', 'is_active'
        ]

class DriverSerializer(serializers.ModelSerializer):
    """Driver serializer"""
    
    driver_name = serializers.CharField(source='user.get_full_name', read_only=True)
    driver_phone = serializers.CharField(source='user.phone_number', read_only=True)
    vehicle_type_name = serializers.CharField(source='vehicle_type.name', read_only=True)
    
    class Meta:
        model = Driver
        fields = [
            'driver_id', 'driver_name', 'driver_phone', 'license_number',
            'vehicle_type', 'vehicle_type_name', 'vehicle_model', 'vehicle_plate', 'vehicle_color',
            'current_latitude', 'current_longitude', 'is_online', 'is_available',
            'average_rating', 'total_rides', 'total_earnings'
        ]
        read_only_fields = ['driver_id', 'average_rating', 'total_rides', 'total_earnings']

class RideSerializer(serializers.ModelSerializer):
    """Ride serializer"""
    
    passenger_name = serializers.CharField(source='passenger.get_full_name', read_only=True)
    driver_name = serializers.CharField(source='driver.get_full_name', read_only=True)
    vehicle_type_name = serializers.CharField(source='vehicle_type.name', read_only=True)
    
    class Meta:
        model = Ride
        fields = [
            'ride_id', 'passenger', 'passenger_name', 'driver', 'driver_name',
            'pickup_latitude', 'pickup_longitude', 'pickup_address',
            'dropoff_latitude', 'dropoff_longitude', 'dropoff_address',
            'vehicle_type', 'vehicle_type_name', 'status', 'distance_km', 'duration_minutes',
            'estimated_fare', 'actual_fare', 'currency', 'requested_at',
            'accepted_at', 'started_at', 'completed_at', 'cancelled_at',
            'special_instructions', 'passenger_count'
        ]
        read_only_fields = ['ride_id', 'requested_at', 'accepted_at', 'started_at', 'completed_at', 'cancelled_at']

class RideCreateSerializer(serializers.ModelSerializer):
    """Ride creation serializer"""
    
    class Meta:
        model = Ride
        fields = [
            'pickup_latitude', 'pickup_longitude', 'pickup_address',
            'dropoff_latitude', 'dropoff_longitude', 'dropoff_address',
            'vehicle_type', 'special_instructions', 'passenger_count'
        ]

class FareCalculationSerializer(serializers.ModelSerializer):
    """Fare calculation serializer"""
    
    vehicle_type_name = serializers.CharField(source='vehicle_type.name', read_only=True)
    
    class Meta:
        model = FareCalculation
        fields = [
            'calculation_id', 'pickup_latitude', 'pickup_longitude',
            'dropoff_latitude', 'dropoff_longitude', 'distance_km',
            'duration_minutes', 'base_fare', 'distance_fare', 'time_fare',
            'total_fare', 'currency', 'vehicle_type', 'vehicle_type_name', 'surge_multiplier'
        ]
        read_only_fields = ['calculation_id']

class DriverLocationSerializer(serializers.Serializer):
    """Driver location serializer"""
    
    latitude = serializers.DecimalField(max_digits=10, decimal_places=8)
    longitude = serializers.DecimalField(max_digits=11, decimal_places=8)

class RideReviewSerializer(serializers.ModelSerializer):
    """Ride review serializer"""
    
    class Meta:
        model = RideReview
        fields = [
            'review_id', 'ride', 'driver_rating', 'vehicle_rating',
            'overall_rating', 'review_text', 'was_on_time', 'was_polite',
            'vehicle_clean', 'safe_driving'
        ]
        read_only_fields = ['review_id']