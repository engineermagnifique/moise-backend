# apps/businesses/serializers.py
from rest_framework import serializers
from django.db.models import Avg, Count
from .models import Business, BusinessCategory, Review, BusinessImage, BusinessHours
from drf_spectacular.utils import extend_schema_field

class BusinessCategorySerializer(serializers.ModelSerializer):
    """Business category serializer with multilingual support"""
    
    class Meta:
        model = BusinessCategory
        fields = [
            'category_id', 'name', 'name_kinyarwanda', 'name_french',
            'description', 'description_kinyarwanda', 'description_french',
            'parent_category', 'icon', 'color_code', 'is_active'
        ]

class BusinessImageSerializer(serializers.ModelSerializer):
    """Business image serializer"""
    
    class Meta:
        model = BusinessImage
        fields = ['image_id', 'image', 'caption', 'is_primary', 'uploaded_at']

class ReviewSerializer(serializers.ModelSerializer):
    """Review serializer"""
    
    reviewer_name = serializers.CharField(source='reviewer.get_full_name', read_only=True)
    reviewer_profile_picture = serializers.ImageField(source='reviewer.profile_picture', read_only=True)
    
    class Meta:
        model = Review
        fields = [
            'review_id', 'rating_score', 'review_text', 'service_rating',
            'quality_rating', 'value_rating', 'is_verified_purchase',
            'is_anonymous', 'helpful_votes', 'business_response',
            'response_date', 'created_at', 'reviewer_name', 'reviewer_profile_picture'
        ]
        read_only_fields = ['review_id', 'helpful_votes', 'created_at']

class BusinessHoursSerializer(serializers.ModelSerializer):
    """Business hours serializer"""
    
    class Meta:
        model = BusinessHours
        fields = [
            'day_of_week', 'opening_time', 'closing_time', 'is_closed',
            'is_special_day', 'special_date', 'special_note'
        ]

class BusinessListSerializer(serializers.ModelSerializer):
    """Serializer for business list views"""
    
    category_name = serializers.CharField(source='category.name', read_only=True)
    average_rating_score = serializers.SerializerMethodField()
    total_reviews = serializers.SerializerMethodField()
    images = BusinessImageSerializer(many=True, read_only=True)
    
    class Meta:
        model = Business
        fields = [
            'business_id', 'business_name', 'description', 'category_name',
            'province', 'district', 'sector', 'address', 'phone_number',
            'latitude', 'longitude', 'price_range', 'amenities',
            'average_rating_score', 'total_reviews', 'verification_status',
            'is_featured', 'images', 'created_at'
        ]

    @extend_schema_field(serializers.FloatField)
    def get_average_rating_score(self, obj):
        return obj.average_rating

    @extend_schema_field(serializers.IntegerField)
    def get_total_reviews(self, obj):
        return obj.total_reviews

class BusinessDetailSerializer(serializers.ModelSerializer):
    """Detailed business serializer"""
    
    category = BusinessCategorySerializer(read_only=True)
    subcategories = BusinessCategorySerializer(many=True, read_only=True)
    images = BusinessImageSerializer(many=True, read_only=True)
    reviews = ReviewSerializer(many=True, read_only=True)
    operating_hours = BusinessHoursSerializer(many=True, read_only=True)
    
    average_rating_score = serializers.SerializerMethodField()
    total_reviews = serializers.SerializerMethodField()
    owner_name = serializers.CharField(source='owner.get_full_name', read_only=True)
    
    class Meta:
        model = Business
        fields = [
            'business_id', 'business_name', 'business_name_kinyarwanda',
            'description', 'description_kinyarwanda', 'category', 'subcategories',
            'province', 'district', 'sector', 'cell', 'address',
            'latitude', 'longitude', 'phone_number', 'secondary_phone',
            'email', 'website', 'business_hours', 'price_range',
            'amenities', 'services_offered', 'payment_methods',
            'logo', 'cover_image', 'verification_status', 'is_active',
            'is_featured', 'search_keywords', 'view_count',
            'average_rating_score', 'total_reviews', 'images',
            'reviews', 'operating_hours', 'owner_name', 'created_at', 'updated_at'
        ]

    @extend_schema_field(serializers.FloatField)
    def get_average_rating_score(self, obj):
        return obj.average_rating

    @extend_schema_field(serializers.IntegerField)
    def get_total_reviews(self, obj):
        return obj.total_reviews

class BusinessCreateSerializer(serializers.ModelSerializer):
    """Business creation serializer"""
    
    operating_hours = BusinessHoursSerializer(many=True, required=False)
    images = BusinessImageSerializer(many=True, required=False, read_only=True)
    
    class Meta:
        model = Business
        fields = [
            'business_name', 'business_name_kinyarwanda', 'description',
            'description_kinyarwanda', 'category', 'subcategories',
            'province', 'district', 'sector', 'cell', 'address',
            'latitude', 'longitude', 'phone_number', 'secondary_phone',
            'email', 'website', 'business_hours', 'price_range',
            'amenities', 'services_offered', 'payment_methods',
            'logo', 'cover_image', 'search_keywords', 'operating_hours', 'images'
        ]

    def create(self, validated_data):
        operating_hours_data = validated_data.pop('operating_hours', [])
        subcategories_data = validated_data.pop('subcategories', [])
        
        # Set owner to current user
        validated_data['owner'] = self.context['request'].user
        
        business = Business.objects.create(**validated_data)
        
        # Add subcategories
        if subcategories_data:
            business.subcategories.set(subcategories_data)
        
        # Create operating hours
        for hours_data in operating_hours_data:
            BusinessHours.objects.create(business=business, **hours_data)
        
        return business

    def update(self, instance, validated_data):
        """Custom update method to handle nested fields"""
        # Extract nested data
        operating_hours_data = validated_data.pop('operating_hours', None)
        subcategories_data = validated_data.pop('subcategories', None)
        
        # Update main business fields
        for attr, value in validated_data.items():
            setattr(instance, attr, value)
        instance.save()
        
        # Handle subcategories update
        if subcategories_data is not None:
            instance.subcategories.set(subcategories_data)
        
        # Handle operating hours update
        if operating_hours_data is not None:
            # Clear existing operating hours
            instance.operating_hours.all().delete()
            
            # Create new operating hours
            for hours_data in operating_hours_data:
                BusinessHours.objects.create(business=instance, **hours_data)
        
        return instance

class ReviewCreateSerializer(serializers.ModelSerializer):
    """Review creation serializer"""
    
    class Meta:
        model = Review
        fields = [
            'rating_score', 'review_text', 'service_rating',
            'quality_rating', 'value_rating', 'is_verified_purchase',
            'is_anonymous'
        ]

    def create(self, validated_data):
        validated_data['reviewer'] = self.context['request'].user
        validated_data['business'] = self.context['business']
        return super().create(validated_data)