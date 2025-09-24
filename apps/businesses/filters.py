
# apps/businesses/filters.py
import django_filters
from django.db.models import Q
from .models import Business, BusinessCategory

class BusinessFilter(django_filters.FilterSet):
    """Advanced business filtering"""
    
    business_category = django_filters.ModelChoiceFilter(
        field_name='category',
        queryset=BusinessCategory.objects.all(),
        to_field_name='category_id'
    )
    
    province = django_filters.CharFilter(
        field_name='province',
        lookup_expr='iexact'
    )
    
    district = django_filters.CharFilter(
        field_name='district', 
        lookup_expr='iexact'
    )
    
    price_range = django_filters.ChoiceFilter(
        choices=Business.PRICE_RANGE_CHOICES
    )
    
    verification_status = django_filters.ChoiceFilter(
        choices=Business.VERIFICATION_CHOICES
    )
    
    min_rating = django_filters.NumberFilter(
        method='filter_min_rating'
    )
    
    amenities = django_filters.CharFilter(
        method='filter_amenities'
    )
    
    class Meta:
        model = Business
        fields = [
            'business_category', 'province', 'district', 
            'price_range', 'verification_status', 'is_featured'
        ]
    
    def filter_min_rating(self, queryset, name, value):
        """Filter by minimum average rating"""
        from django.db.models import Avg
        return queryset.annotate(
            avg_rating=Avg('reviews__rating_score')
        ).filter(avg_rating__gte=value)
    
    def filter_amenities(self, queryset, name, value):
        """Filter by amenities (comma-separated)"""
        amenities = [a.strip() for a in value.split(',')]
        q = Q()
        for amenity in amenities:
            q |= Q(amenities__contains=[amenity])
        return queryset.filter(q)