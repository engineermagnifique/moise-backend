# apps/search/serializers.py
from rest_framework import serializers
from .models import SearchQuery, PopularSearch

class SearchQuerySerializer(serializers.ModelSerializer):
    """Search query serializer"""
    
    class Meta:
        model = SearchQuery
        fields = [
            'query_id', 'user', 'query_text', 'original_language',
            'processed_query', 'user_location', 'search_filters',
            'search_type', 'results_count', 'clicked_business_ids',
            'user_satisfaction', 'response_time_ms', 'search_session_id',
            'created_at'
        ]
        read_only_fields = ['query_id', 'created_at']

class PopularSearchSerializer(serializers.ModelSerializer):
    """Popular search serializer"""
    
    class Meta:
        model = PopularSearch
        fields = [
            'search_term', 'search_count', 'language', 'category',
            'searches_this_week', 'searches_this_month', 'trend_score',
            'last_searched', 'created_at'
        ]
        read_only_fields = ['created_at']

class IntelligentSearchSerializer(serializers.Serializer):
    """Intelligent search serializer"""
    
    query = serializers.CharField()
    language = serializers.CharField(default='en')
    location = serializers.DictField(required=False)
    filters = serializers.DictField(required=False)
    sort_by = serializers.CharField(default='relevance')
    page = serializers.IntegerField(default=1)

class QuickSearchSerializer(serializers.Serializer):
    """Quick search serializer"""
    
    query = serializers.CharField()
    limit = serializers.IntegerField(default=10)

class AdvancedSearchSerializer(serializers.Serializer):
    """Advanced search serializer"""
    
    query = serializers.CharField(required=False)
    category = serializers.CharField(required=False)
    location = serializers.DictField(required=False)
    price_range = serializers.CharField(required=False)
    rating_min = serializers.IntegerField(required=False)
    amenities = serializers.ListField(child=serializers.CharField(), required=False)
    distance_km = serializers.IntegerField(default=10)
    sort_by = serializers.CharField(default='relevance')
    page = serializers.IntegerField(default=1)

class SearchSuggestionSerializer(serializers.Serializer):
    """Search suggestion serializer"""
    
    query = serializers.CharField()
    language = serializers.CharField(default='en')

class SearchResultSerializer(serializers.Serializer):
    """Search result serializer"""
    
    business_id = serializers.CharField()
    business_name = serializers.CharField()
    description = serializers.CharField()
    category = serializers.CharField()
    address = serializers.CharField()
    province = serializers.CharField()
    district = serializers.CharField()
    phone_number = serializers.CharField()
    price_range = serializers.CharField()
    rating = serializers.FloatField()
    total_reviews = serializers.IntegerField()
    verification_status = serializers.CharField()
    latitude = serializers.FloatField(required=False)
    longitude = serializers.FloatField(required=False)
    distance_km = serializers.FloatField(required=False)

class SearchResponseSerializer(serializers.Serializer):
    """Search response serializer"""
    
    success = serializers.BooleanField()
    data = serializers.DictField()
    error = serializers.DictField(required=False)

