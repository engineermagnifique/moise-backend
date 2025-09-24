# apps/analytics/serializers.py
from rest_framework import serializers
from .models import (
    MarketIntelligence, CustomerInsight, CompetitiveAnalysis,
    RevenueOptimization, BusinessPerformanceMetric, SearchAnalytics,
    UserBehaviorAnalytics
)

class MarketIntelligenceSerializer(serializers.ModelSerializer):
    """Market intelligence serializer"""
    
    class Meta:
        model = MarketIntelligence
        fields = [
            'intelligence_id', 'category_name', 'location', 'total_businesses',
            'category_growth_rate', 'market_saturation', 'competition_level',
            'peak_search_times', 'popular_search_terms', 'seasonal_trends',
            'average_price_range', 'price_sensitivity', 'recommended_pricing',
            'underserved_areas', 'emerging_trends', 'recommended_improvements',
            'data_period_start', 'data_period_end', 'created_at', 'updated_at'
        ]
        read_only_fields = ['intelligence_id', 'created_at', 'updated_at']

class CustomerInsightSerializer(serializers.ModelSerializer):
    """Customer insight serializer"""
    
    class Meta:
        model = CustomerInsight
        fields = [
            'insight_id', 'business', 'customer_segments', 'overall_satisfaction',
            'service_satisfaction', 'value_satisfaction', 'improvement_areas',
            'growth_potential', 'churn_risk', 'revenue_forecast',
            'analysis_period_days', 'confidence_score', 'created_at', 'updated_at'
        ]
        read_only_fields = ['insight_id', 'created_at', 'updated_at']

class CompetitiveAnalysisSerializer(serializers.ModelSerializer):
    """Competitive analysis serializer"""
    
    class Meta:
        model = CompetitiveAnalysis
        fields = [
            'analysis_id', 'business', 'competitors', 'market_rank',
            'unique_advantages', 'areas_for_improvement', 'differentiation_score',
            'strategic_recommendations', 'radius_km', 'category_focus',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['analysis_id', 'created_at', 'updated_at']

class RevenueOptimizationSerializer(serializers.ModelSerializer):
    """Revenue optimization serializer"""
    
    class Meta:
        model = RevenueOptimization
        fields = [
            'optimization_id', 'business', 'current_metrics', 'optimization_strategies',
            'predicted_outcomes', 'implementation_timeline', 'priority_level',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['optimization_id', 'created_at', 'updated_at']

class BusinessPerformanceMetricSerializer(serializers.ModelSerializer):
    """Business performance metric serializer"""
    
    class Meta:
        model = BusinessPerformanceMetric
        fields = [
            'metric_id', 'business', 'date', 'metric_type', 'value',
            'previous_value', 'change_percentage', 'source', 'notes',
            'created_at', 'updated_at'
        ]
        read_only_fields = ['metric_id', 'created_at', 'updated_at']

class SearchAnalyticsSerializer(serializers.ModelSerializer):
    """Search analytics serializer"""
    
    class Meta:
        model = SearchAnalytics
        fields = [
            'analytics_id', 'search_term', 'search_category', 'location',
            'search_count', 'result_count', 'click_through_rate', 'date',
            'hour', 'trend_score', 'is_trending', 'created_at', 'updated_at'
        ]
        read_only_fields = ['analytics_id', 'created_at', 'updated_at']

class UserBehaviorAnalyticsSerializer(serializers.ModelSerializer):
    """User behavior analytics serializer"""
    
    class Meta:
        model = UserBehaviorAnalytics
        fields = [
            'analytics_id', 'user_segment', 'location', 'session_duration_minutes',
            'pages_viewed', 'searches_performed', 'businesses_contacted', 'date',
            'engagement_score', 'conversion_score', 'created_at', 'updated_at'
        ]
        read_only_fields = ['analytics_id', 'created_at', 'updated_at']

