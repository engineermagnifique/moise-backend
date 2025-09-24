# apps/analytics/views.py
from rest_framework import generics, status, permissions, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, extend_schema_view
from django.db.models import Count, Avg, Q
from django.utils import timezone
from datetime import timedelta

from .models import (
    MarketIntelligence, CustomerInsight, CompetitiveAnalysis,
    RevenueOptimization, BusinessPerformanceMetric, SearchAnalytics,
    UserBehaviorAnalytics
)
from .serializers import (
    MarketIntelligenceSerializer, CustomerInsightSerializer,
    CompetitiveAnalysisSerializer, RevenueOptimizationSerializer,
    BusinessPerformanceMetricSerializer, SearchAnalyticsSerializer,
    UserBehaviorAnalyticsSerializer
)
from .services.business_analytics import BusinessAnalyticsService
from .services.market_intelligence import MarketIntelligenceService
from apps.businesses.models import Business

# Add serializer classes
class BusinessPerformanceSerializer(serializers.Serializer):
    """Serializer for business performance"""
    business_id = serializers.UUIDField()
    business_name = serializers.CharField()
    time_period = serializers.CharField()
    performance_metrics = serializers.DictField()
    customer_insights = serializers.DictField()
    search_performance = serializers.DictField()
    growth_trends = serializers.DictField()
    recommendations = serializers.ListField(child=serializers.CharField())

class MarketIntelligenceSerializer(serializers.Serializer):
    """Serializer for market intelligence"""
    market_overview = serializers.DictField()
    category_trends = serializers.ListField(child=serializers.DictField())
    competitive_landscape = serializers.DictField()
    customer_insights = serializers.DictField()
    growth_opportunities = serializers.ListField(child=serializers.DictField())
    recommendations = serializers.ListField(child=serializers.CharField())

class SearchAnalyticsSerializer(serializers.Serializer):
    """Serializer for search analytics"""
    time_period = serializers.CharField()
    language = serializers.CharField()
    total_searches = serializers.IntegerField()
    average_click_through_rate = serializers.FloatField()
    trending_searches = serializers.ListField(child=serializers.DictField())
    popular_searches = serializers.ListField(child=serializers.DictField())

class UserBehaviorSerializer(serializers.Serializer):
    """Serializer for user behavior analytics"""
    time_period = serializers.CharField()
    location = serializers.CharField(required=False)
    total_sessions = serializers.IntegerField()
    average_session_duration_minutes = serializers.FloatField()
    average_pages_viewed = serializers.FloatField()
    average_searches_performed = serializers.FloatField()
    average_engagement_score = serializers.FloatField()
    top_user_segments = serializers.ListField(child=serializers.DictField())

class BusinessInsightsSerializer(serializers.Serializer):
    """Serializer for business insights"""
    business_id = serializers.UUIDField()
    business_name = serializers.CharField()
    performance_summary = serializers.DictField()
    competitive_position = serializers.DictField()
    market_opportunities = serializers.ListField(child=serializers.CharField())
    customer_feedback = serializers.DictField()
    key_insights = serializers.ListField(child=serializers.CharField())
    action_items = serializers.ListField(child=serializers.CharField())

class MarketTrendsSerializer(serializers.Serializer):
    """Serializer for market trends"""
    current_trends = serializers.ListField(child=serializers.DictField())
    growth_predictions = serializers.DictField()
    seasonal_patterns = serializers.DictField()
    market_forecast = serializers.DictField()

@extend_schema_view(
    get=extend_schema(
        summary="Business Performance Analytics",
        description="Get business performance metrics and analytics",
        tags=["Analytics"]
    )
)
class BusinessPerformanceView(generics.GenericAPIView):
    """Business performance analytics endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = BusinessPerformanceSerializer

    def get(self, request, *args, **kwargs):
        """Get business performance analytics"""
        try:
            business_id = request.query_params.get('business_id')
            time_period = request.query_params.get('time_period', 'month')
            
            if not business_id:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Business ID is required',
                        'code': 'missing_business_id'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get business
            try:
                business = Business.objects.get(business_id=business_id)
            except Business.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Business not found',
                        'code': 'business_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check if user has permission to view this business
            if not (request.user.is_staff or business.owner == request.user):
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Permission denied',
                        'code': 'permission_denied'
                    }
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Get analytics
            analytics_service = BusinessAnalyticsService()
            performance_data = analytics_service.get_business_performance(business, time_period)
            
            return Response({
                'success': True,
                'data': performance_data
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'analytics_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Market Intelligence",
        description="Get market intelligence and insights",
        tags=["Analytics"]
    )
)
class MarketIntelligenceView(generics.GenericAPIView):
    """Market intelligence endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MarketIntelligenceSerializer

    def get(self, request, *args, **kwargs):
        """Get market intelligence data"""
        try:
            category = request.query_params.get('category')
            location = request.query_params.get('location')
            
            intelligence_service = MarketIntelligenceService()
            intelligence_data = intelligence_service.get_market_intelligence(category, location)
            
            return Response({
                'success': True,
                'data': intelligence_data
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'intelligence_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Search Analytics",
        description="Get search analytics and trends",
        tags=["Analytics"]
    )
)
class SearchAnalyticsView(generics.GenericAPIView):
    """Search analytics endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SearchAnalyticsSerializer

    def get(self, request, *args, **kwargs):
        """Get search analytics"""
        try:
            time_period = request.query_params.get('time_period', 'week')
            language = request.query_params.get('language', 'en')
            
            # Calculate time range
            if time_period == 'day':
                since = timezone.now() - timedelta(days=1)
            elif time_period == 'week':
                since = timezone.now() - timedelta(days=7)
            elif time_period == 'month':
                since = timezone.now() - timedelta(days=30)
            else:
                since = timezone.now() - timedelta(days=7)
            
            # Get search analytics
            search_analytics = SearchAnalytics.objects.filter(
                date__gte=since.date(),
                language=language
            ).order_by('-date', '-trend_score')
            
            # Calculate trends
            trending_searches = search_analytics.filter(is_trending=True)[:10]
            
            # Get popular searches
            popular_searches = search_analytics.order_by('-search_count')[:10]
            
            # Calculate metrics
            total_searches = search_analytics.aggregate(
                total=Count('search_count')
            )['total'] or 0
            
            avg_click_through = search_analytics.aggregate(
                avg_ctr=Avg('click_through_rate')
            )['avg_ctr'] or 0
            
            return Response({
                'success': True,
                'data': {
                    'time_period': time_period,
                    'language': language,
                    'total_searches': total_searches,
                    'average_click_through_rate': round(avg_click_through, 2),
                    'trending_searches': [
                        {
                            'search_term': search.search_term,
                            'trend_score': search.trend_score,
                            'search_count': search.search_count
                        }
                        for search in trending_searches
                    ],
                    'popular_searches': [
                        {
                            'search_term': search.search_term,
                            'search_count': search.search_count,
                            'click_through_rate': search.click_through_rate
                        }
                        for search in popular_searches
                    ]
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'search_analytics_error'
                }
            }, status=status.HTTP_500_INternal_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="User Behavior Analytics",
        description="Get user behavior analytics",
        tags=["Analytics"]
    )
)
class UserBehaviorAnalyticsView(generics.GenericAPIView):
    """User behavior analytics endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = UserBehaviorSerializer

    def get(self, request, *args, **kwargs):
        """Get user behavior analytics"""
        try:
            time_period = request.query_params.get('time_period', 'week')
            location = request.query_params.get('location')
            
            # Calculate time range
            if time_period == 'day':
                since = timezone.now() - timedelta(days=1)
            elif time_period == 'week':
                since = timezone.now() - timedelta(days=7)
            elif time_period == 'month':
                since = timezone.now() - timedelta(days=30)
            else:
                since = timezone.now() - timedelta(days=7)
            
            # Get user behavior analytics
            behavior_analytics = UserBehaviorAnalytics.objects.filter(
                date__gte=since.date()
            )
            
            if location:
                behavior_analytics = behavior_analytics.filter(location=location)
            
            # Calculate metrics
            total_sessions = behavior_analytics.count()
            avg_session_duration = behavior_analytics.aggregate(
                avg_duration=Avg('session_duration_minutes')
            )['avg_duration'] or 0
            
            avg_pages_viewed = behavior_analytics.aggregate(
                avg_pages=Avg('pages_viewed')
            )['avg_pages'] or 0
            
            avg_searches = behavior_analytics.aggregate(
                avg_searches=Avg('searches_performed')
            )['avg_searches'] or 0
            
            avg_engagement = behavior_analytics.aggregate(
                avg_engagement=Avg('engagement_score')
            )['avg_engagement'] or 0
            
            # Get top user segments
            top_segments = behavior_analytics.values('user_segment').annotate(
                count=Count('user_segment')
            ).order_by('-count')[:5]
            
            return Response({
                'success': True,
                'data': {
                    'time_period': time_period,
                    'location': location,
                    'total_sessions': total_sessions,
                    'average_session_duration_minutes': round(avg_session_duration, 2),
                    'average_pages_viewed': round(avg_pages_viewed, 2),
                    'average_searches_performed': round(avg_searches, 2),
                    'average_engagement_score': round(avg_engagement, 2),
                    'top_user_segments': [
                        {
                            'segment': item['user_segment'],
                            'count': item['count']
                        }
                        for item in top_segments
                    ]
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'behavior_analytics_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Business Insights",
        description="Get business insights and recommendations",
        tags=["Analytics"]
    )
)
class BusinessInsightsView(generics.GenericAPIView):
    """Business insights endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = BusinessInsightsSerializer

    def get(self, request, *args, **kwargs):
        """Get business insights"""
        try:
            business_id = request.query_params.get('business_id')
            
            if not business_id:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Business ID is required',
                        'code': 'missing_business_id'
                    }
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Get business
            try:
                business = Business.objects.get(business_id=business_id)
            except Business.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Business not found',
                        'code': 'business_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
            
            # Check permissions
            if not (request.user.is_staff or business.owner == request.user):
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Permission denied',
                        'code': 'permission_denied'
                    }
                }, status=status.HTTP_403_FORBIDDEN)
            
            # Get insights
            analytics_service = BusinessAnalyticsService()
            insights = analytics_service.get_business_insights(business)
            
            return Response({
                'success': True,
                'data': insights
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'insights_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    get=extend_schema(
        summary="Market Trends",
        description="Get market trends and predictions",
        tags=["Analytics"]
    )
)
class MarketTrendsView(generics.GenericAPIView):
    """Market trends endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MarketTrendsSerializer

    def get(self, request, *args, **kwargs):
        """Get market trends"""
        try:
            category = request.query_params.get('category')
            location = request.query_params.get('location')
            
            intelligence_service = MarketIntelligenceService()
            trends = intelligence_service.get_market_trends(category, location)
            
            return Response({
                'success': True,
                'data': trends
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'trends_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
