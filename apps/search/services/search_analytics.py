# apps/search/services/search_analytics.py
from typing import Dict, Any, List
from django.db.models import Count, Avg, Q
from django.utils import timezone
from datetime import timedelta
from apps.search.models import SearchQuery, PopularSearch
from apps.businesses.models import Business

class SearchAnalyticsService:
    """Service for search analytics and insights"""
    
    def get_search_stats(self, user=None, time_period='week') -> Dict[str, Any]:
        """Get search statistics"""
        
        # Calculate time range
        if time_period == 'day':
            since = timezone.now() - timedelta(days=1)
        elif time_period == 'week':
            since = timezone.now() - timedelta(days=7)
        elif time_period == 'month':
            since = timezone.now() - timedelta(days=30)
        else:
            since = timezone.now() - timedelta(days=7)
        
        # Base queryset
        queryset = SearchQuery.objects.filter(created_at__gte=since)
        
        if user:
            queryset = queryset.filter(user=user)
        
        # Calculate statistics
        total_searches = queryset.count()
        unique_queries = queryset.values('query_text').distinct().count()
        avg_results = queryset.aggregate(avg_results=Avg('results_count'))['avg_results'] or 0
        
        # Most searched terms
        popular_terms = queryset.values('query_text').annotate(
            count=Count('query_text')
        ).order_by('-count')[:10]
        
        # Search by language
        language_stats = queryset.values('original_language').annotate(
            count=Count('original_language')
        ).order_by('-count')
        
        # Search by type
        type_stats = queryset.values('search_type').annotate(
            count=Count('search_type')
        ).order_by('-count')
        
        return {
            'total_searches': total_searches,
            'unique_queries': unique_queries,
            'average_results': round(avg_results, 2),
            'popular_terms': [
                {'term': item['query_text'], 'count': item['count']}
                for item in popular_terms
            ],
            'language_distribution': [
                {'language': item['original_language'], 'count': item['count']}
                for item in language_stats
            ],
            'search_type_distribution': [
                {'type': item['search_type'], 'count': item['count']}
                for item in type_stats
            ],
            'time_period': time_period
        }
    
    def get_trending_searches(self, language='en', time_period='week') -> List[Dict[str, Any]]:
        """Get trending search terms"""
        
        # Calculate time range
        if time_period == 'day':
            since = timezone.now() - timedelta(days=1)
        elif time_period == 'week':
            since = timezone.now() - timedelta(days=7)
        elif time_period == 'month':
            since = timezone.now() - timedelta(days=30)
        else:
            since = timezone.now() - timedelta(days=7)
        
        # Get trending searches
        trending = PopularSearch.objects.filter(
            language=language,
            last_searched__gte=since
        ).order_by('-trend_score', '-search_count')[:20]
        
        return [
            {
                'search_term': search.search_term,
                'search_count': search.search_count,
                'trend_score': search.trend_score,
                'category': search.category,
                'last_searched': search.last_searched.isoformat()
            }
            for search in trending
        ]
    
    def get_search_insights(self, user=None) -> Dict[str, Any]:
        """Get search insights and recommendations"""
        
        # Get user's search history
        user_searches = SearchQuery.objects.filter(user=user) if user else SearchQuery.objects.all()
        
        # Analyze search patterns
        search_patterns = self._analyze_search_patterns(user_searches)
        
        # Get search performance metrics
        performance_metrics = self._calculate_performance_metrics(user_searches)
        
        # Generate insights
        insights = self._generate_insights(search_patterns, performance_metrics)
        
        return {
            'search_patterns': search_patterns,
            'performance_metrics': performance_metrics,
            'insights': insights,
            'recommendations': self._generate_recommendations(search_patterns)
        }
    
    def _analyze_search_patterns(self, searches) -> Dict[str, Any]:
        """Analyze search patterns"""
        
        # Most common search times
        search_times = searches.extra(
            select={'hour': 'EXTRACT(hour FROM created_at)'}
        ).values('hour').annotate(count=Count('hour')).order_by('-count')
        
        # Most common search days
        search_days = searches.extra(
            select={'day': 'EXTRACT(dow FROM created_at)'}
        ).values('day').annotate(count=Count('day')).order_by('-count')
        
        # Search success rate (queries with results)
        successful_searches = searches.filter(results_count__gt=0).count()
        total_searches = searches.count()
        success_rate = (successful_searches / total_searches * 100) if total_searches > 0 else 0
        
        return {
            'peak_hours': [item['hour'] for item in search_times[:5]],
            'peak_days': [item['day'] for item in search_days[:5]],
            'success_rate': round(success_rate, 2),
            'total_searches': total_searches,
            'successful_searches': successful_searches
        }
    
    def _calculate_performance_metrics(self, searches) -> Dict[str, Any]:
        """Calculate search performance metrics"""
        
        # Average response time
        avg_response_time = searches.aggregate(
            avg_time=Avg('response_time_ms')
        )['avg_time'] or 0
        
        # Average results per search
        avg_results = searches.aggregate(
            avg_results=Avg('results_count')
        )['avg_results'] or 0
        
        # Search satisfaction (based on user satisfaction ratings)
        satisfaction_ratings = searches.filter(user_satisfaction__isnull=False)
        avg_satisfaction = satisfaction_ratings.aggregate(
            avg_satisfaction=Avg('user_satisfaction')
        )['avg_satisfaction'] or 0
        
        return {
            'average_response_time_ms': round(avg_response_time, 2),
            'average_results_per_search': round(avg_results, 2),
            'average_satisfaction_rating': round(avg_satisfaction, 2),
            'total_satisfaction_ratings': satisfaction_ratings.count()
        }
    
    def _generate_insights(self, patterns: Dict[str, Any], metrics: Dict[str, Any]) -> List[str]:
        """Generate search insights"""
        
        insights = []
        
        # Success rate insights
        if patterns['success_rate'] > 80:
            insights.append("High search success rate - users are finding what they're looking for")
        elif patterns['success_rate'] < 50:
            insights.append("Low search success rate - consider improving search algorithms")
        
        # Response time insights
        if metrics['average_response_time_ms'] < 500:
            insights.append("Fast search response times - good user experience")
        elif metrics['average_response_time_ms'] > 2000:
            insights.append("Slow search response times - consider optimization")
        
        # Satisfaction insights
        if metrics['average_satisfaction_rating'] > 4.0:
            insights.append("High user satisfaction with search results")
        elif metrics['average_satisfaction_rating'] < 3.0:
            insights.append("Low user satisfaction - consider improving result quality")
        
        # Peak time insights
        if patterns['peak_hours']:
            peak_hour = patterns['peak_hours'][0]
            insights.append(f"Peak search time is {peak_hour}:00 - consider server scaling")
        
        return insights
    
    def _generate_recommendations(self, patterns: Dict[str, Any]) -> List[str]:
        """Generate search recommendations"""
        
        recommendations = []
        
        # Success rate recommendations
        if patterns['success_rate'] < 70:
            recommendations.append("Improve search algorithm to increase success rate")
            recommendations.append("Add more search suggestions and autocomplete")
        
        # Peak time recommendations
        if patterns['peak_hours']:
            recommendations.append("Consider caching popular searches during peak hours")
        
        # General recommendations
        recommendations.extend([
            "Implement search analytics dashboard for better insights",
            "Add search result feedback mechanism",
            "Consider A/B testing different search algorithms"
        ])
        
        return recommendations
    
    def get_business_search_performance(self, business_id: str) -> Dict[str, Any]:
        """Get search performance for a specific business"""
        
        # Get searches that resulted in this business being clicked
        business_searches = SearchQuery.objects.filter(
            clicked_business_ids__contains=[business_id]
        )
        
        # Calculate metrics
        total_appearances = business_searches.count()
        click_through_rate = 0
        
        if total_appearances > 0:
            total_searches = SearchQuery.objects.filter(
                results_count__gt=0
            ).count()
            click_through_rate = (total_appearances / total_searches * 100) if total_searches > 0 else 0
        
        # Get search terms that led to this business
        search_terms = business_searches.values('query_text').annotate(
            count=Count('query_text')
        ).order_by('-count')[:10]
        
        return {
            'total_appearances': total_appearances,
            'click_through_rate': round(click_through_rate, 2),
            'top_search_terms': [
                {'term': item['query_text'], 'count': item['count']}
                for item in search_terms
            ]
        }
    
    def update_search_trends(self):
        """Update search trend scores"""
        
        # Get all popular searches
        popular_searches = PopularSearch.objects.all()
        
        for search in popular_searches:
            # Calculate trend score based on recent activity
            recent_searches = SearchQuery.objects.filter(
                query_text=search.search_term,
                created_at__gte=timezone.now() - timedelta(days=7)
            ).count()
            
            # Update trend score
            search.trend_score = min(recent_searches / 10, 1.0)
            search.save()
    
    def get_search_health_score(self) -> Dict[str, Any]:
        """Get overall search health score"""
        
        # Calculate various metrics
        total_searches = SearchQuery.objects.count()
        successful_searches = SearchQuery.objects.filter(results_count__gt=0).count()
        avg_response_time = SearchQuery.objects.aggregate(
            avg_time=Avg('response_time_ms')
        )['avg_time'] or 0
        
        # Calculate health score (0-100)
        success_rate = (successful_searches / total_searches * 100) if total_searches > 0 else 0
        response_score = max(0, 100 - (avg_response_time / 10))  # Penalize slow responses
        health_score = (success_rate + response_score) / 2
        
        return {
            'health_score': round(health_score, 2),
            'success_rate': round(success_rate, 2),
            'average_response_time_ms': round(avg_response_time, 2),
            'total_searches': total_searches,
            'status': 'healthy' if health_score > 80 else 'needs_attention' if health_score > 60 else 'critical'
        }