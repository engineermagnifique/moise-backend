# apps/analytics/services/business_analytics.py
from typing import Dict, Any, List
from django.db.models import Count, Avg, Q, F
from django.utils import timezone
from datetime import timedelta
from apps.businesses.models import Business, Review
from apps.search.models import SearchQuery
from .. models import BusinessPerformanceMetric, CustomerInsight

class BusinessAnalyticsService:
    """Service for business analytics and insights"""
    
    def get_business_performance(self, business: Business, time_period: str = 'month') -> Dict[str, Any]:
        """Get comprehensive business performance metrics"""
        
        # Calculate time range
        if time_period == 'day':
            since = timezone.now() - timedelta(days=1)
        elif time_period == 'week':
            since = timezone.now() - timedelta(days=7)
        elif time_period == 'month':
            since = timezone.now() - timedelta(days=30)
        else:
            since = timezone.now() - timedelta(days=30)
        
        # Get performance metrics
        metrics = self._calculate_performance_metrics(business, since)
        
        # Get customer insights
        customer_insights = self._get_customer_insights(business, since)
        
        # Get search performance
        search_performance = self._get_search_performance(business, since)
        
        # Get growth trends
        growth_trends = self._get_growth_trends(business, time_period)
        
        return {
            'business_id': str(business.business_id),
            'business_name': business.business_name,
            'time_period': time_period,
            'performance_metrics': metrics,
            'customer_insights': customer_insights,
            'search_performance': search_performance,
            'growth_trends': growth_trends,
            'recommendations': self._generate_recommendations(metrics, customer_insights)
        }
    
    def _calculate_performance_metrics(self, business: Business, since: timezone.datetime) -> Dict[str, Any]:
        """Calculate key performance metrics"""
        
        # View metrics
        total_views = business.view_count
        recent_views = business.view_count  # Simplified - in production, track daily views
        
        # Review metrics
        reviews = business.reviews.all()
        total_reviews = reviews.count()
        avg_rating = reviews.aggregate(avg_rating=Avg('rating_score'))['avg_rating'] or 0
        
        # Recent reviews
        recent_reviews = reviews.filter(created_at__gte=since)
        recent_review_count = recent_reviews.count()
        recent_avg_rating = recent_reviews.aggregate(avg_rating=Avg('rating_score'))['avg_rating'] or 0
        
        # Contact metrics (simplified)
        contact_clicks = business.contact_clicks
        
        # Search appearances
        search_appearances = SearchQuery.objects.filter(
            clicked_business_ids__contains=[str(business.business_id)]
        ).count()
        
        return {
            'total_views': total_views,
            'recent_views': recent_views,
            'total_reviews': total_reviews,
            'average_rating': round(avg_rating, 2),
            'recent_reviews': recent_review_count,
            'recent_average_rating': round(recent_avg_rating, 2),
            'contact_clicks': contact_clicks,
            'search_appearances': search_appearances,
            'verification_status': business.verification_status
        }
    
    def _get_customer_insights(self, business: Business, since: timezone.datetime) -> Dict[str, Any]:
        """Get customer insights and satisfaction metrics"""
        
        reviews = business.reviews.filter(created_at__gte=since)
        
        # Satisfaction breakdown
        satisfaction_breakdown = {
            'service': reviews.aggregate(avg=Avg('service_rating'))['avg'] or 0,
            'quality': reviews.aggregate(avg=Avg('quality_rating'))['avg'] or 0,
            'value': reviews.aggregate(avg=Avg('value_rating'))['avg'] or 0
        }
        
        # Review sentiment (simplified)
        positive_reviews = reviews.filter(rating_score__gte=4).count()
        negative_reviews = reviews.filter(rating_score__lte=2).count()
        neutral_reviews = reviews.filter(rating_score=3).count()
        
        # Customer segments (simplified)
        customer_segments = {
            'new_customers': reviews.filter(created_at__gte=since).count(),
            'returning_customers': 0,  # Would need more complex tracking
            'verified_purchases': reviews.filter(is_verified_purchase=True).count()
        }
        
        return {
            'total_reviews_analyzed': reviews.count(),
            'satisfaction_breakdown': satisfaction_breakdown,
            'sentiment_distribution': {
                'positive': positive_reviews,
                'neutral': neutral_reviews,
                'negative': negative_reviews
            },
            'customer_segments': customer_segments,
            'improvement_areas': self._identify_improvement_areas(satisfaction_breakdown)
        }
    
    def _get_search_performance(self, business: Business, since: timezone.datetime) -> Dict[str, Any]:
        """Get search performance metrics"""
        
        # Search appearances
        search_queries = SearchQuery.objects.filter(
            clicked_business_ids__contains=[str(business.business_id)],
            created_at__gte=since
        )
        
        total_appearances = search_queries.count()
        
        # Top search terms
        search_terms = search_queries.values('query_text').annotate(
            count=Count('query_text')
        ).order_by('-count')[:10]
        
        # Click-through rate (simplified)
        total_searches = SearchQuery.objects.filter(created_at__gte=since).count()
        click_through_rate = (total_appearances / total_searches * 100) if total_searches > 0 else 0
        
        return {
            'total_appearances': total_appearances,
            'click_through_rate': round(click_through_rate, 2),
            'top_search_terms': [
                {'term': item['query_text'], 'count': item['count']}
                for item in search_terms
            ],
            'search_rank': self._calculate_search_rank(business)
        }
    
    def _get_growth_trends(self, business: Business, time_period: str) -> Dict[str, Any]:
        """Get growth trends and patterns"""
        
        # Calculate periods for comparison
        if time_period == 'month':
            current_period = timezone.now() - timedelta(days=30)
            previous_period = timezone.now() - timedelta(days=60)
        elif time_period == 'week':
            current_period = timezone.now() - timedelta(days=7)
            previous_period = timezone.now() - timedelta(days=14)
        else:
            current_period = timezone.now() - timedelta(days=30)
            previous_period = timezone.now() - timedelta(days=60)
        
        # View growth
        current_views = business.view_count  # Simplified
        previous_views = business.view_count * 0.8  # Placeholder
        view_growth = ((current_views - previous_views) / previous_views * 100) if previous_views > 0 else 0
        
        # Review growth
        current_reviews = business.reviews.filter(created_at__gte=current_period).count()
        previous_reviews = business.reviews.filter(
            created_at__gte=previous_period,
            created_at__lt=current_period
        ).count()
        review_growth = ((current_reviews - previous_reviews) / previous_reviews * 100) if previous_reviews > 0 else 0
        
        return {
            'view_growth_percentage': round(view_growth, 2),
            'review_growth_percentage': round(review_growth, 2),
            'current_period_views': current_views,
            'current_period_reviews': current_reviews,
            'trend_direction': 'up' if view_growth > 0 else 'down' if view_growth < 0 else 'stable'
        }
    
    def _identify_improvement_areas(self, satisfaction_breakdown: Dict[str, float]) -> List[str]:
        """Identify areas for improvement based on satisfaction scores"""
        
        improvement_areas = []
        
        for area, score in satisfaction_breakdown.items():
            if score < 3.5:  # Below average
                improvement_areas.append(f"Improve {area} quality")
        
        if not improvement_areas:
            improvement_areas.append("Maintain current quality standards")
        
        return improvement_areas
    
    def _calculate_search_rank(self, business: Business) -> int:
        """Calculate search ranking (simplified)"""
        
        # Simple ranking based on views and rating
        base_rank = 100 - (business.view_count / 100)  # Lower views = higher rank number
        rating_bonus = business.average_rating * 10  # Higher rating = better rank
        
        return max(1, int(base_rank - rating_bonus))
    
    def _generate_recommendations(self, metrics: Dict[str, Any], customer_insights: Dict[str, Any]) -> List[str]:
        """Generate actionable recommendations"""
        
        recommendations = []
        
        # View recommendations
        if metrics['total_views'] < 100:
            recommendations.append("Increase visibility through better SEO and social media presence")
        
        # Rating recommendations
        if metrics['average_rating'] < 4.0:
            recommendations.append("Focus on improving service quality to increase ratings")
        
        # Review recommendations
        if metrics['total_reviews'] < 10:
            recommendations.append("Encourage customers to leave reviews after their visit")
        
        # Contact recommendations
        if metrics['contact_clicks'] < 5:
            recommendations.append("Make contact information more prominent and accessible")
        
        # Search recommendations
        if metrics['search_appearances'] < 20:
            recommendations.append("Optimize business listing for better search visibility")
        
        # Customer insight recommendations
        improvement_areas = customer_insights.get('improvement_areas', [])
        recommendations.extend(improvement_areas)
        
        return recommendations[:5]  # Limit to top 5 recommendations
    
    def get_business_insights(self, business: Business) -> Dict[str, Any]:
        """Get comprehensive business insights"""
        
        # Get recent performance
        recent_performance = self.get_business_performance(business, 'month')
        
        # Get competitive position
        competitive_position = self._get_competitive_position(business)
        
        # Get market opportunities
        market_opportunities = self._get_market_opportunities(business)
        
        # Get customer feedback summary
        customer_feedback = self._get_customer_feedback_summary(business)
        
        return {
            'business_id': str(business.business_id),
            'business_name': business.business_name,
            'performance_summary': recent_performance,
            'competitive_position': competitive_position,
            'market_opportunities': market_opportunities,
            'customer_feedback': customer_feedback,
            'key_insights': self._generate_key_insights(recent_performance, competitive_position),
            'action_items': self._generate_action_items(recent_performance, market_opportunities)
        }
    
    def _get_competitive_position(self, business: Business) -> Dict[str, Any]:
        """Get competitive position analysis"""
        
        # Get similar businesses in the same category and location
        competitors = Business.objects.filter(
            category=business.category,
            province=business.province,
            is_active=True
        ).exclude(business_id=business.business_id)
        
        # Calculate position metrics
        total_competitors = competitors.count()
        better_rated = competitors.filter(
            reviews__rating_score__gt=business.average_rating
        ).count()
        
        market_position = {
            'total_competitors': total_competitors,
            'better_rated_competitors': better_rated,
            'market_rank': better_rated + 1,
            'competitive_advantage': self._identify_competitive_advantages(business, competitors)
        }
        
        return market_position
    
    def _get_market_opportunities(self, business: Business) -> List[str]:
        """Get market opportunities for the business"""
        
        opportunities = []
        
        # Category opportunities
        if business.category:
            opportunities.append(f"Expand services in {business.category.name} category")
        
        # Location opportunities
        opportunities.append(f"Target customers in nearby districts")
        
        # Service opportunities
        if 'wifi' not in business.amenities:
            opportunities.append("Add WiFi as an amenity to attract more customers")
        
        if 'parking' not in business.amenities:
            opportunities.append("Provide parking facilities")
        
        # Digital opportunities
        if not business.website:
            opportunities.append("Create a website to improve online presence")
        
        return opportunities[:5]
    
    def _get_customer_feedback_summary(self, business: Business) -> Dict[str, Any]:
        """Get customer feedback summary"""
        
        recent_reviews = business.reviews.filter(
            created_at__gte=timezone.now() - timedelta(days=30)
        )
        
        if not recent_reviews.exists():
            return {
                'total_feedback': 0,
                'sentiment': 'neutral',
                'common_themes': [],
                'satisfaction_score': 0
            }
        
        # Analyze review themes (simplified)
        positive_themes = []
        negative_themes = []
        
        for review in recent_reviews:
            if review.rating_score >= 4:
                positive_themes.append("Good service")
            else:
                negative_themes.append("Needs improvement")
        
        return {
            'total_feedback': recent_reviews.count(),
            'sentiment': 'positive' if len(positive_themes) > len(negative_themes) else 'negative',
            'common_themes': list(set(positive_themes + negative_themes)),
            'satisfaction_score': recent_reviews.aggregate(avg=Avg('rating_score'))['avg'] or 0
        }
    
    def _identify_competitive_advantages(self, business: Business, competitors) -> List[str]:
        """Identify competitive advantages"""
        
        advantages = []
        
        # Rating advantage
        if business.average_rating > 4.0:
            advantages.append("High customer ratings")
        
        # Verification advantage
        if business.verification_status == 'verified':
            advantages.append("Verified business status")
        
        # Feature advantages
        if business.is_featured:
            advantages.append("Featured listing")
        
        # Amenity advantages
        if len(business.amenities) > 3:
            advantages.append("Comprehensive amenities")
        
        return advantages
    
    def _generate_key_insights(self, performance: Dict[str, Any], competitive: Dict[str, Any]) -> List[str]:
        """Generate key insights"""
        
        insights = []
        
        # Performance insights
        if performance['performance_metrics']['average_rating'] > 4.5:
            insights.append("Excellent customer satisfaction - maintain current standards")
        
        if performance['performance_metrics']['total_views'] > 500:
            insights.append("Strong online visibility - leverage for growth")
        
        # Competitive insights
        if competitive['market_rank'] <= 3:
            insights.append("Top performer in your category - consider expansion")
        
        if competitive['total_competitors'] > 10:
            insights.append("Highly competitive market - focus on differentiation")
        
        return insights
    
    def _generate_action_items(self, performance: Dict[str, Any], opportunities: List[str]) -> List[str]:
        """Generate actionable items"""
        
        action_items = []
        
        # High priority items
        if performance['performance_metrics']['average_rating'] < 3.5:
            action_items.append("URGENT: Improve service quality to increase ratings")
        
        if performance['performance_metrics']['total_reviews'] < 5:
            action_items.append("HIGH: Implement review collection strategy")
        
        # Medium priority items
        action_items.extend(opportunities[:3])
        
        # Low priority items
        action_items.append("Consider seasonal promotions and events")
        action_items.append("Explore partnership opportunities")
        
        return action_items[:5]

