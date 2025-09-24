# apps/analytics/services/market_intelligence.py
from typing import Dict, Any, List, Optional
from django.db.models import Count, Avg, Q
from django.utils import timezone
from datetime import timedelta
from apps.businesses.models import Business, BusinessCategory
from apps.search.models import SearchQuery, PopularSearch
from ..models import MarketIntelligence

class MarketIntelligenceService:
    """Service for market intelligence and insights"""
    
    def get_market_intelligence(self, category: Optional[str] = None, location: Optional[str] = None) -> Dict[str, Any]:
        """Get market intelligence data"""
        
        # Get market overview
        market_overview = self._get_market_overview(category, location)
        
        # Get category trends
        category_trends = self._get_category_trends(category, location)
        
        # Get competitive landscape
        competitive_landscape = self._get_competitive_landscape(category, location)
        
        # Get customer insights
        customer_insights = self._get_customer_insights(category, location)
        
        # Get growth opportunities
        growth_opportunities = self._get_growth_opportunities(category, location)
        
        return {
            'market_overview': market_overview,
            'category_trends': category_trends,
            'competitive_landscape': competitive_landscape,
            'customer_insights': customer_insights,
            'growth_opportunities': growth_opportunities,
            'recommendations': self._generate_market_recommendations(market_overview, category_trends)
        }
    
    def _get_market_overview(self, category: Optional[str], location: Optional[str]) -> Dict[str, Any]:
        """Get market overview statistics"""
        
        # Base queryset
        businesses = Business.objects.filter(is_active=True, verification_status='verified')
        
        if category:
            businesses = businesses.filter(category__name__icontains=category)
        
        if location:
            businesses = businesses.filter(
                Q(province__icontains=location) | Q(district__icontains=location)
            )
        
        # Calculate metrics
        total_businesses = businesses.count()
        verified_businesses = businesses.filter(verification_status='verified').count()
        avg_rating = businesses.aggregate(avg_rating=Avg('reviews__rating_score'))['avg_rating'] or 0
        total_reviews = businesses.aggregate(total_reviews=Count('reviews'))['total_reviews'] or 0
        
        # Growth rate (simplified)
        thirty_days_ago = timezone.now() - timedelta(days=30)
        new_businesses = businesses.filter(created_at__gte=thirty_days_ago).count()
        growth_rate = (new_businesses / total_businesses * 100) if total_businesses > 0 else 0
        
        return {
            'total_businesses': total_businesses,
            'verified_businesses': verified_businesses,
            'average_rating': round(avg_rating, 2),
            'total_reviews': total_reviews,
            'new_businesses_30_days': new_businesses,
            'growth_rate_percentage': round(growth_rate, 2),
            'market_saturation': self._calculate_market_saturation(total_businesses, location)
        }
    
    def _get_category_trends(self, category: Optional[str], location: Optional[str]) -> List[Dict[str, Any]]:
        """Get category trends and performance"""
        
        # Get all categories or specific category
        if category:
            categories = BusinessCategory.objects.filter(name__icontains=category)
        else:
            categories = BusinessCategory.objects.all()
        
        trends = []
        
        for cat in categories:
            # Get businesses in this category
            category_businesses = Business.objects.filter(
                category=cat,
                is_active=True,
                verification_status='verified'
            )
            
            if location:
                category_businesses = category_businesses.filter(
                    Q(province__icontains=location) | Q(district__icontains=location)
                )
            
            # Calculate metrics
            business_count = category_businesses.count()
            avg_rating = category_businesses.aggregate(
                avg_rating=Avg('reviews__rating_score')
            )['avg_rating'] or 0
            
            # Search popularity
            search_count = SearchQuery.objects.filter(
                query_text__icontains=cat.name
            ).count()
            
            # Growth trend (simplified)
            thirty_days_ago = timezone.now() - timedelta(days=30)
            recent_businesses = category_businesses.filter(created_at__gte=thirty_days_ago).count()
            growth_trend = 'up' if recent_businesses > 0 else 'stable'
            
            trends.append({
                'category_name': cat.name,
                'business_count': business_count,
                'average_rating': round(avg_rating, 2),
                'search_popularity': search_count,
                'growth_trend': growth_trend,
                'market_share': 0  # Would need total market size
            })
        
        return sorted(trends, key=lambda x: x['business_count'], reverse=True)[:10]
    
    def _get_competitive_landscape(self, category: Optional[str], location: Optional[str]) -> Dict[str, Any]:
        """Get competitive landscape analysis"""
        
        # Get businesses for analysis
        businesses = Business.objects.filter(
            is_active=True,
            verification_status='verified'
        )
        
        if category:
            businesses = businesses.filter(category__name__icontains=category)
        
        if location:
            businesses = businesses.filter(
                Q(province__icontains=location) | Q(district__icontains=location)
            )
        
        # Calculate competitive metrics
        total_businesses = businesses.count()
        
        # Price range distribution
        price_ranges = businesses.values('price_range').annotate(
            count=Count('price_range')
        ).order_by('-count')
        
        # Rating distribution
        rating_ranges = [
            {'range': '4.5-5.0', 'count': businesses.filter(reviews__rating_score__gte=4.5).count()},
            {'range': '4.0-4.4', 'count': businesses.filter(reviews__rating_score__gte=4.0, reviews__rating_score__lt=4.5).count()},
            {'range': '3.5-3.9', 'count': businesses.filter(reviews__rating_score__gte=3.5, reviews__rating_score__lt=4.0).count()},
            {'range': '3.0-3.4', 'count': businesses.filter(reviews__rating_score__gte=3.0, reviews__rating_score__lt=3.5).count()},
            {'range': 'Below 3.0', 'count': businesses.filter(reviews__rating_score__lt=3.0).count()}
        ]
        
        # Market concentration
        top_performers = businesses.annotate(
            avg_rating=Avg('reviews__rating_score')
        ).order_by('-avg_rating')[:5]
        
        return {
            'total_competitors': total_businesses,
            'price_range_distribution': list(price_ranges),
            'rating_distribution': rating_ranges,
            'top_performers': [
                {
                    'business_name': biz.business_name,
                    'rating': round(biz.avg_rating or 0, 2),
                    'province': biz.province
                }
                for biz in top_performers
            ],
            'competition_level': self._calculate_competition_level(total_businesses)
        }
    
    def _get_customer_insights(self, category: Optional[str], location: Optional[str]) -> Dict[str, Any]:
        """Get customer behavior insights"""
        
        # Get search patterns
        search_queries = SearchQuery.objects.all()
        
        if category:
            search_queries = search_queries.filter(query_text__icontains=category)
        
        # Popular search terms
        popular_terms = search_queries.values('query_text').annotate(
            count=Count('query_text')
        ).order_by('-count')[:10]
        
        # Peak search times
        peak_times = search_queries.extra(
            select={'hour': 'EXTRACT(hour FROM created_at)'}
        ).values('hour').annotate(count=Count('hour')).order_by('-count')[:5]
        
        # Customer preferences
        preferences = {
            'most_searched_categories': self._get_most_searched_categories(),
            'preferred_price_ranges': self._get_preferred_price_ranges(),
            'location_preferences': self._get_location_preferences()
        }
        
        return {
            'popular_search_terms': [
                {'term': item['query_text'], 'count': item['count']}
                for item in popular_terms
            ],
            'peak_search_hours': [item['hour'] for item in peak_times],
            'customer_preferences': preferences,
            'search_volume_trend': self._calculate_search_volume_trend()
        }
    
    def _get_growth_opportunities(self, category: Optional[str], location: Optional[str]) -> List[Dict[str, Any]]:
        """Get growth opportunities and recommendations"""
        
        opportunities = []
        
        # Underserved areas
        underserved_areas = self._identify_underserved_areas(category)
        opportunities.extend(underserved_areas)
        
        # Emerging trends
        emerging_trends = self._identify_emerging_trends()
        opportunities.extend(emerging_trends)
        
        # Service gaps
        service_gaps = self._identify_service_gaps(category, location)
        opportunities.extend(service_gaps)
        
        return opportunities[:10]
    
    def _calculate_market_saturation(self, total_businesses: int, location: Optional[str]) -> str:
        """Calculate market saturation level"""
        
        # Simplified saturation calculation
        if location == 'Kigali':
            threshold = 100
        else:
            threshold = 50
        
        if total_businesses > threshold * 1.5:
            return 'high'
        elif total_businesses > threshold:
            return 'medium'
        else:
            return 'low'
    
    def _calculate_competition_level(self, total_businesses: int) -> str:
        """Calculate competition level"""
        
        if total_businesses > 50:
            return 'high'
        elif total_businesses > 20:
            return 'medium'
        else:
            return 'low'
    
    def _get_most_searched_categories(self) -> List[str]:
        """Get most searched business categories"""
        
        # This would typically come from search analytics
        return ['Restaurants', 'Hotels', 'Shopping', 'Services', 'Healthcare']
    
    def _get_preferred_price_ranges(self) -> List[str]:
        """Get preferred price ranges"""
        
        # This would come from user behavior analytics
        return ['medium', 'low', 'high']
    
    def _get_location_preferences(self) -> List[str]:
        """Get location preferences"""
        
        # This would come from search and user analytics
        return ['Kigali', 'Butare', 'Ruhengeri', 'Gisenyi']
    
    def _calculate_search_volume_trend(self) -> str:
        """Calculate search volume trend"""
        
        # Simplified trend calculation
        return 'increasing'
    
    def _identify_underserved_areas(self, category: Optional[str]) -> List[Dict[str, Any]]:
        """Identify underserved areas"""
        
        opportunities = []
        
        # Check different provinces
        provinces = ['Eastern', 'Western', 'Northern', 'Southern']
        
        for province in provinces:
            business_count = Business.objects.filter(
                province=province,
                is_active=True
            ).count()
            
            if business_count < 10:  # Threshold for underserved
                opportunities.append({
                    'type': 'underserved_area',
                    'location': province,
                    'opportunity': f'Low business density in {province}',
                    'potential': 'high'
                })
        
        return opportunities
    
    def _identify_emerging_trends(self) -> List[Dict[str, Any]]:
        """Identify emerging trends"""
        
        trends = [
            {
                'type': 'emerging_trend',
                'trend': 'Digital payments adoption',
                'description': 'Increasing demand for mobile money and digital payment options',
                'impact': 'medium'
            },
            {
                'type': 'emerging_trend',
                'trend': 'Online presence importance',
                'description': 'Businesses with strong online presence perform better',
                'impact': 'high'
            },
            {
                'type': 'emerging_trend',
                'trend': 'Sustainability focus',
                'description': 'Growing interest in eco-friendly and sustainable businesses',
                'impact': 'medium'
            }
        ]
        
        return trends
    
    def _identify_service_gaps(self, category: Optional[str], location: Optional[str]) -> List[Dict[str, Any]]:
        """Identify service gaps in the market"""
        
        gaps = []
        
        # Check for missing amenities
        common_amenities = ['wifi', 'parking', 'delivery', 'takeaway']
        
        for amenity in common_amenities:
            businesses_with_amenity = Business.objects.filter(
                amenities__contains=[amenity],
                is_active=True
            ).count()
            
            total_businesses = Business.objects.filter(is_active=True).count()
            
            if businesses_with_amenity / total_businesses < 0.3:  # Less than 30% have this amenity
                gaps.append({
                    'type': 'service_gap',
                    'service': amenity,
                    'description': f'Only {round(businesses_with_amenity/total_businesses*100, 1)}% of businesses offer {amenity}',
                    'opportunity': 'high'
                })
        
        return gaps
    
    def _generate_market_recommendations(self, market_overview: Dict[str, Any], category_trends: List[Dict[str, Any]]) -> List[str]:
        """Generate market recommendations"""
        
        recommendations = []
        
        # Market saturation recommendations
        if market_overview['market_saturation'] == 'high':
            recommendations.append("Market is highly saturated - focus on differentiation and niche services")
        elif market_overview['market_saturation'] == 'low':
            recommendations.append("Market has growth potential - consider expansion opportunities")
        
        # Growth rate recommendations
        if market_overview['growth_rate_percentage'] > 10:
            recommendations.append("High growth market - invest in scaling operations")
        elif market_overview['growth_rate_percentage'] < 5:
            recommendations.append("Slow growth market - focus on market share and efficiency")
        
        # Category trend recommendations
        top_categories = sorted(category_trends, key=lambda x: x['business_count'], reverse=True)[:3]
        for category in top_categories:
            if category['growth_trend'] == 'up':
                recommendations.append(f"Consider entering {category['category_name']} category - growing market")
        
        return recommendations
    
    def get_market_trends(self, category: Optional[str] = None, location: Optional[str] = None) -> Dict[str, Any]:
        """Get market trends and predictions"""
        
        # Get current trends
        current_trends = self._get_current_trends(category, location)
        
        # Get growth predictions
        growth_predictions = self._get_growth_predictions(category, location)
        
        # Get seasonal patterns
        seasonal_patterns = self._get_seasonal_patterns(category, location)
        
        return {
            'current_trends': current_trends,
            'growth_predictions': growth_predictions,
            'seasonal_patterns': seasonal_patterns,
            'market_forecast': self._generate_market_forecast(current_trends, growth_predictions)
        }
    
    def _get_current_trends(self, category: Optional[str], location: Optional[str]) -> List[Dict[str, Any]]:
        """Get current market trends"""
        
        trends = []
        
        # Search trend analysis
        recent_searches = SearchQuery.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=30)
        )
        
        if category:
            recent_searches = recent_searches.filter(query_text__icontains=category)
        
        # Get trending search terms
        trending_terms = recent_searches.values('query_text').annotate(
            count=Count('query_text')
        ).order_by('-count')[:5]
        
        for term in trending_terms:
            trends.append({
                'trend_type': 'search',
                'description': f'"{term["query_text"]}" is trending',
                'strength': 'high' if term['count'] > 10 else 'medium',
                'timeframe': '30 days'
            })
        
        return trends
    
    def _get_growth_predictions(self, category: Optional[str], location: Optional[str]) -> Dict[str, Any]:
        """Get growth predictions"""
        
        # Simplified growth prediction
        current_businesses = Business.objects.filter(is_active=True).count()
        
        # Predict 10% growth for next quarter
        predicted_growth = current_businesses * 0.1
        
        return {
            'next_quarter_growth': round(predicted_growth, 0),
            'growth_percentage': 10.0,
            'confidence_level': 'medium',
            'factors': [
                'Economic stability',
                'Digital adoption',
                'Tourism growth'
            ]
        }
    
    def _get_seasonal_patterns(self, category: Optional[str], location: Optional[str]) -> Dict[str, Any]:
        """Get seasonal patterns"""
        
        # Simplified seasonal analysis
        return {
            'peak_season': 'December - March',
            'low_season': 'June - August',
            'seasonal_factors': [
                'Tourism peaks during dry season',
                'Holiday shopping increases in December',
                'Rainy season affects outdoor businesses'
            ]
        }
    
    def _generate_market_forecast(self, current_trends: List[Dict[str, Any]], growth_predictions: Dict[str, Any]) -> Dict[str, Any]:
        """Generate market forecast"""
        
        return {
            'short_term_forecast': 'Positive growth expected in next 3 months',
            'medium_term_forecast': 'Steady expansion with increased competition',
            'long_term_forecast': 'Market consolidation with focus on digital transformation',
            'key_drivers': [
                'Technology adoption',
                'Consumer behavior changes',
                'Economic development'
            ],
            'risks': [
                'Economic uncertainty',
                'Increased competition',
                'Regulatory changes'
            ]
        }

