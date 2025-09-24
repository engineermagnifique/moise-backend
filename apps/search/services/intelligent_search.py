# apps/search/services/intelligent_search.py
from typing import Dict, Any, List, Optional
from django.db.models import Q, Avg, Count
from apps.businesses.models import Business, BusinessCategory
from apps.search.models import SearchQuery, PopularSearch
from apps.ai_engine.services.intent_analyzer import IntentAnalyzer
from apps.ai_engine.services.language_service import LanguageService

class IntelligentSearchService:
    """Service for intelligent search with AI-powered features"""
    
    def __init__(self):
        self.intent_analyzer = IntentAnalyzer()
        self.language_service = LanguageService()
    
    def search(self, query: str, language: str = 'en', location: Dict[str, float] = None,
               filters: Dict[str, Any] = None, sort_by: str = 'relevance', page: int = 1) -> Dict[str, Any]:
        """Perform intelligent search with AI analysis"""
        
        # Analyze query intent
        intent_analysis = self.intent_analyzer.analyze_query(query)
        
        # Process query based on intent
        processed_query = self._process_query(query, intent_analysis)
        
        # Build search filters
        search_filters = self._build_search_filters(processed_query, filters, location)
        
        # Execute search
        results = self._execute_search(search_filters, sort_by, page)
        
        # Enhance results with AI insights
        enhanced_results = self._enhance_results(results, intent_analysis, language)
        
        # Update search analytics
        self._update_search_analytics(query, language, len(results.get('results', [])))
        
        return {
            'results': enhanced_results,
            'total_found': results['total_count'],
            'search_metadata': {
                'query': query,
                'processed_query': processed_query,
                'language': language,
                'intent_analysis': intent_analysis,
                'search_suggestions': self._generate_search_suggestions(query, language)
            },
            'pagination': {
                'current_page': page,
                'total_pages': results['total_pages'],
                'page_size': 20,
                'has_next': page < results['total_pages'],
                'has_previous': page > 1
            }
        }
    
    def _process_query(self, query: str, intent_analysis: Dict[str, Any]) -> str:
        """Process query based on intent analysis"""
        
        intent = intent_analysis.get('intent', 'general_inquiry')
        entities = intent_analysis.get('entities', [])
        
        # Extract business type from entities
        business_types = [e['value'] for e in entities if e['type'] == 'business_type']
        
        # Extract location from entities
        locations = [e['value'] for e in entities if e['type'] == 'location']
        
        # Build processed query
        processed_parts = [query]
        
        if business_types:
            processed_parts.extend(business_types)
        
        if locations:
            processed_parts.extend(locations)
        
        return ' '.join(processed_parts)
    
    def _build_search_filters(self, query: str, filters: Dict[str, Any], location: Dict[str, float]) -> Dict[str, Any]:
        """Build search filters based on query and user filters"""
        
        search_filters = {
            'query': query,
            'location': location,
            'is_active': True,
            'verification_status': 'verified'
        }
        
        if filters:
            search_filters.update(filters)
        
        return search_filters
    
    def _execute_search(self, filters: Dict[str, Any], sort_by: str, page: int) -> Dict[str, Any]:
        """Execute the actual search query"""
        
        # Build Django Q objects
        q_objects = Q(is_active=True, verification_status='verified')
        
        query = filters.get('query', '')
        if query:
            q_objects &= (
                Q(business_name__icontains=query) |
                Q(description__icontains=query) |
                Q(category__name__icontains=query) |
                Q(address__icontains=query)
            )
        
        # Apply category filter
        if filters.get('category'):
            q_objects &= Q(category__name__icontains=filters['category'])
        
        # Apply price range filter
        if filters.get('price_range'):
            q_objects &= Q(price_range=filters['price_range'])
        
        # Apply rating filter
        if filters.get('min_rating'):
            q_objects &= Q(reviews__rating_score__gte=filters['min_rating'])
        
        # Apply amenities filter
        if filters.get('amenities'):
            for amenity in filters['amenities']:
                q_objects &= Q(amenities__contains=[amenity])
        
        # Execute query
        businesses = Business.objects.filter(q_objects).distinct()
        
        # Apply sorting
        if sort_by == 'rating':
            businesses = businesses.annotate(avg_rating=Avg('reviews__rating_score')).order_by('-avg_rating')
        elif sort_by == 'distance' and filters.get('location'):
            # Distance sorting would require PostGIS in production
            businesses = businesses.order_by('-view_count')
        elif sort_by == 'name':
            businesses = businesses.order_by('business_name')
        elif sort_by == 'created':
            businesses = businesses.order_by('-created_at')
        else:  # relevance
            businesses = businesses.order_by('-view_count', '-created_at')
        
        # Get total count
        total_count = businesses.count()
        
        # Apply pagination
        page_size = 20
        start = (page - 1) * page_size
        end = start + page_size
        paginated_businesses = businesses[start:end]
        
        # Format results
        results = []
        for business in paginated_businesses:
            results.append({
                'business_id': str(business.business_id),
                'business_name': business.business_name,
                'description': business.description,
                'category': business.category.name if business.category else '',
                'address': business.address,
                'province': business.province,
                'district': business.district,
                'phone_number': business.phone_number,
                'email': business.email,
                'website': business.website,
                'price_range': business.price_range,
                'amenities': business.amenities,
                'latitude': float(business.latitude) if business.latitude else None,
                'longitude': float(business.longitude) if business.longitude else None,
                'rating': business.average_rating,
                'total_reviews': business.total_reviews,
                'verification_status': business.verification_status,
                'is_featured': business.is_featured,
                'view_count': business.view_count,
                'created_at': business.created_at.isoformat()
            })
        
        return {
            'results': results,
            'total_count': total_count,
            'total_pages': (total_count + page_size - 1) // page_size
        }
    
    def _enhance_results(self, results: Dict[str, Any], intent_analysis: Dict[str, Any], language: str) -> List[Dict[str, Any]]:
        """Enhance search results with AI insights"""
        
        enhanced_results = results.get('results', [])
        intent = intent_analysis.get('intent', 'general_inquiry')
        
        # Add AI insights to each result
        for result in enhanced_results:
            result['ai_insights'] = {
                'relevance_score': self._calculate_relevance_score(result, intent_analysis),
                'recommendation_reason': self._get_recommendation_reason(result, intent),
                'key_features': self._extract_key_features(result, intent)
            }
        
        # Sort by relevance score if not already sorted
        if intent_analysis.get('intent') != 'general_inquiry':
            enhanced_results.sort(key=lambda x: x['ai_insights']['relevance_score'], reverse=True)
        
        return enhanced_results
    
    def _calculate_relevance_score(self, result: Dict[str, Any], intent_analysis: Dict[str, Any]) -> float:
        """Calculate relevance score for a result"""
        
        score = 0.5  # Base score
        
        intent = intent_analysis.get('intent', 'general_inquiry')
        entities = intent_analysis.get('entities', [])
        
        # Boost score based on intent
        if intent == 'search_business':
            # Check if business type matches
            for entity in entities:
                if entity['type'] == 'business_type':
                    if entity['value'].lower() in result['business_name'].lower():
                        score += 0.3
                    if entity['value'].lower() in result['category'].lower():
                        score += 0.2
        
        # Boost score based on rating
        if result.get('rating', 0) > 4.0:
            score += 0.2
        elif result.get('rating', 0) > 3.0:
            score += 0.1
        
        # Boost score for verified businesses
        if result.get('verification_status') == 'verified':
            score += 0.1
        
        # Boost score for featured businesses
        if result.get('is_featured'):
            score += 0.1
        
        return min(score, 1.0)
    
    def _get_recommendation_reason(self, result: Dict[str, Any], intent: str) -> str:
        """Get reason why this result is recommended"""
        
        reasons = []
        
        if result.get('rating', 0) > 4.0:
            reasons.append("Highly rated")
        
        if result.get('verification_status') == 'verified':
            reasons.append("Verified business")
        
        if result.get('is_featured'):
            reasons.append("Featured listing")
        
        if result.get('total_reviews', 0) > 10:
            reasons.append("Popular choice")
        
        if not reasons:
            reasons.append("Matches your search")
        
        return ", ".join(reasons)
    
    def _extract_key_features(self, result: Dict[str, Any], intent: str) -> List[str]:
        """Extract key features relevant to the search intent"""
        
        features = []
        
        if intent == 'search_business':
            if result.get('amenities'):
                features.extend(result['amenities'][:3])  # Top 3 amenities
        
        elif intent == 'make_reservation':
            if result.get('phone_number'):
                features.append("Takes reservations")
            if 'restaurant' in result.get('category', '').lower():
                features.append("Restaurant")
        
        elif intent == 'get_directions':
            if result.get('latitude') and result.get('longitude'):
                features.append("Location available")
            if result.get('address'):
                features.append("Full address provided")
        
        return features[:5]  # Limit to 5 features
    
    def _generate_search_suggestions(self, query: str, language: str) -> List[str]:
        """Generate search suggestions based on query"""
        
        suggestions = []
        
        # Get popular searches that match the query
        popular_searches = PopularSearch.objects.filter(
            search_term__icontains=query,
            language=language
        ).order_by('-search_count')[:5]
        
        suggestions.extend([search.search_term for search in popular_searches])
        
        # Add category-based suggestions
        if 'restaurant' in query.lower():
            suggestions.extend(['restaurants near me', 'best restaurants in Kigali'])
        elif 'hotel' in query.lower():
            suggestions.extend(['hotels in Kigali', 'accommodation near me'])
        elif 'shop' in query.lower():
            suggestions.extend(['shopping centers', 'stores near me'])
        
        return suggestions[:5]
    
    def _update_search_analytics(self, query: str, language: str, results_count: int):
        """Update search analytics"""
        
        # Update popular searches
        popular_search, created = PopularSearch.objects.get_or_create(
            search_term=query,
            language=language,
            defaults={'search_count': 1}
        )
        
        if not created:
            popular_search.search_count += 1
            popular_search.save()
        
        # Update trend scores
        self._update_trend_scores()
    
    def _update_trend_scores(self):
        """Update trend scores for popular searches"""
        
        from django.utils import timezone
        from datetime import timedelta
        
        # Get searches from the last week
        week_ago = timezone.now() - timedelta(days=7)
        recent_searches = PopularSearch.objects.filter(
            last_searched__gte=week_ago
        )
        
        for search in recent_searches:
            # Simple trend calculation
            search.trend_score = min(search.search_count / 10, 1.0)
            search.save()