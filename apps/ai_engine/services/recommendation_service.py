# apps/ai_engine/services/recommendation_service.py
import logging
from typing import Dict, Any, List, Optional
from django.db.models import Q
from apps.businesses.models import Business, Review

logger = logging.getLogger(__name__)

class RecommendationService:
    def __init__(self):
        self.search_radius_km = 10
        self.max_recommendations = 10
    
    def get_recommendations(self, intent: str, entities: List[Dict], 
                          user_location: Optional[Dict], language: str = 'en') -> Dict[str, Any]:
        try:
            if intent == 'food_search':
                return self._get_food_recommendations(entities, user_location, language)
            elif intent == 'search_business':
                return self._get_business_recommendations(entities, user_location, language)
            elif intent == 'emergency_help':
                return self._get_emergency_recommendations(entities, user_location, language)
            else:
                return self._get_general_recommendations(entities, user_location, language)
        except Exception as e:
            logger.exception(f"Error in recommendation service: {e}")
            return {'success': False, 'error': str(e), 'recommendations': []}
    
    def _get_food_recommendations(self, entities: List[Dict], user_location: Optional[Dict], language: str) -> Dict[str, Any]:
        query = Q(category__name__icontains='restaurant') | Q(category__name__icontains='food')
        businesses = Business.objects.filter(query).select_related('category')[:self.max_recommendations]
        
        recommendations = []
        for business in businesses:
            recommendations.append(self._format_business_recommendation(business, language))
        
        return {
            'success': True,
            'recommendations': recommendations,
            'total_found': len(recommendations),
            'search_type': 'food',
            'language': language
        }
    
    def _get_business_recommendations(self, entities: List[Dict], user_location: Optional[Dict], language: str) -> Dict[str, Any]:
        business_type = None
        for entity in entities:
            if entity.get('type') == 'business_type':
                business_type = entity.get('value')
                break
        
        query = Q()
        if business_type == 'restaurant':
            query = Q(category__name__icontains='restaurant') | Q(category__name__icontains='food')
        elif business_type == 'hotel':
            query = Q(category__name__icontains='hotel') | Q(category__name__icontains='accommodation')
        elif business_type == 'shop':
            query = Q(category__name__icontains='shop') | Q(category__name__icontains='retail')
        elif business_type == 'garage':
            query = Q(category__name__icontains='garage') | Q(category__name__icontains='automotive')
        
        businesses = Business.objects.filter(query).select_related('category')[:self.max_recommendations]
        
        recommendations = []
        for business in businesses:
            recommendations.append(self._format_business_recommendation(business, language))
        
        return {
            'success': True,
            'recommendations': recommendations,
            'total_found': len(recommendations),
            'search_type': 'business',
            'business_type': business_type,
            'language': language
        }
    
    def _get_emergency_recommendations(self, entities: List[Dict], user_location: Optional[Dict], language: str) -> Dict[str, Any]:
        emergency_services = ['garage', 'hospital', 'clinic', 'police', 'fire', 'ambulance']
        
        query = Q()
        for service in emergency_services:
            query |= Q(category__name__icontains=service) | Q(name__icontains=service)
        
        businesses = Business.objects.filter(query).select_related('category')[:5]
        
        recommendations = []
        for business in businesses:
            recommendations.append(self._format_emergency_recommendation(business, language))
        
        return {
            'success': True,
            'recommendations': recommendations,
            'total_found': len(recommendations),
            'search_type': 'emergency',
            'language': language
        }
    
    def _get_general_recommendations(self, entities: List[Dict], user_location: Optional[Dict], language: str) -> Dict[str, Any]:
        query = Q(is_verified=True)
        businesses = Business.objects.filter(query).select_related('category')[:5]
        
        recommendations = []
        for business in businesses:
            recommendations.append(self._format_business_recommendation(business, language))
        
        return {
            'success': True,
            'recommendations': recommendations,
            'total_found': len(recommendations),
            'search_type': 'general',
            'language': language
        }
    
    def _format_business_recommendation(self, business: Business, language: str) -> Dict[str, Any]:
        recent_reviews = Review.objects.filter(business=business).order_by('-created_at')[:3]
        
        reviews_data = []
        for review in recent_reviews:
            reviews_data.append({
                'rating': review.rating,
                'comment': review.comment,
                'reviewer_name': review.reviewer.get_full_name() if review.reviewer else 'Anonymous',
                'created_at': review.created_at.isoformat()
            })
        
        business_data = {
            'id': str(business.business_id),
            'name': business.name,
            'description': business.description,
            'category': business.category.name if business.category else 'General',
            'address': business.address,
            'phone': business.phone,
            'email': business.email,
            'website': business.website,
            'average_rating': float(business.average_rating) if business.average_rating else 0.0,
            'total_reviews': business.total_reviews,
            'is_verified': business.is_verified,
            'coordinates': {
                'latitude': business.location.y if business.location else None,
                'longitude': business.location.x if business.location else None
            },
            'operating_hours': business.operating_hours,
            'recent_reviews': reviews_data
        }
        
        if language == 'rw':
            business_data['message'] = f"Ni byiza! Nabonye {business.name} hafi yawe."
        else:
            business_data['message'] = f"Great! I found {business.name} near you."
        
        return business_data
    
    def _format_emergency_recommendation(self, business: Business, language: str) -> Dict[str, Any]:
        business_data = self._format_business_recommendation(business, language)
        business_data['is_emergency'] = True
        business_data['urgency_level'] = 'high'
        
        if language == 'rw':
            business_data['message'] = f"UBUFASHA BWAHAFI: {business.name} - Nimero: {business.phone}"
            business_data['emergency_instructions'] = f"Hamagare {business.phone} vuba!"
        else:
            business_data['message'] = f"NEARBY HELP: {business.name} - Phone: {business.phone}"
            business_data['emergency_instructions'] = f"Call {business.phone} immediately!"
        
        return business_data