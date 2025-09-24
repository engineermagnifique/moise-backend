# apps/ai_engine/services/conversation_service.py
import json
import time
from typing import Dict, Any, Optional
from django.utils import timezone

from ..models import ConversationSession, ConversationMessage, IntentClassification
from .advanced_conversation_service import AdvancedConversationService

class ConversationService:
    """Service for handling AI conversations - now uses advanced conversation service"""
    
    def __init__(self):
        self.advanced_service = AdvancedConversationService()
    
    def process_message(self, session: ConversationSession, message: str, user_location: Optional[Dict] = None) -> Dict[str, Any]:
        """Process user message and generate AI response using advanced service"""
        return self.advanced_service.process_message(session, message, user_location)
    
    def _analyze_intent(self, message: str, language: str) -> Dict[str, Any]:
        """Analyze user intent from message"""
        
        # Simple intent analysis (in production, use ML models)
        message_lower = message.lower()
        
        intents = {
            'search_business': ['find', 'search', 'look for', 'where is', 'near me'],
            'get_directions': ['directions', 'how to get', 'route', 'navigate'],
            'business_hours': ['hours', 'open', 'closed', 'when does'],
            'make_reservation': ['reserve', 'book', 'table', 'appointment'],
            'get_reviews': ['reviews', 'ratings', 'opinions', 'feedback'],
            'contact_business': ['contact', 'call', 'phone', 'email'],
            'general_inquiry': ['what', 'how', 'why', 'tell me about']
        }
        
        detected_intent = 'general_inquiry'
        confidence = 0.5
        
        for intent, keywords in intents.items():
            for keyword in keywords:
                if keyword in message_lower:
                    detected_intent = intent
                    confidence = 0.8
                    break
        
        # Extract entities (simplified)
        entities = []
        if 'restaurant' in message_lower:
            entities.append({'type': 'business_type', 'value': 'restaurant'})
        if 'hotel' in message_lower:
            entities.append({'type': 'business_type', 'value': 'hotel'})
        if 'shop' in message_lower or 'store' in message_lower:
            entities.append({'type': 'business_type', 'value': 'shop'})
        
        return {
            'intent': detected_intent,
            'confidence': confidence,
            'entities': entities,
            'language': language
        }
    
    def _generate_response(self, message: str, intent_analysis: Dict, session: ConversationSession, user_location: Optional[Dict]) -> Dict[str, Any]:
        """Generate AI response based on intent and context"""
        
        intent = intent_analysis.get('intent', 'general_inquiry')
        
        # Simple response generation (in production, use GPT or similar)
        responses = {
            'search_business': "I'd be happy to help you find businesses! What type of business are you looking for?",
            'get_directions': "I can help you get directions. Which business would you like directions to?",
            'business_hours': "I can check business hours for you. Which business are you interested in?",
            'make_reservation': "I can help you make a reservation. Which restaurant would you like to book?",
            'get_reviews': "I can show you reviews and ratings. Which business would you like to know about?",
            'contact_business': "I can help you contact a business. Which one would you like to reach?",
            'general_inquiry': "I'm here to help you find and learn about businesses in Rwanda. What would you like to know?"
        }
        
        base_response = responses.get(intent, responses['general_inquiry'])
        
        # Add context-specific suggestions
        suggestions = self._generate_suggestions(intent, session, user_location)
        
        return {
            'response': base_response,
            'suggestions': suggestions,
            'conversation_state': {
                'last_intent': intent,
                'language': session.user_language,
                'confidence': intent_analysis.get('confidence', 0.5)
            },
            'next_step': self._get_next_step(intent)
        }
    
    def _generate_suggestions(self, intent: str, session: ConversationSession, user_location: Optional[Dict]) -> list:
        """Generate contextual suggestions"""
        
        suggestions = []
        
        if intent == 'search_business':
            suggestions = [
                "Restaurants near me",
                "Hotels in Kigali",
                "Shopping centers",
                "Medical services"
            ]
        elif intent == 'get_directions':
            suggestions = [
                "Show me the route",
                "How long will it take?",
                "What's the best way to get there?"
            ]
        elif intent == 'business_hours':
            suggestions = [
                "Are they open now?",
                "What time do they close?",
                "Do they open on weekends?"
            ]
        
        return suggestions
    
    def _get_next_step(self, intent: str) -> str:
        """Get suggested next step based on intent"""
        
        next_steps = {
            'search_business': "Please specify the type of business and location",
            'get_directions': "Please provide the business name or address",
            'business_hours': "Please specify which business you're interested in",
            'make_reservation': "Please provide the restaurant name and preferred time",
            'get_reviews': "Please specify which business you'd like to see reviews for",
            'contact_business': "Please provide the business name",
            'general_inquiry': "Please let me know what specific information you need"
        }
        
        return next_steps.get(intent, "How can I help you further?")