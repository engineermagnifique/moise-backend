# apps/ai_engine/services/advanced_conversation_service.py
import json
import time
import logging
from typing import Dict, Any, Optional, List, Tuple
from django.utils import timezone
from django.db import transaction
from django.conf import settings
import requests
import re
from datetime import datetime, timedelta

from ..models import ConversationSession, ConversationMessage, IntentClassification, UserPreferenceProfile
from apps.businesses.models import Business, BusinessCategory
from apps.locations.models import RwandaProvince, RwandaDistrict, RwandaSector, RwandaCell
from apps.search.services.intelligent_search import IntelligentSearchService
from .language_service import LanguageService
from .intent_analyzer import IntentAnalyzer
from .recommendation_service import RecommendationService
from .voice_service import VoiceService
from .conversation_flow_service import ConversationFlowService

logger = logging.getLogger(__name__)

class AdvancedConversationService:
    """
    Advanced AI conversation service that provides friend-like interactions
    in Kinyarwanda and English with dynamic, contextual responses.
    """
    
    def __init__(self):
        self.language_service = LanguageService()
        self.intent_analyzer = IntentAnalyzer()
        self.recommendation_service = RecommendationService()
        self.voice_service = VoiceService()
        self.conversation_flow_service = ConversationFlowService()
        
        # Conversation personality and tone
        self.conversation_personality = {
            'en': {
                'greeting': "Hello! I'm your friendly BusiMap assistant. How can I help you today?",
                'confirmation': "Got it! Let me help you with that.",
                'clarification': "I want to make sure I understand you correctly. Are you saying...",
                'encouragement': "Don't worry, I'm here to help you find exactly what you need!",
                'friendly_close': "Is there anything else I can help you with today?",
                'thinking': "Let me think about that for a moment...",
                'found_something': "Great! I found some options for you:",
                'not_found': "Hmm, I couldn't find exactly what you're looking for. Let me try a different approach...",
                'location_help': "I can see you're in {location}. Let me find the best options nearby.",
                'follow_up': "What would you like to know more about?",
                'confused': "I'm not sure I understood that. Could you help me by saying it differently?",
                'excited': "That sounds great! Let me help you with that right away!",
                'reassuring': "No problem at all! I'm here to make this easy for you."
            },
            'rw': {
                'greeting': "Muraho! Ndi umufasha wawe wa BusiMap. Nshobora gufasha iki?",
                'confirmation': "Yego, ndabyumva. Reka ngufashe.",
                'clarification': "Nshaka kumenya neza ko ndabyumva. Uravuga ko...",
                'encouragement': "Ntihangane, ndi hano kugufasha kubona ibyo ushaka!",
                'friendly_close': "Hari ikindi nshobora gufasha?",
                'thinking': "Reka ndibitegereze gato...",
                'found_something': "Ni byiza! Nabonye amahitamo yawe:",
                'not_found': "Hmm, sinashoboye kubona ibyo ushaka. Reka ndagerageze nindi nzira...",
                'location_help': "Nabonye ko uri muri {location}. Reka nshakire ibyiza bikwegereye.",
                'follow_up': "Ushaka kumenya iki byongera?",
                'confused': "Sinumva neza. Woshobora kuvuga nandi nzira?",
                'excited': "Bisubiza! Reka ngufashe ubu!",
                'reassuring': "Ntakibazo! Ndi hano kugufasha kugira ibyoroshe."
            }
        }
        
        # Conversation context patterns for different scenarios
        self.conversation_patterns = {
            'food_search': {
                'en': {
                    'keywords': ['hungry', 'eat', 'food', 'restaurant', 'meal', 'dining'],
                    'follow_up': "What type of food are you in the mood for?",
                    'location_ask': "Where would you like to eat? I can find places near you.",
                    'price_ask': "What's your budget range for this meal?",
                    'cuisine_ask': "Any specific cuisine you prefer? (Rwandan, International, Fast food, etc.)"
                },
                'rw': {
                    'keywords': ['inzara', 'kurya', 'ibiribwa', 'restoran', 'ifunguro', 'gufungura'],
                    'follow_up': "Ushaka ibiribwa byahe?",
                    'location_ask': "Ushaka kurya he? Nshobora gushakira aho uri hafi.",
                    'price_ask': "Ufite amafaranga angahe yo kurya?",
                    'cuisine_ask': "Ushaka ibiribwa byahe? (by'u Rwanda, by'ahandi, byihuse, etc.)"
                }
            },
            'transport_search': {
                'en': {
                    'keywords': ['transport', 'ride', 'taxi', 'moto', 'bus', 'travel', 'go to'],
                    'follow_up': "Where do you need to go?",
                    'vehicle_ask': "What type of transport do you prefer? (Moto, Car, Bus)",
                    'urgency_ask': "How soon do you need to travel?",
                    'location_ask': "Where are you starting from?"
                },
                'rw': {
                    'keywords': ['genda', 'moto', 'taxi', 'bus', 'guhaguruka', 'kugenda'],
                    'follow_up': "Ushaka kugenda he?",
                    'vehicle_ask': "Ushaka ubuhe bwoko bw'ubwoba? (Moto, Imodoka, Bus)",
                    'urgency_ask': "Ushaka kugenda ryari?",
                    'location_ask': "Uva he?"
                }
            },
            'emergency_help': {
                'en': {
                    'keywords': ['help', 'emergency', 'broken', 'stuck', 'lost', 'problem'],
                    'follow_up': "What kind of help do you need?",
                    'urgency_ask': "How urgent is this?",
                    'location_ask': "Where are you located? I can find help nearby.",
                    'reassurance': "Don't worry, I'll help you find the right assistance."
                },
                'rw': {
                    'keywords': ['fasha', 'ikibazo', 'rapfuye', 'ntashoboye', 'wabuze', 'ikibazo'],
                    'follow_up': "Ufite ikihe kibazo?",
                    'urgency_ask': "Kibazo cyahe?",
                    'location_ask': "Uri he? Nshobora gushakira umufasha hafi yawe.",
                    'reassurance': "Ntihangane, nzaguha ubufasha bukwiriye."
                }
            }
        }
    
    def process_message(self, session: ConversationSession, message: str, user_location: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Process user message and generate advanced AI response with friend-like interaction
        """
        start_time = time.time()
        
        try:
            # Detect language and ensure consistency
            detected_lang = self.language_service.detect_language(message)
            if session.user_language != detected_lang:
                # Update session language if different
                session.user_language = detected_lang
                session.save()
            
            # Create user message record
            user_message = ConversationMessage.objects.create(
                conversation=session,
                message_type='user',
                content=message,
                original_language=detected_lang
            )
            
            # Advanced intent analysis with context
            intent_analysis = self._analyze_advanced_intent(message, session, user_location)
            
            # Generate contextual AI response
            ai_response = self._generate_advanced_response(
                message, intent_analysis, session, user_location, user_message
            )
            
            # Create AI message record
            ai_message = ConversationMessage.objects.create(
                conversation=session,
                message_type='ai',
                content=ai_response['response'],
                intent_detected=intent_analysis.get('intent', ''),
                entities_extracted=json.dumps(intent_analysis.get('entities', [])),
                confidence_score=intent_analysis.get('confidence', 0.0),
                response_time_ms=int((time.time() - start_time) * 1000),
                ai_model_used='advanced_conversation_v1'
            )
            
            # Update session with new context
            self._update_session_context(session, message, ai_response, intent_analysis)
            
            return {
                'conversation_id': str(session.session_id),
                'ai_response': ai_response,
                'intent_analysis': intent_analysis,
                'response_time_ms': int((time.time() - start_time) * 1000),
                'conversation_state': {
                    'language': session.user_language,
                    'context': session.session_context,
                    'memory': session.conversation_memory
                }
            }
            
        except Exception as e:
            logger.exception(f"Error in advanced conversation processing: {e}")
            return self._generate_error_response(session, str(e))
    
    def process_voice_message(self, session: ConversationSession, audio_data: bytes, 
                            user_location: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Process voice message and generate voice response for natural conversation
        """
        start_time = time.time()
        
        try:
            # Process voice input
            voice_result = self.voice_service.process_voice_input(
                audio_data, session.user_language, user_location
            )
            
            if not voice_result['success']:
                return self._generate_voice_error_response(session, voice_result['error'])
            
            # Get conversation flow for natural discussion
            conversation_flow = self.conversation_flow_service.get_conversation_flow(
                voice_result['intent_analysis']['intent'],
                'exploring',
                session.user_language
            )
            
            # Generate enhanced AI response with conversation flow
            enhanced_response = self._generate_enhanced_voice_response(
                voice_result['ai_response'],
                conversation_flow,
                session.user_language
            )
            
            # Update conversation state
            self.conversation_flow_service.manage_conversation_state(
                str(session.session_id),
                voice_result['text_input'],
                enhanced_response['response'],
                voice_result['intent_analysis']['intent']
            )
            
            return {
                'conversation_id': str(session.session_id),
                'text_input': voice_result['text_input'],
                'ai_response': enhanced_response,
                'voice_response': voice_result['voice_response'],
                'conversation_flow': conversation_flow,
                'intent_analysis': voice_result['intent_analysis'],
                'response_time_ms': int((time.time() - start_time) * 1000),
                'conversation_state': {
                    'language': session.user_language,
                    'is_voice_conversation': True,
                    'conversation_quality': 'enhanced'
                }
            }
            
        except Exception as e:
            logger.exception(f"Error in voice message processing: {e}")
            return self._generate_voice_error_response(session, str(e))
    
    def start_voice_conversation(self, language: str = 'en') -> Dict[str, Any]:
        """
        Start a new voice conversation session
        """
        try:
            # Start voice conversation
            voice_result = self.voice_service.start_voice_conversation(language)
            
            if not voice_result['success']:
                return voice_result
            
            # Get conversation flow for greeting
            conversation_flow = self.conversation_flow_service.get_conversation_flow(
                'greeting', 'greeting', language
            )
            
            return {
                'success': True,
                'session_id': voice_result['session_id'],
                'greeting': voice_result['greeting'],
                'voice_response': voice_result['voice_response'],
                'conversation_flow': conversation_flow,
                'language': language,
                'conversation_state': 'started'
            }
            
        except Exception as e:
            logger.exception(f"Error starting voice conversation: {e}")
            return {
                'success': False,
                'error': str(e),
                'conversation_state': 'error'
            }
    
    def continue_voice_conversation(self, session_id: str, audio_data: bytes, 
                                  user_location: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Continue an existing voice conversation
        """
        try:
            # Get session
            session = ConversationSession.objects.get(session_id=session_id)
            
            # Process voice message
            result = self.process_voice_message(session, audio_data, user_location)
            
            return result
            
        except ConversationSession.DoesNotExist:
            return {
                'success': False,
                'error': 'Session not found',
                'conversation_state': 'error'
            }
        except Exception as e:
            logger.exception(f"Error continuing voice conversation: {e}")
            return {
                'success': False,
                'error': str(e),
                'conversation_state': 'error'
            }
    
    def end_voice_conversation(self, session_id: str) -> Dict[str, Any]:
        """
        End a voice conversation session
        """
        try:
            # End voice conversation
            voice_result = self.voice_service.end_voice_conversation(session_id)
            
            return voice_result
            
        except Exception as e:
            logger.exception(f"Error ending voice conversation: {e}")
            return {
                'success': False,
                'error': str(e),
                'conversation_state': 'error'
            }
    
    def _generate_enhanced_voice_response(self, base_response: Dict, 
                                        conversation_flow: Dict, language: str) -> Dict[str, Any]:
        """
        Generate enhanced response for voice conversation with natural flow
        """
        # Get conversation flow message
        flow_message = conversation_flow.get('message', '')
        
        # Combine base response with conversation flow
        enhanced_response = base_response.copy()
        
        # Add conversation flow elements
        enhanced_response['conversation_flow'] = conversation_flow
        enhanced_response['follow_up_questions'] = conversation_flow.get('follow_up_questions', [])
        enhanced_response['conversation_state'] = conversation_flow.get('current_state', 'exploring')
        
        # Add natural conversation elements
        if language == 'rw':
            enhanced_response['natural_elements'] = {
                'acknowledgment': "Nabyumva",
                'encouragement': "Ntihangane, ndi hano kugufasha",
                'clarification': "Nshaka kumenya neza",
                'satisfaction_check': "Bibagufasha?"
            }
        else:
            enhanced_response['natural_elements'] = {
                'acknowledgment': "I understand",
                'encouragement': "Don't worry, I'm here to help",
                'clarification': "Let me make sure I understand",
                'satisfaction_check': "Does this help you?"
            }
        
        return enhanced_response
    
    def _generate_voice_error_response(self, session: ConversationSession, error: str) -> Dict[str, Any]:
        """
        Generate error response for voice conversation
        """
        language = session.user_language
        
        if language == 'rw':
            error_message = "Uwo ni ikibazo. Reka ndagerageze nindi nzira. Ntihangane!"
        else:
            error_message = "Something went wrong. Let me try a different approach. Don't worry!"
        
        return {
            'conversation_id': str(session.session_id),
            'ai_response': {
                'response': error_message,
                'suggestions': [self.conversation_personality[language]['follow_up']],
                'conversation_state': {
                    'last_intent': 'error',
                    'language': language,
                    'error': True
                },
                'next_step': self.conversation_personality[language]['friendly_close']
            },
            'intent_analysis': {
                'intent': 'error',
                'confidence': 0.0,
                'entities': [],
                'language': language
            },
            'response_time_ms': 0,
            'conversation_state': {
                'language': language,
                'is_voice_conversation': True,
                'error': True
            }
        }
    
    def _analyze_advanced_intent(self, message: str, session: ConversationSession, user_location: Optional[Dict]) -> Dict[str, Any]:
        """
        Advanced intent analysis with context awareness and cultural understanding
        """
        # Get conversation history for context
        recent_messages = ConversationMessage.objects.filter(
            conversation=session
        ).order_by('-created_at')[:5]
        
        # Build context from recent conversation
        context = {
            'recent_messages': [msg.content for msg in recent_messages],
            'session_intent': session.current_intent,
            'user_location': user_location,
            'language': session.user_language,
            'conversation_memory': session.conversation_memory
        }
        
        # Detect conversation pattern
        pattern = self._detect_conversation_pattern(message, context)
        
        # Analyze intent with cultural context
        intent_analysis = self._analyze_intent_with_culture(message, pattern, context)
        
        # Extract entities with location awareness
        entities = self._extract_entities_with_context(message, context, user_location)
        
        return {
            'intent': intent_analysis['intent'],
            'confidence': intent_analysis['confidence'],
            'entities': entities,
            'pattern': pattern,
            'cultural_context': intent_analysis.get('cultural_context', {}),
            'language': session.user_language,
            'requires_clarification': intent_analysis.get('requires_clarification', False),
            'suggested_questions': intent_analysis.get('suggested_questions', [])
        }
    
    def _detect_conversation_pattern(self, message: str, context: Dict) -> str:
        """
        Detect the conversation pattern based on message and context
        """
        message_lower = message.lower()
        language = context.get('language', 'en')
        
        # Check for emergency/urgent patterns first
        emergency_keywords = self.conversation_patterns['emergency_help'][language]['keywords']
        if any(keyword in message_lower for keyword in emergency_keywords):
            return 'emergency_help'
        
        # Check for food-related patterns
        food_keywords = self.conversation_patterns['food_search'][language]['keywords']
        if any(keyword in message_lower for keyword in food_keywords):
            return 'food_search'
        
        # Check for transport patterns
        transport_keywords = self.conversation_patterns['transport_search'][language]['keywords']
        if any(keyword in message_lower for keyword in transport_keywords):
            return 'transport_search'
        
        # Check conversation history for pattern continuation
        if context.get('session_intent'):
            return context['session_intent']
        
        return 'general_inquiry'
    
    def _analyze_intent_with_culture(self, message: str, pattern: str, context: Dict) -> Dict[str, Any]:
        """
        Analyze intent with cultural understanding and context
        """
        language = context.get('language', 'en')
        
        # Cultural context analysis
        cultural_context = self._analyze_cultural_context(message, language)
        
        # Intent confidence based on cultural understanding
        confidence = 0.7  # Base confidence
        if cultural_context.get('is_culturally_appropriate'):
            confidence += 0.2
        if cultural_context.get('has_location_context'):
            confidence += 0.1
        
        # Determine if clarification is needed
        requires_clarification = confidence < 0.6 or cultural_context.get('ambiguous')
        
        # Generate suggested questions for clarification
        suggested_questions = []
        if requires_clarification:
            suggested_questions = self._generate_clarification_questions(pattern, language, context)
        
        return {
            'intent': pattern,
            'confidence': min(confidence, 1.0),
            'cultural_context': cultural_context,
            'requires_clarification': requires_clarification,
            'suggested_questions': suggested_questions
        }
    
    def _analyze_cultural_context(self, message: str, language: str) -> Dict[str, Any]:
        """
        Analyze cultural context and appropriateness
        """
        # Kinyarwanda cultural patterns
        rw_cultural_indicators = {
            'respectful_greeting': ['muraho', 'mwaramutse', 'mwirirwe', 'murakoze'],
            'polite_request': ['nshobora', 'woshobora', 'ndabaza', 'ndasaba'],
            'gratitude': ['murakoze', 'urakoze', 'turakoze', 'twese'],
            'location_reference': ['hano', 'hariya', 'hafi', 'kure', 'mu kigali', 'mu rwanda']
        }
        
        # English cultural patterns
        en_cultural_indicators = {
            'polite_request': ['please', 'could you', 'would you', 'can you help'],
            'gratitude': ['thank you', 'thanks', 'appreciate'],
            'location_reference': ['here', 'there', 'near me', 'around', 'in kigali']
        }
        
        cultural_indicators = rw_cultural_indicators if language == 'rw' else en_cultural_indicators
        message_lower = message.lower()
        
        # Check cultural appropriateness
        is_culturally_appropriate = any(
            any(indicator in message_lower for indicator in indicators)
            for indicators in cultural_indicators.values()
        )
        
        # Check for location context
        has_location_context = any(
            indicator in message_lower 
            for indicator in cultural_indicators['location_reference']
        )
        
        # Check for ambiguity
        ambiguous = len(message.split()) < 3 or '?' in message
        
        return {
            'is_culturally_appropriate': is_culturally_appropriate,
            'has_location_context': has_location_context,
            'ambiguous': ambiguous,
            'language': language,
            'cultural_indicators_found': [
                category for category, indicators in cultural_indicators.items()
                if any(indicator in message_lower for indicator in indicators)
            ]
        }
    
    def _extract_entities_with_context(self, message: str, context: Dict, user_location: Optional[Dict]) -> List[Dict[str, Any]]:
        """
        Extract entities with location and cultural context
        """
        entities = []
        language = context.get('language', 'en')
        message_lower = message.lower()
        
        # Business type entities
        business_types = {
            'en': {
                'restaurant': ['restaurant', 'food', 'eat', 'meal', 'dining', 'cafe'],
                'hotel': ['hotel', 'accommodation', 'stay', 'sleep', 'lodge'],
                'shop': ['shop', 'store', 'buy', 'shopping', 'market'],
                'transport': ['taxi', 'moto', 'bus', 'transport', 'ride'],
                'garage': ['garage', 'repair', 'fix', 'mechanic', 'car'],
                'hospital': ['hospital', 'clinic', 'doctor', 'medical', 'health']
            },
            'rw': {
                'restaurant': ['restoran', 'ibiribwa', 'kurya', 'ifunguro', 'gufungura'],
                'hotel': ['hoteli', 'guhagarara', 'kurara', 'ubwoba'],
                'shop': ['ubucuruzi', 'gucururwa', 'gucuruza', 'isoko'],
                'transport': ['taxi', 'moto', 'bus', 'guhaguruka', 'genda'],
                'garage': ['igaraje', 'gukora', 'gukora', 'makanika', 'imodoka'],
                'hospital': ['ibitaro', 'kliniki', 'muganga', 'ubuzima']
            }
        }
        
        # Extract business type entities
        for entity_type, keywords in business_types[language].items():
            if any(keyword in message_lower for keyword in keywords):
                entities.append({
                    'type': 'business_type',
                    'value': entity_type,
                    'confidence': 0.8,
                    'language': language
                })
        
        # Location entities
        if user_location:
            entities.append({
                'type': 'location',
                'value': {
                    'latitude': user_location.get('latitude'),
                    'longitude': user_location.get('longitude'),
                    'address': user_location.get('address', '')
                },
                'confidence': 1.0
            })
        
        # Price range entities
        price_indicators = {
            'en': ['cheap', 'expensive', 'budget', 'affordable', 'price'],
            'rw': ['gihugu', 'cyiza', 'amafaranga', 'gusa', 'agaciro']
        }
        
        if any(indicator in message_lower for indicator in price_indicators[language]):
            entities.append({
                'type': 'price_range',
                'value': 'mentioned',
                'confidence': 0.7
            })
        
        return entities
    
    def _generate_advanced_response(self, message: str, intent_analysis: Dict, session: ConversationSession, 
                                  user_location: Optional[Dict], user_message: ConversationMessage) -> Dict[str, Any]:
        """
        Generate advanced, contextual AI response with friend-like interaction
        """
        language = session.user_language
        intent = intent_analysis.get('intent', 'general_inquiry')
        pattern = intent_analysis.get('pattern', 'general_inquiry')
        requires_clarification = intent_analysis.get('requires_clarification', False)
        
        # Generate base response based on pattern and context
        if requires_clarification:
            response = self._generate_clarification_response(intent_analysis, language)
        elif pattern == 'emergency_help':
            response = self._generate_emergency_response(message, intent_analysis, user_location, language)
        elif pattern == 'food_search':
            response = self._generate_food_search_response(message, intent_analysis, user_location, language)
        elif pattern == 'transport_search':
            response = self._generate_transport_response(message, intent_analysis, user_location, language)
        else:
            response = self._generate_general_response(message, intent_analysis, language)
        
        # Add contextual suggestions
        suggestions = self._generate_contextual_suggestions(pattern, intent_analysis, language)
        
        # Add conversation memory updates
        memory_updates = self._generate_memory_updates(intent_analysis, user_location)
        
        return {
            'response': response,
            'suggestions': suggestions,
            'conversation_state': {
                'last_intent': intent,
                'pattern': pattern,
                'language': language,
                'confidence': intent_analysis.get('confidence', 0.5),
                'requires_follow_up': not requires_clarification
            },
            'next_step': self._get_next_step(pattern, intent_analysis, language),
            'memory_updates': memory_updates,
            'response_type': 'conversational'
        }
    
    def _generate_clarification_response(self, intent_analysis: Dict, language: str) -> str:
        """
        Generate clarification response when intent is unclear
        """
        personality = self.conversation_personality[language]
        suggested_questions = intent_analysis.get('suggested_questions', [])
        
        if suggested_questions:
            question = suggested_questions[0]  # Use first suggested question
            return f"{personality['clarification']} {question}"
        else:
            return personality['confused']
    
    def _generate_emergency_response(self, message: str, intent_analysis: Dict, user_location: Optional[Dict], language: str) -> str:
        """
        Generate emergency help response with immediate assistance
        """
        personality = self.conversation_personality[language]
        
        # Check if it's a car/transport emergency
        if any(word in message.lower() for word in ['car', 'modoka', 'broken', 'rapfuye', 'stuck', 'wabuze']):
            if language == 'rw':
                response = f"{personality['reassuring']} Nabyumva ko imodoka yawe yagize ikibazo. "
                if user_location:
                    response += f"Nabonye ko uri muri {user_location.get('address', 'hano')}. "
                response += "Reka nshakire amagaraje akora amamodoka hafi yawe numero zabo zo kuvugana na bo."
            else:
                response = f"{personality['reassuring']} I understand your car has a problem. "
                if user_location:
                    response += f"I can see you're in {user_location.get('address', 'this area')}. "
                response += "Let me find nearby garages with their contact numbers for you."
        else:
            # General emergency
            if language == 'rw':
                response = f"{personality['reassuring']} Nabyumva ko ufite ikibazo. "
                if user_location:
                    response += f"Nabonye ko uri muri {user_location.get('address', 'hano')}. "
                response += "Reka nshakire ubufasha hafi yawe."
            else:
                response = f"{personality['reassuring']} I understand you need help. "
                if user_location:
                    response += f"I can see you're in {user_location.get('address', 'this area')}. "
                response += "Let me find assistance nearby for you."
        
        return response
    
    def _generate_food_search_response(self, message: str, intent_analysis: Dict, user_location: Optional[Dict], language: str) -> str:
        """
        Generate food search response with cultural understanding
        """
        personality = self.conversation_personality[language]
        
        if language == 'rw':
            response = f"{personality['excited']} Ushaka kurya! "
            if user_location:
                response += f"Nabonye ko uri muri {user_location.get('address', 'hano')}. "
            response += "Reka nshakire amaresitora akuri hafi nawe, ndakubwira ibyiza byose."
        else:
            response = f"{personality['excited']} You want to eat! "
            if user_location:
                response += f"I can see you're in {user_location.get('address', 'this area')}. "
            response += "Let me find the best restaurants near you."
        
        return response
    
    def _generate_transport_response(self, message: str, intent_analysis: Dict, user_location: Optional[Dict], language: str) -> str:
        """
        Generate transport search response
        """
        personality = self.conversation_personality[language]
        
        if language == 'rw':
            response = f"{personality['confirmation']} Ushaka kugenda! "
            if user_location:
                response += f"Nabonye ko uri muri {user_location.get('address', 'hano')}. "
            response += "Reka nshakire ubuhe bwoko bw'ubwoba wagufasha kugenda."
        else:
            response = f"{personality['confirmation']} You need to travel! "
            if user_location:
                response += f"I can see you're in {user_location.get('address', 'this area')}. "
            response += "Let me find the best transport options for you."
        
        return response
    
    def _generate_general_response(self, message: str, intent_analysis: Dict, language: str) -> str:
        """
        Generate general response for unclear intents
        """
        personality = self.conversation_personality[language]
        return personality['greeting']
    
    def _generate_contextual_suggestions(self, pattern: str, intent_analysis: Dict, language: str) -> List[str]:
        """
        Generate contextual suggestions based on conversation pattern
        """
        suggestions = []
        
        if pattern == 'food_search':
            if language == 'rw':
                suggestions = [
                    "Amaresitora akuri hafi",
                    "Ibiribwa by'u Rwanda",
                    "Ibiribwa by'ahandi",
                    "Amaresitora y'ijoro"
                ]
            else:
                suggestions = [
                    "Restaurants near me",
                    "Rwandan food",
                    "International cuisine",
                    "Late night dining"
                ]
        
        elif pattern == 'transport_search':
            if language == 'rw':
                suggestions = [
                    "Moto hafi yawe",
                    "Taxi y'ijoro",
                    "Bus y'ubwoba",
                    "Guhaguruka"
                ]
            else:
                suggestions = [
                    "Moto nearby",
                    "Taxi service",
                    "Bus routes",
                    "Ride options"
                ]
        
        elif pattern == 'emergency_help':
            if language == 'rw':
                suggestions = [
                    "Amagaraje akora amamodoka",
                    "Amabwiriza y'ubuzima",
                    "Ubufasha bw'ijambo",
                    "Amabwiriza y'ubutabazi"
                ]
            else:
                suggestions = [
                    "Car repair services",
                    "Medical assistance",
                    "Emergency contacts",
                    "Police services"
                ]
        
        return suggestions
    
    def _generate_memory_updates(self, intent_analysis: Dict, user_location: Optional[Dict]) -> Dict[str, Any]:
        """
        Generate memory updates for conversation context
        """
        updates = {
            'last_intent': intent_analysis.get('intent'),
            'last_pattern': intent_analysis.get('pattern'),
            'last_confidence': intent_analysis.get('confidence'),
            'timestamp': timezone.now().isoformat()
        }
        
        if user_location:
            updates['last_location'] = user_location
        
        return updates
    
    def _get_next_step(self, pattern: str, intent_analysis: Dict, language: str) -> str:
        """
        Get suggested next step based on conversation pattern
        """
        if language == 'rw':
            next_steps = {
                'food_search': "Reka nshakire amaresitora akuri hafi nawe",
                'transport_search': "Reka nshakire ubuhe bwoko bw'ubwoba",
                'emergency_help': "Reka nshakire ubufasha hafi yawe",
                'general_inquiry': "Nshobora gufasha iki?"
            }
        else:
            next_steps = {
                'food_search': "Let me find restaurants near you",
                'transport_search': "Let me find transport options for you",
                'emergency_help': "Let me find help nearby for you",
                'general_inquiry': "How can I help you?"
            }
        
        return next_steps.get(pattern, next_steps['general_inquiry'])
    
    def _update_session_context(self, session: ConversationSession, message: str, ai_response: Dict, intent_analysis: Dict):
        """
        Update session context with new conversation data
        """
        # Update conversation memory
        memory_updates = ai_response.get('memory_updates', {})
        session.conversation_memory.update(memory_updates)
        
        # Update session context
        context_entry = {
            'timestamp': timezone.now().isoformat(),
            'user_message': message,
            'ai_response': ai_response['response'],
            'intent': intent_analysis.get('intent'),
            'confidence': intent_analysis.get('confidence')
        }
        
        session.session_context.append(context_entry)
        
        # Keep only last 10 context entries
        if len(session.session_context) > 10:
            session.session_context = session.session_context[-10:]
        
        # Update session state
        session.current_intent = intent_analysis.get('intent', '')
        session.total_messages += 1
        session.last_activity = timezone.now()
        session.save()
    
    def _generate_error_response(self, session: ConversationSession, error_message: str) -> Dict[str, Any]:
        """
        Generate error response when something goes wrong
        """
        language = session.user_language
        personality = self.conversation_personality[language]
        
        if language == 'rw':
            response = f"Uwo ni ikibazo. Reka ndagerageze nindi nzira. Ntihangane!"
        else:
            response = f"Something went wrong. Let me try a different approach. Don't worry!"
        
        return {
            'conversation_id': str(session.session_id),
            'ai_response': {
                'response': response,
                'suggestions': [personality['follow_up']],
                'conversation_state': {
                    'last_intent': 'error',
                    'language': language,
                    'error': True
                },
                'next_step': personality['friendly_close']
            },
            'intent_analysis': {
                'intent': 'error',
                'confidence': 0.0,
                'entities': [],
                'language': language
            },
            'response_time_ms': 0
        }
    
    def _generate_clarification_questions(self, pattern: str, language: str, context: Dict) -> List[str]:
        """
        Generate clarification questions based on pattern and context
        """
        if pattern == 'food_search':
            if language == 'rw':
                return [
                    "Ushaka ibiribwa byahe?",
                    "Ushaka kurya he?",
                    "Ufite amafaranga angahe?"
                ]
            else:
                return [
                    "What type of food do you want?",
                    "Where would you like to eat?",
                    "What's your budget?"
                ]
        
        elif pattern == 'transport_search':
            if language == 'rw':
                return [
                    "Ushaka kugenda he?",
                    "Ushaka ubuhe bwoko bw'ubwoba?",
                    "Ushaka kugenda ryari?"
                ]
            else:
                return [
                    "Where do you need to go?",
                    "What type of transport do you prefer?",
                    "When do you need to travel?"
                ]
        
        elif pattern == 'emergency_help':
            if language == 'rw':
                return [
                    "Ufite ikihe kibazo?",
                    "Uri he?",
                    "Kibazo cyahe?"
                ]
            else:
                return [
                    "What kind of help do you need?",
                    "Where are you located?",
                    "How urgent is this?"
                ]
        
        # Default clarification questions
        if language == 'rw':
            return ["Woshobora kuvuga nandi nzira?", "Ushaka iki?"]
        else:
            return ["Could you say that differently?", "What do you need?"]
