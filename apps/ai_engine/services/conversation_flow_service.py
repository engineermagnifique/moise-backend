# apps/ai_engine/services/conversation_flow_service.py
import logging
from typing import Dict, Any, List, Optional
from django.utils import timezone

logger = logging.getLogger(__name__)

class ConversationFlowService:
    """
    Advanced conversation flow service for natural friend-like discussions
    Manages conversation state, context, and natural progression
    """
    
    def __init__(self):
        # Conversation flow patterns for different scenarios
        self.flow_patterns = {
            'food_search': {
                'en': {
                    'opening': [
                        "I'm here to help you find the perfect place to eat!",
                        "Let's find you some great food!",
                        "I love helping people discover amazing restaurants!"
                    ],
                    'exploration': [
                        "What type of food are you in the mood for?",
                        "Are you looking for something specific?",
                        "What's your favorite cuisine?",
                        "Any dietary preferences I should know about?"
                    ],
                    'location_discussion': [
                        "Where are you located? I can find places near you.",
                        "Are you looking for something close by?",
                        "What area are you in? I'll find the best options nearby."
                    ],
                    'price_discussion': [
                        "What's your budget range?",
                        "Are you looking for something budget-friendly or more upscale?",
                        "Price range doesn't matter, or do you have a preference?"
                    ],
                    'satisfaction_check': [
                        "Does this sound good to you?",
                        "Is this what you were looking for?",
                        "Are you happy with these options?",
                        "Would you like me to find more options?"
                    ],
                    'follow_up': [
                        "What else can I help you with?",
                        "Is there anything else you need?",
                        "Any other questions about these places?"
                    ]
                },
                'rw': {
                    'opening': [
                        "Ndi hano kugufasha kubona aho warira!",
                        "Reka dusakire aho warira!",
                        "Nkunda gufasha abantu kubona amaresitora meza!"
                    ],
                    'exploration': [
                        "Ushaka ibiribwa byahe?",
                        "Ushaka ikintu runaka?",
                        "Ushaka ibiribwa byahe?",
                        "Hari ibyo utabaza?"
                    ],
                    'location_discussion': [
                        "Uri he? Nshobora gushakira aho uri hafi.",
                        "Ushaka ikintu hafi?",
                        "Uri mu kihe gace? Nzashakira ibyiza bikwegereye."
                    ],
                    'price_discussion': [
                        "Ufite amafaranga angahe?",
                        "Ushaka ikintu cy'ubusa cyangwa cyiza?",
                        "Amafaranga ntacyo, cyangwa ufite ibyo ushaka?"
                    ],
                    'satisfaction_check': [
                        "Bisubiza?",
                        "Ni ibyo wari ushakaga?",
                        "Urakishimira ayo mahitamo?",
                        "Ushaka nshakire andi mahitamo?"
                    ],
                    'follow_up': [
                        "Nshobora gufasha iki byongera?",
                        "Hari ikindi ukeneye?",
                        "Hari ibindi ubaza ku ayo mahitamo?"
                    ]
                }
            },
            'emergency_help': {
                'en': {
                    'opening': [
                        "I'm here to help you right away!",
                        "Don't worry, I'll help you solve this!",
                        "Let me help you get through this situation!"
                    ],
                    'assessment': [
                        "What kind of help do you need?",
                        "Can you tell me what's happening?",
                        "What's the situation? I'm here to help."
                    ],
                    'location_priority': [
                        "Where are you located? I need to find help nearby.",
                        "What's your location? I'll find the closest assistance.",
                        "Are you safe right now? Where are you?"
                    ],
                    'urgency_assessment': [
                        "How urgent is this?",
                        "Is this an emergency?",
                        "Do you need immediate help?"
                    ],
                    'solution_provided': [
                        "I found help for you!",
                        "Here are your options:",
                        "I've located assistance nearby:"
                    ],
                    'follow_up': [
                        "Are you okay now?",
                        "Did this help you?",
                        "Do you need anything else?"
                    ]
                },
                'rw': {
                    'opening': [
                        "Ndi hano kugufasha ubu!",
                        "Ntihangane, nzaguha ubufasha!",
                        "Reka ngufashe kugira ubwoba!"
                    ],
                    'assessment': [
                        "Ufite ikihe kibazo?",
                        "Woshobora kumbwira iki kibaho?",
                        "Ni iki kibaho? Ndi hano kugufasha."
                    ],
                    'location_priority': [
                        "Uri he? Nkeneye gushakira ubufasha hafi.",
                        "Uri he? Nzashakira ubufasha bugufi.",
                        "Urakagira neza ubu? Uri he?"
                    ],
                    'urgency_assessment': [
                        "Kibazo cyahe?",
                        "Ni ikibazo?",
                        "Ukeneye ubufasha vuba?"
                    ],
                    'solution_provided': [
                        "Nabonye ubufasha bwawe!",
                        "Dore amahitamo yawe:",
                        "Nabonye ubufasha hafi:"
                    ],
                    'follow_up': [
                        "Urakagira neza ubu?",
                        "Bibagufashije?",
                        "Ukeneye ikindi?"
                    ]
                }
            },
            'transport_search': {
                'en': {
                    'opening': [
                        "I'll help you find the best way to get around!",
                        "Let's find you the perfect transport option!",
                        "I love helping people with transportation!"
                    ],
                    'destination_discussion': [
                        "Where do you need to go?",
                        "What's your destination?",
                        "Where are you heading?"
                    ],
                    'transport_preference': [
                        "What type of transport do you prefer?",
                        "Do you have a preference for moto, taxi, or bus?",
                        "What's your preferred way to travel?"
                    ],
                    'budget_discussion': [
                        "What's your budget for this trip?",
                        "Are you looking for something affordable?",
                        "Price range for transportation?"
                    ],
                    'satisfaction_check': [
                        "Does this work for you?",
                        "Is this what you were looking for?",
                        "Are you happy with these options?"
                    ],
                    'follow_up': [
                        "Need anything else for your trip?",
                        "Any other questions about transportation?",
                        "Is there anything else I can help with?"
                    ]
                },
                'rw': {
                    'opening': [
                        "Nzaguha ubufasha kubona uburyo bwo kugenda!",
                        "Reka dusakire ubuhe bwoko bw'ubwoba!",
                        "Nkunda gufasha abantu mu bwoba!"
                    ],
                    'destination_discussion': [
                        "Ushaka kugenda he?",
                        "Ushaka kugera he?",
                        "Ushaka kugenda he?"
                    ],
                    'transport_preference': [
                        "Ushaka ubuhe bwoko bw'ubwoba?",
                        "Ufite ibyifuza ku moto, taxi, cyangwa bus?",
                        "Ushaka ubuhe bwoko bwo kugenda?"
                    ],
                    'budget_discussion': [
                        "Ufite amafaranga angahe yo kugenda?",
                        "Ushaka ikintu cy'ubusa?",
                        "Amafaranga yo kugenda?"
                    ],
                    'satisfaction_check': [
                        "Bibagufasha?",
                        "Ni ibyo wari ushakaga?",
                        "Urakishimira ayo mahitamo?"
                    ],
                    'follow_up': [
                        "Ukeneye ikindi mu rugendo rwawe?",
                        "Hari ibindi ubaza ku bwoba?",
                        "Hari ikindi nshobora gufasha?"
                    ]
                }
            }
        }
        
        # Conversation state management
        self.conversation_states = {
            'greeting': 'opening',
            'exploring': 'exploration',
            'clarifying': 'assessment',
            'solving': 'solution_provided',
            'satisfying': 'satisfaction_check',
            'following_up': 'follow_up'
        }
    
    def get_conversation_flow(self, intent: str, state: str, language: str, 
                            context: Dict = None) -> Dict[str, Any]:
        """
        Get conversation flow for current state and intent
        """
        try:
            # Get flow pattern for intent and language
            flow_pattern = self.flow_patterns.get(intent, {}).get(language, {})
            
            if not flow_pattern:
                return self._get_default_flow(language)
            
            # Get current state messages
            state_messages = flow_pattern.get(state, [])
            
            # Select appropriate message based on context
            selected_message = self._select_message(state_messages, context)
            
            # Generate follow-up questions
            follow_up_questions = self._generate_follow_up_questions(intent, state, language)
            
            # Determine next state
            next_state = self._determine_next_state(intent, state, context)
            
            return {
                'message': selected_message,
                'follow_up_questions': follow_up_questions,
                'current_state': state,
                'next_state': next_state,
                'conversation_flow': self._get_conversation_flow_context(intent, state),
                'language': language
            }
            
        except Exception as e:
            logger.exception(f"Error in conversation flow: {e}")
            return self._get_default_flow(language)
    
    def _select_message(self, messages: List[str], context: Dict = None) -> str:
        """
        Select the most appropriate message based on context
        """
        if not messages:
            return "I'm here to help you!"
        
        # Simple selection logic - in production, use more sophisticated AI
        import random
        return random.choice(messages)
    
    def _generate_follow_up_questions(self, intent: str, state: str, language: str) -> List[str]:
        """
        Generate follow-up questions for natural conversation flow
        """
        follow_up_patterns = {
            'food_search': {
                'en': [
                    "What type of food do you want?",
                    "Where would you like to eat?",
                    "What's your budget?",
                    "Any dietary preferences?"
                ],
                'rw': [
                    "Ushaka ibiribwa byahe?",
                    "Ushaka kurya he?",
                    "Ufite amafaranga angahe?",
                    "Hari ibyo utabaza?"
                ]
            },
            'emergency_help': {
                'en': [
                    "What kind of help do you need?",
                    "Where are you located?",
                    "How urgent is this?",
                    "Are you safe right now?"
                ],
                'rw': [
                    "Ufite ikihe kibazo?",
                    "Uri he?",
                    "Kibazo cyahe?",
                    "Urakagira neza ubu?"
                ]
            },
            'transport_search': {
                'en': [
                    "Where do you need to go?",
                    "What type of transport do you prefer?",
                    "What's your budget?",
                    "When do you need to travel?"
                ],
                'rw': [
                    "Ushaka kugenda he?",
                    "Ushaka ubuhe bwoko bw'ubwoba?",
                    "Ufite amafaranga angahe?",
                    "Ushaka kugenda ryari?"
                ]
            }
        }
        
        return follow_up_patterns.get(intent, {}).get(language, [])
    
    def _determine_next_state(self, intent: str, current_state: str, context: Dict = None) -> str:
        """
        Determine the next conversation state based on current state and context
        """
        state_transitions = {
            'greeting': 'exploring',
            'exploring': 'clarifying',
            'clarifying': 'solving',
            'solving': 'satisfying',
            'satisfying': 'following_up',
            'following_up': 'exploring'
        }
        
        return state_transitions.get(current_state, 'exploring')
    
    def _get_conversation_flow_context(self, intent: str, state: str) -> Dict[str, Any]:
        """
        Get conversation flow context for better understanding
        """
        return {
            'intent': intent,
            'state': state,
            'is_active': True,
            'timestamp': timezone.now().isoformat(),
            'flow_type': 'natural_conversation'
        }
    
    def _get_default_flow(self, language: str) -> Dict[str, Any]:
        """
        Get default conversation flow when specific flow is not available
        """
        if language == 'rw':
            return {
                'message': "Ndi hano kugufasha. Ni iki ushaka?",
                'follow_up_questions': ["Ni iki ushaka?", "Nshobora gufasha iki?"],
                'current_state': 'exploring',
                'next_state': 'clarifying',
                'conversation_flow': {'intent': 'general', 'state': 'exploring'},
                'language': language
            }
        else:
            return {
                'message': "I'm here to help you. What do you need?",
                'follow_up_questions': ["What do you need?", "How can I help you?"],
                'current_state': 'exploring',
                'next_state': 'clarifying',
                'conversation_flow': {'intent': 'general', 'state': 'exploring'},
                'language': language
            }
    
    def manage_conversation_state(self, session_id: str, user_input: str, 
                                ai_response: str, intent: str) -> Dict[str, Any]:
        """
        Manage conversation state and provide context for next interaction
        """
        try:
            from ..models import ConversationSession
            
            # Get session
            session = ConversationSession.objects.get(session_id=session_id)
            
            # Update conversation memory
            conversation_entry = {
                'timestamp': timezone.now().isoformat(),
                'user_input': user_input,
                'ai_response': ai_response,
                'intent': intent,
                'conversation_quality': self._assess_conversation_quality(user_input, ai_response)
            }
            
            # Add to session context
            if not session.session_context:
                session.session_context = []
            
            session.session_context.append(conversation_entry)
            
            # Keep only last 10 entries
            if len(session.session_context) > 10:
                session.session_context = session.session_context[-10:]
            
            # Update conversation memory
            session.conversation_memory.update({
                'last_intent': intent,
                'last_user_input': user_input,
                'conversation_quality': conversation_entry['conversation_quality'],
                'last_activity': timezone.now().isoformat()
            })
            
            session.save()
            
            return {
                'success': True,
                'conversation_state': 'updated',
                'session_id': session_id,
                'conversation_quality': conversation_entry['conversation_quality']
            }
            
        except Exception as e:
            logger.exception(f"Error managing conversation state: {e}")
            return {
                'success': False,
                'error': str(e),
                'conversation_state': 'error'
            }
    
    def _assess_conversation_quality(self, user_input: str, ai_response: str) -> str:
        """
        Assess the quality of the conversation for improvement
        """
        # Simple quality assessment - in production, use more sophisticated analysis
        
        # Check if user input is clear
        user_clarity = len(user_input.split()) > 2
        
        # Check if AI response is helpful
        ai_helpfulness = len(ai_response.split()) > 5
        
        # Check if conversation is progressing
        conversation_progress = user_clarity and ai_helpfulness
        
        if conversation_progress:
            return 'good'
        elif user_clarity:
            return 'needs_improvement'
        else:
            return 'unclear'
    
    def get_conversation_suggestions(self, session_id: str, current_intent: str, 
                                   language: str) -> Dict[str, Any]:
        """
        Get conversation suggestions for better user experience
        """
        try:
            from ..models import ConversationSession
            
            # Get session
            session = ConversationSession.objects.get(session_id=session_id)
            
            # Get conversation history
            recent_context = session.session_context[-3:] if session.session_context else []
            
            # Generate suggestions based on context
            suggestions = self._generate_contextual_suggestions(
                current_intent, language, recent_context
            )
            
            return {
                'success': True,
                'suggestions': suggestions,
                'conversation_context': recent_context,
                'language': language
            }
            
        except Exception as e:
            logger.exception(f"Error getting conversation suggestions: {e}")
            return {
                'success': False,
                'error': str(e),
                'suggestions': []
            }
    
    def _generate_contextual_suggestions(self, intent: str, language: str, 
                                       context: List[Dict]) -> List[str]:
        """
        Generate contextual suggestions based on conversation history
        """
        if language == 'rw':
            suggestions = {
                'food_search': [
                    "Ushaka ibiribwa byahe?",
                    "Ufite amafaranga angahe?",
                    "Ushaka kurya he?",
                    "Hari ibyo utabaza?"
                ],
                'emergency_help': [
                    "Uri he?",
                    "Kibazo cyahe?",
                    "Ukeneye ubufasha vuba?",
                    "Urakagira neza?"
                ],
                'transport_search': [
                    "Ushaka kugenda he?",
                    "Ushaka ubuhe bwoko bw'ubwoba?",
                    "Ufite amafaranga angahe?",
                    "Ushaka kugenda ryari?"
                ]
            }
        else:
            suggestions = {
                'food_search': [
                    "What type of food do you want?",
                    "What's your budget?",
                    "Where would you like to eat?",
                    "Any dietary preferences?"
                ],
                'emergency_help': [
                    "Where are you located?",
                    "What kind of problem do you have?",
                    "Do you need immediate help?",
                    "Are you safe right now?"
                ],
                'transport_search': [
                    "Where do you need to go?",
                    "What type of transport do you prefer?",
                    "What's your budget?",
                    "When do you need to travel?"
                ]
            }
        
        return suggestions.get(intent, [])




