# apps/ai_engine/services/voice_service.py
import logging
import base64
import io
import wave
import tempfile
import os
from typing import Dict, Any, Optional, Tuple
import requests
import json
from django.conf import settings

logger = logging.getLogger(__name__)

class VoiceService:
    """
    Advanced voice service for speech-to-text and text-to-speech
    Enables natural voice conversations with the AI system
    """
    
    def __init__(self):
        # Voice configuration
        self.supported_languages = {
            'en': 'en-US',
            'rw': 'rw-RW',  # Kinyarwanda
            'fr': 'fr-FR'
        }
        
        # Voice personalities for different languages
        self.voice_personalities = {
            'en': {
                'voice_id': 'en-US-Standard-C',
                'speaking_rate': 1.0,
                'pitch': 0.0,
                'volume_gain_db': 0.0,
                'tone': 'friendly'
            },
            'rw': {
                'voice_id': 'en-US-Standard-C',  # Will use English voice for Kinyarwanda
                'speaking_rate': 0.9,
                'pitch': 0.0,
                'volume_gain_db': 0.0,
                'tone': 'warm'
            }
        }
        
        # Conversation flow patterns
        self.conversation_flows = {
            'greeting': {
                'en': [
                    "Hello! I'm your BusiMap friend. How can I help you today?",
                    "Hi there! What can I do for you?",
                    "Hey! I'm here to help you find what you need."
                ],
                'rw': [
                    "Muraho! Ndi umufasha wawe wa BusiMap. Nshobora gufasha iki?",
                    "Mwaramutse! Ni iki nshobora gukugenzura?",
                    "Muraho! Ndi hano kugufasha kubona ibyo ushaka."
                ]
            },
            'listening': {
                'en': [
                    "I'm listening, tell me what you need.",
                    "Go ahead, I'm here to help.",
                    "What's on your mind?"
                ],
                'rw': [
                    "Ndamumva, mbwira iki ushaka.",
                    "Genda, ndi hano kugufasha.",
                    "Ni iki uri gutekereza?"
                ]
            },
            'thinking': {
                'en': [
                    "Let me think about that for a moment...",
                    "Hmm, let me see what I can find...",
                    "Give me a second to figure this out..."
                ],
                'rw': [
                    "Reka ndibitegereze gato...",
                    "Hmm, reka ndebe nshobora kubona iki...",
                    "Reka ndegerere gato kugira nshobore..."
                ]
            },
            'clarification': {
                'en': [
                    "I want to make sure I understand you correctly. Are you saying...",
                    "Let me clarify this. You need...",
                    "Just to be clear, you're looking for..."
                ],
                'rw': [
                    "Nshaka kumenya neza ko ndabyumva. Uravuga ko...",
                    "Reka ndibisobanure. Ufite ukeneye...",
                    "Gusa kugira ndumve neza, ushaka..."
                ]
            },
            'satisfaction_check': {
                'en': [
                    "Is this what you were looking for?",
                    "Does this help you?",
                    "Are you satisfied with this information?",
                    "Is there anything else you need?"
                ],
                'rw': [
                    "Ni ibyo wari ushakaga?",
                    "Bibagufasha?",
                    "Urakishimira iyo makuru?",
                    "Hari ikindi ukeneye?"
                ]
            }
        }
    
    def process_voice_input(self, audio_data: bytes, language: str = 'en', 
                          user_location: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Process voice input and return AI response
        """
        try:
            # Convert speech to text
            text_result = self.speech_to_text(audio_data, language)
            
            if not text_result['success']:
                return {
                    'success': False,
                    'error': text_result['error'],
                    'voice_response': self._generate_error_voice_response(language)
                }
            
            # Process the text with AI conversation system
            from .advanced_conversation_service import AdvancedConversationService
            from ..models import ConversationSession
            
            # Get or create conversation session
            session = self._get_or_create_session(language)
            
            # Process with AI
            conversation_service = AdvancedConversationService()
            ai_result = conversation_service.process_message(
                session, text_result['text'], user_location
            )
            
            # Generate voice response
            voice_response = self.text_to_speech(
                ai_result['ai_response']['response'], 
                language
            )
            
            # Add conversation flow elements
            conversation_flow = self._generate_conversation_flow(
                ai_result['intent_analysis']['intent'],
                language,
                ai_result['ai_response'].get('suggestions', [])
            )
            
            return {
                'success': True,
                'text_input': text_result['text'],
                'ai_response': ai_result['ai_response'],
                'voice_response': voice_response,
                'conversation_flow': conversation_flow,
                'intent_analysis': ai_result['intent_analysis'],
                'session_id': str(session.session_id),
                'language': language
            }
            
        except Exception as e:
            logger.exception(f"Error in voice processing: {e}")
            return {
                'success': False,
                'error': str(e),
                'voice_response': self._generate_error_voice_response(language)
            }
    
    def speech_to_text(self, audio_data: bytes, language: str = 'en') -> Dict[str, Any]:
        """
        Convert speech to text using advanced speech recognition
        """
        try:
            # For production, integrate with Google Speech-to-Text API
            # For now, we'll use a simplified approach
            
            # Save audio to temporary file
            with tempfile.NamedTemporaryFile(suffix='.wav', delete=False) as temp_file:
                temp_file.write(audio_data)
                temp_file_path = temp_file.name
            
            try:
                # In production, use Google Speech-to-Text API
                # For demo purposes, we'll simulate the response
                simulated_text = self._simulate_speech_recognition(audio_data, language)
                
                return {
                    'success': True,
                    'text': simulated_text,
                    'confidence': 0.95,
                    'language_detected': language
                }
                
            finally:
                # Clean up temporary file
                if os.path.exists(temp_file_path):
                    os.unlink(temp_file_path)
                    
        except Exception as e:
            logger.exception(f"Error in speech-to-text: {e}")
            return {
                'success': False,
                'error': str(e),
                'text': '',
                'confidence': 0.0
            }
    
    def text_to_speech(self, text: str, language: str = 'en') -> Dict[str, Any]:
        """
        Convert text to speech with natural voice
        """
        try:
            # For production, integrate with Google Text-to-Speech API
            # For now, we'll use a simplified approach
            
            # Get voice configuration
            voice_config = self.voice_personalities.get(language, self.voice_personalities['en'])
            
            # In production, use Google Text-to-Speech API
            # For demo purposes, we'll simulate the response
            audio_data = self._simulate_text_to_speech(text, language, voice_config)
            
            return {
                'success': True,
                'audio_data': audio_data,
                'voice_id': voice_config['voice_id'],
                'language': language,
                'duration_seconds': len(audio_data) / 16000,  # Approximate
                'text': text
            }
            
        except Exception as e:
            logger.exception(f"Error in text-to-speech: {e}")
            return {
                'success': False,
                'error': str(e),
                'audio_data': b'',
                'text': text
            }
    
    def _simulate_speech_recognition(self, audio_data: bytes, language: str) -> str:
        """
        Simulate speech recognition for demo purposes
        In production, replace with actual Google Speech-to-Text API
        """
        # This is a simulation - in production, use Google Speech-to-Text API
        # For demo, we'll return sample text based on language
        
        if language == 'rw':
            sample_texts = [
                "Ndashaka kurya ariko sinzi aho narira",
                "imodoka yange irapfuye, mfasha rero",
                "mvuye muntara nza muri kigari, nje kugura moto",
                "muraho, nshobora gufasha?",
                "ndabaza ubufasha"
            ]
        else:
            sample_texts = [
                "I want to eat but I don't know where to go",
                "my car is broken, please help me",
                "I need to buy a motorcycle in Kigali",
                "hello, can you help me?",
                "I need help"
            ]
        
        # Return a random sample text for demo
        import random
        return random.choice(sample_texts)
    
    def _simulate_text_to_speech(self, text: str, language: str, voice_config: Dict) -> bytes:
        """
        Simulate text-to-speech for demo purposes
        In production, replace with actual Google Text-to-Speech API
        """
        # This is a simulation - in production, use Google Text-to-Speech API
        # For demo, we'll return empty audio data
        
        # In production, this would call Google TTS API:
        # response = client.synthesize_speech(
        #     input={'text': text},
        #     voice={'language_code': language, 'name': voice_config['voice_id']},
        #     audio_config={'audio_encoding': 'LINEAR16'}
        # )
        # return response.audio_content
        
        # For demo, return empty audio data
        return b''
    
    def _generate_conversation_flow(self, intent: str, language: str, suggestions: list) -> Dict[str, Any]:
        """
        Generate conversation flow elements for natural discussion
        """
        flow_elements = {
            'greeting': self.conversation_flows['greeting'][language][0],
            'listening': self.conversation_flows['listening'][language][0],
            'thinking': self.conversation_flows['thinking'][language][0],
            'clarification': self.conversation_flows['clarification'][language][0],
            'satisfaction_check': self.conversation_flows['satisfaction_check'][language][0]
        }
        
        # Add contextual follow-up questions
        follow_up_questions = self._generate_follow_up_questions(intent, language, suggestions)
        
        return {
            'flow_elements': flow_elements,
            'follow_up_questions': follow_up_questions,
            'conversation_state': 'active',
            'next_expected_input': 'user_response'
        }
    
    def _generate_follow_up_questions(self, intent: str, language: str, suggestions: list) -> list:
        """
        Generate follow-up questions for natural conversation flow
        """
        if language == 'rw':
            follow_ups = {
                'food_search': [
                    "Ushaka ibiribwa byahe?",
                    "Ufite amafaranga angahe yo kurya?",
                    "Ushaka kurya he?"
                ],
                'emergency_help': [
                    "Uri he?",
                    "Kibazo cyahe?",
                    "Ufite ikihe kibazo?"
                ],
                'transport_search': [
                    "Ushaka kugenda he?",
                    "Ushaka ubuhe bwoko bw'ubwoba?",
                    "Ufite amafaranga angahe?"
                ]
            }
        else:
            follow_ups = {
                'food_search': [
                    "What type of food do you want?",
                    "What's your budget for this meal?",
                    "Where would you like to eat?"
                ],
                'emergency_help': [
                    "Where are you located?",
                    "What kind of problem do you have?",
                    "What do you need help with?"
                ],
                'transport_search': [
                    "Where do you need to go?",
                    "What type of transport do you prefer?",
                    "What's your budget?"
                ]
            }
        
        return follow_ups.get(intent, [])
    
    def _get_or_create_session(self, language: str) -> 'ConversationSession':
        """
        Get or create conversation session for voice interaction
        """
        from ..models import ConversationSession
        from django.contrib.auth import get_user_model
        
        User = get_user_model()
        
        # For demo purposes, create a temporary session
        # In production, this would be tied to the authenticated user
        session, created = ConversationSession.objects.get_or_create(
            user_id=1,  # Demo user ID
            user_language=language,
            defaults={
                'session_context': [],
                'conversation_memory': {},
                'total_messages': 0
            }
        )
        
        return session
    
    def _generate_error_voice_response(self, language: str) -> Dict[str, Any]:
        """
        Generate error response for voice interaction
        """
        if language == 'rw':
            error_text = "Uwo ni ikibazo. Reka ndagerageze nindi nzira. Ntihangane!"
        else:
            error_text = "Something went wrong. Let me try a different approach. Don't worry!"
        
        return {
            'success': False,
            'audio_data': b'',
            'text': error_text,
            'language': language,
            'is_error': True
        }
    
    def start_voice_conversation(self, language: str = 'en') -> Dict[str, Any]:
        """
        Start a new voice conversation session
        """
        try:
            # Create new conversation session
            session = self._get_or_create_session(language)
            
            # Generate greeting
            greeting = self.conversation_flows['greeting'][language][0]
            voice_response = self.text_to_speech(greeting, language)
            
            return {
                'success': True,
                'session_id': str(session.session_id),
                'greeting': greeting,
                'voice_response': voice_response,
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
            from ..models import ConversationSession
            
            # Get session
            session = ConversationSession.objects.get(session_id=session_id)
            
            # Process voice input
            result = self.process_voice_input(
                audio_data, 
                session.user_language, 
                user_location
            )
            
            # Update session
            session.total_messages += 1
            session.save()
            
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
            from ..models import ConversationSession
            
            # Get session
            session = ConversationSession.objects.get(session_id=session_id)
            
            # Generate closing message
            if session.user_language == 'rw':
                closing_message = "Murakoze cyane! Nifite ikindi nshobora gufasha, mbwira gusa."
            else:
                closing_message = "Thank you so much! If you need anything else, just let me know."
            
            voice_response = self.text_to_speech(closing_message, session.user_language)
            
            return {
                'success': True,
                'closing_message': closing_message,
                'voice_response': voice_response,
                'conversation_state': 'ended',
                'total_messages': session.total_messages
            }
            
        except ConversationSession.DoesNotExist:
            return {
                'success': False,
                'error': 'Session not found',
                'conversation_state': 'error'
            }
        except Exception as e:
            logger.exception(f"Error ending voice conversation: {e}")
            return {
                'success': False,
                'error': str(e),
                'conversation_state': 'error'
            }




