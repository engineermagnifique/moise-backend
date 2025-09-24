# apps/ai_engine/views.py
from rest_framework import generics, status, permissions, serializers
from rest_framework.decorators import api_view, permission_classes
from rest_framework.response import Response
from drf_spectacular.utils import extend_schema, extend_schema_view
from django.utils import timezone
import json
import uuid
import logging

from .models import ConversationSession, ConversationMessage, IntentClassification, UserPreferenceProfile
from .serializers import (
    ConversationSessionSerializer, ConversationMessageSerializer,
    AIResponseSerializer, LanguageDetectionSerializer, TranslationSerializer,
    QueryAnalysisSerializer, SearchSuggestionSerializer
)
from .services.conversation_service import ConversationService
from .services.advanced_conversation_service import AdvancedConversationService
from .services.language_service import LanguageService
from .services.intent_analyzer import IntentAnalyzer
from .services.recommendation_service import RecommendationService
from .services.voice_service import VoiceService
from .services.conversation_flow_service import ConversationFlowService

logger = logging.getLogger(__name__)

# Add serializer classes
class BusinessInsightsSerializer(serializers.Serializer):
    """Serializer for business insights"""
    market_opportunities = serializers.ListField(child=serializers.CharField())
    business_trends = serializers.ListField(child=serializers.DictField())
    recommendations = serializers.ListField(child=serializers.CharField())

class MarketTrendsSerializer(serializers.Serializer):
    """Serializer for market trends"""
    overall_market_health = serializers.CharField()
    growth_rate = serializers.FloatField()
    trending_categories = serializers.ListField(child=serializers.DictField())
    regional_insights = serializers.ListField(child=serializers.DictField())
    predictions = serializers.ListField(child=serializers.CharField())

class ConversationContextSerializer(serializers.Serializer):
    """Serializer for conversation context"""
    conversation_id = serializers.UUIDField()
    context = serializers.ListField()
    memory = serializers.DictField()

class VoiceResponseSerializer(serializers.Serializer):
    """Serializer for voice responses"""
    success = serializers.BooleanField()
    session_id = serializers.CharField(required=False)
    audio_data = serializers.CharField(required=False)
    text = serializers.CharField(required=False)
    error = serializers.CharField(required=False)

class SpeechToTextSerializer(serializers.Serializer):
    """Serializer for speech-to-text"""
    transcript = serializers.CharField()
    confidence = serializers.FloatField()

class TextToSpeechSerializer(serializers.Serializer):
    """Serializer for text-to-speech"""
    audio_url = serializers.CharField()
    duration = serializers.IntegerField()

@extend_schema_view(
    post=extend_schema(
        summary="AI Chat Conversation",
        description="Start or continue an AI conversation",
        tags=["AI & Intelligence"]
    )
)
class AIConversationView(generics.GenericAPIView):
    """AI conversation endpoint"""
    
    serializer_class = AIResponseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Process user message and return AI response"""
        try:
            message = request.data.get('message', '')
            conversation_id = request.data.get('conversation_id')
            language = request.data.get('language', 'en')
            user_location = request.data.get('user_location')
            
            # Get or create conversation session
            if conversation_id:
                try:
                    session = ConversationSession.objects.get(
                        session_id=conversation_id,
                        user=request.user
                    )
                except ConversationSession.DoesNotExist:
                    session = None
            else:
                session = None
            
            if not session:
                session = ConversationSession.objects.create(
                    user=request.user,
                    user_language=language,
                    user_latitude=user_location.get('latitude') if user_location else None,
                    user_longitude=user_location.get('longitude') if user_location else None
                )
            
            # Process the conversation
            conversation_service = ConversationService()
            response_data = conversation_service.process_message(
                session=session,
                message=message,
                user_location=user_location
            )
            
            return Response({
                'success': True,
                'data': response_data,
                'conversation_id': str(session.session_id)
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'conversation_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="AI Recommendations",
        description="Get AI-powered business recommendations",
        tags=["AI & Intelligence"]
    )
)
class AIRecommendationsView(generics.GenericAPIView):
    """AI recommendations endpoint"""
    
    serializer_class = AIResponseSerializer
    permission_classes = [permissions.IsAuthenticated]

    def post(self, request, *args, **kwargs):
        """Get personalized recommendations"""
        try:
            user_preferences = request.data.get('user_preferences', {})
            location = request.data.get('location')
            context = request.data.get('context', '')
            
            recommendation_service = RecommendationService()
            recommendations = recommendation_service.get_recommendations(
                user=request.user,
                preferences=user_preferences,
                location=location,
                context=context
            )
            
            return Response({
                'success': True,
                'data': {
                    'recommendations': recommendations,
                    'reasoning': 'Based on your preferences and location'
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'recommendation_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Language Detection",
        description="Detect the language of input text",
        tags=["AI & Intelligence"]
    )
)
class LanguageDetectionView(generics.GenericAPIView):
    """Language detection endpoint"""
    
    serializer_class = LanguageDetectionSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Detect language of input text"""
        try:
            text = request.data.get('text', '')
            
            language_service = LanguageService()
            detected_language = language_service.detect_language(text)
            
            return Response({
                'success': True,
                'data': {
                    'text': text,
                    'detected_language': detected_language,
                    'confidence': 0.95  # Placeholder confidence score
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'language_detection_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Text Translation",
        description="Translate text between supported languages",
        tags=["AI & Intelligence"]
    )
)
class TranslationView(generics.GenericAPIView):
    """Translation endpoint"""
    
    serializer_class = TranslationSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Translate text"""
        try:
            text = request.data.get('text', '')
            target_language = request.data.get('target_language', 'en')
            source_language = request.data.get('source_language')
            
            language_service = LanguageService()
            translated_text = language_service.translate_text(
                text=text,
                target_language=target_language,
                source_language=source_language
            )
            
            return Response({
                'success': True,
                'data': {
                    'original_text': text,
                    'translated_text': translated_text,
                    'source_language': source_language or 'auto',
                    'target_language': target_language
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'translation_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Query Analysis",
        description="Analyze user query for intent and entities",
        tags=["AI & Intelligence"]
    )
)
class QueryAnalysisView(generics.GenericAPIView):
    """Query analysis endpoint"""
    
    serializer_class = QueryAnalysisSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Analyze user query"""
        try:
            query = request.data.get('query', '')
            user_context = request.data.get('user_context', {})
            
            intent_analyzer = IntentAnalyzer()
            analysis = intent_analyzer.analyze_query(query, user_context)
            
            return Response({
                'success': True,
                'data': analysis
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'query_analysis_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

@extend_schema_view(
    post=extend_schema(
        summary="Search Suggestions",
        description="Get AI-powered search suggestions",
        tags=["AI & Intelligence"]
    )
)
class SearchSuggestionsView(generics.GenericAPIView):
    """Search suggestions endpoint"""
    
    serializer_class = SearchSuggestionSerializer
    permission_classes = [permissions.AllowAny]

    def post(self, request, *args, **kwargs):
        """Get search suggestions"""
        try:
            partial_query = request.data.get('partial_query', '')
            language = request.data.get('language', 'en')
            category = request.data.get('category')
            
            # Simple suggestions based on partial query
            suggestions = [
                f"{partial_query} restaurant",
                f"{partial_query} hotel",
                f"{partial_query} shop",
                f"{partial_query} service"
            ]
            
            return Response({
                'success': True,
                'data': {
                    'suggestions': suggestions[:5],
                    'query': partial_query,
                    'language': language
                }
            })
            
        except Exception as e:
            return Response({
                'success': False,
                'error': {
                    'message': str(e),
                    'code': 'suggestion_error'
                }
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

# Additional AI endpoints for voice and advanced features
@extend_schema_view(
    post=extend_schema(
        summary="Speech to Text",
        description="Convert speech audio to text",
        tags=["AI & Intelligence"]
    )
)
class SpeechToTextView(generics.GenericAPIView):
    """Speech to text endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = SpeechToTextSerializer

    def post(self, request, *args, **kwargs):
        """Convert speech to text"""
        # Placeholder implementation
        return Response({
            'success': True,
            'data': {
                'transcript': 'Speech to text functionality will be implemented',
                'confidence': 0.0
            }
        })

@extend_schema_view(
    post=extend_schema(
        summary="Text to Speech",
        description="Convert text to speech audio",
        tags=["AI & Intelligence"]
    )
)
class TextToSpeechView(generics.GenericAPIView):
    """Text to speech endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = TextToSpeechSerializer

    def post(self, request, *args, **kwargs):
        """Convert text to speech"""
        # Placeholder implementation
        return Response({
            'success': True,
            'data': {
                'audio_url': 'Text to speech functionality will be implemented',
                'duration': 0
            }
        })

@extend_schema_view(
    get=extend_schema(
        summary="Conversation Context",
        description="Get conversation context",
        tags=["AI & Intelligence"]
    )
)
class ConversationContextView(generics.RetrieveAPIView):
    """Conversation context endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = ConversationContextSerializer

    def get(self, request, *args, **kwargs):
        """Get conversation context"""
        conversation_id = request.query_params.get('conversation_id')
        
        if conversation_id:
            try:
                session = ConversationSession.objects.get(
                    session_id=conversation_id,
                    user=request.user
                )
                return Response({
                    'success': True,
                    'data': {
                        'conversation_id': str(session.session_id),
                        'context': session.session_context,
                        'memory': session.conversation_memory
                    }
                })
            except ConversationSession.DoesNotExist:
                return Response({
                    'success': False,
                    'error': {
                        'message': 'Conversation not found',
                        'code': 'conversation_not_found'
                    }
                }, status=status.HTTP_404_NOT_FOUND)
        
        return Response({
            'success': False,
            'error': {
                'message': 'Conversation ID required',
                'code': 'missing_conversation_id'
            }
        }, status=status.HTTP_400_BAD_REQUEST)


@extend_schema_view(
    get=extend_schema(
        summary="Business Insights",
        description="Get AI-powered business insights and analytics.",
        tags=["AI & Intelligence"]
    )
)
class BusinessInsightsView(generics.GenericAPIView):
    """AI-powered business insights endpoint"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = BusinessInsightsSerializer

    def get(self, request, *args, **kwargs):
        try:
            # TODO: Implement AI business insights
            insights = {
                "market_opportunities": [
                    "Food delivery services are growing in Kigali",
                    "Tech startups are emerging in Nyarugenge",
                    "Tourism services needed in rural areas"
                ],
                "business_trends": [
                    {
                        "category": "Technology",
                        "growth_rate": 15.2,
                        "trend": "increasing"
                    },
                    {
                        "category": "Food & Beverage",
                        "growth_rate": 8.7,
                        "trend": "stable"
                    }
                ],
                "recommendations": [
                    "Consider expanding digital presence",
                    "Focus on mobile-first customer experience",
                    "Leverage social media marketing"
                ]
            }
            
            return Response(insights, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception("Unexpected error in BusinessInsightsView")
            return Response({"detail": "An unexpected error occurred."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    get=extend_schema(
        summary="Market Trends",
        description="Get AI-powered market trends and analysis.",
        tags=["AI & Intelligence"]
    )
)
class MarketTrendsView(generics.GenericAPIView):
    """AI-powered market trends endpoint"""
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = MarketTrendsSerializer

    def get(self, request, *args, **kwargs):
        try:
            # TODO: Implement AI market trends analysis
            trends = {
                "overall_market_health": "growing",
                "growth_rate": 12.5,
                "trending_categories": [
                    {
                        "name": "Digital Services",
                        "growth": 25.3,
                        "businesses": 145
                    },
                    {
                        "name": "E-commerce",
                        "growth": 18.7,
                        "businesses": 89
                    },
                    {
                        "name": "Healthcare",
                        "growth": 14.2,
                        "businesses": 67
                    }
                ],
                "regional_insights": [
                    {
                        "region": "Kigali",
                        "growth_rate": 15.8,
                        "key_sectors": ["Technology", "Finance", "Tourism"]
                    },
                    {
                        "region": "Northern Province",
                        "growth_rate": 8.3,
                        "key_sectors": ["Agriculture", "Tourism", "Mining"]
                    }
                ],
                "predictions": [
                    "Digital payment adoption will increase by 30%",
                    "Remote work services will see significant growth",
                    "Sustainable business practices will become priority"
                ]
            }
            
            return Response(trends, status=status.HTTP_200_OK)
        except Exception as e:
            logger.exception("Unexpected error in MarketTrendsView")
            return Response({"detail": "An unexpected error occurred."},
                            status=status.HTTP_500_INTERNAL_SERVER_ERROR)


# Voice Conversation Endpoints

@extend_schema_view(
    post=extend_schema(
        summary="Start Voice Conversation",
        description="Start a new voice conversation session",
        tags=["AI & Intelligence", "Voice"]
    )
)
class StartVoiceConversationView(generics.GenericAPIView):
    """Start voice conversation endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VoiceResponseSerializer

    def post(self, request, *args, **kwargs):
        """Start a new voice conversation"""
        try:
            language = request.data.get('language', 'en')
            
            # Start voice conversation
            conversation_service = AdvancedConversationService()
            result = conversation_service.start_voice_conversation(language)
            
            if result['success']:
                return Response(result, status=status.HTTP_200_OK)
            else:
                return Response(result, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.exception("Error in StartVoiceConversationView")
            return Response({"detail": "An unexpected error occurred."},
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    post=extend_schema(
        summary="Continue Voice Conversation",
        description="Continue an existing voice conversation with audio input",
        tags=["AI & Intelligence", "Voice"]
    )
)
class ContinueVoiceConversationView(generics.GenericAPIView):
    """Continue voice conversation endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VoiceResponseSerializer

    def post(self, request, *args, **kwargs):
        """Continue voice conversation with audio input"""
        try:
            session_id = request.data.get('session_id')
            audio_data = request.data.get('audio_data')  # Base64 encoded audio
            user_location = request.data.get('user_location')
            
            if not session_id or not audio_data:
                return Response({
                    'success': False,
                    'error': 'Session ID and audio data are required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Decode audio data
            try:
                import base64
                audio_bytes = base64.b64decode(audio_data)
            except Exception as e:
                return Response({
                    'success': False,
                    'error': 'Invalid audio data format'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Continue voice conversation
            conversation_service = AdvancedConversationService()
            result = conversation_service.continue_voice_conversation(
                session_id, audio_bytes, user_location
            )
            
            if result.get('success', True):  # Default to success if not specified
                return Response(result, status=status.HTTP_200_OK)
            else:
                return Response(result, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.exception("Error in ContinueVoiceConversationView")
            return Response({"detail": "An unexpected error occurred."},
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    post=extend_schema(
        summary="End Voice Conversation",
        description="End a voice conversation session",
        tags=["AI & Intelligence", "Voice"]
    )
)
class EndVoiceConversationView(generics.GenericAPIView):
    """End voice conversation endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VoiceResponseSerializer

    def post(self, request, *args, **kwargs):
        """End voice conversation session"""
        try:
            session_id = request.data.get('session_id')
            
            if not session_id:
                return Response({
                    'success': False,
                    'error': 'Session ID is required'
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # End voice conversation
            conversation_service = AdvancedConversationService()
            result = conversation_service.end_voice_conversation(session_id)
            
            if result['success']:
                return Response(result, status=status.HTTP_200_OK)
            else:
                return Response(result, status=status.HTTP_400_BAD_REQUEST)
                
        except Exception as e:
            logger.exception("Error in EndVoiceConversationView")
            return Response({"detail": "An unexpected error occurred."},
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)


@extend_schema_view(
    post=extend_schema(
        summary="Voice Message Processing",
        description="Process voice message and get AI response",
        tags=["AI & Intelligence", "Voice"]
    )
)
class VoiceMessageView(generics.GenericAPIView):
    """Voice message processing endpoint"""
    
    permission_classes = [permissions.IsAuthenticated]
    serializer_class = VoiceResponseSerializer

    def post(self, request, *args, **kwargs):
        """Process voice message and return AI response"""
        try:
            message = request.data.get('message', '')
            conversation_id = request.data.get('conversation_id')
            language = request.data.get('language', 'en')
            user_location = request.data.get('user_location')
            is_voice = request.data.get('is_voice', False)
            
            # Get or create conversation session
            if conversation_id:
                try:
                    session = ConversationSession.objects.get(
                        session_id=conversation_id,
                        user=request.user
                    )
                except ConversationSession.DoesNotExist:
                    return Response({
                        'success': False,
                        'error': 'Conversation session not found'
                    }, status=status.HTTP_404_NOT_FOUND)
            else:
                session = ConversationSession.objects.create(
                    user=request.user,
                    user_language=language,
                    session_context=[],
                    conversation_memory={}
                )
            
            # Process message with advanced conversation service
            conversation_service = AdvancedConversationService()
            
            if is_voice:
                # Simulate voice processing for demo
                result = conversation_service.process_message(
                    session, message, user_location
                )
                result['is_voice_conversation'] = True
            else:
                result = conversation_service.process_message(
                    session, message, user_location
                )
            
            return Response(result, status=status.HTTP_200_OK)
                
        except Exception as e:
            logger.exception("Error in VoiceMessageView")
            return Response({"detail": "An unexpected error occurred."},
                          status=status.HTTP_500_INTERNAL_SERVER_ERROR)