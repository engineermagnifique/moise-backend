# apps/ai_engine/serializers.py
from rest_framework import serializers
from .models import ConversationSession, ConversationMessage, IntentClassification, UserPreferenceProfile

class ConversationSessionSerializer(serializers.ModelSerializer):
    """Conversation session serializer"""
    
    class Meta:
        model = ConversationSession
        fields = [
            'session_id', 'current_intent', 'conversation_state',
            'user_language', 'user_latitude', 'user_longitude',
            'location_context', 'conversation_memory', 'session_context',
            'total_messages', 'satisfaction_score', 'created_at', 'last_activity'
        ]
        read_only_fields = ['session_id', 'created_at', 'last_activity']

class ConversationMessageSerializer(serializers.ModelSerializer):
    """Conversation message serializer"""
    
    class Meta:
        model = ConversationMessage
        fields = [
            'message_id', 'conversation', 'message_type', 'content',
            'original_language', 'translated_content', 'processing_state',
            'intent_detected', 'entities_extracted', 'confidence_score',
            'response_time_ms', 'ai_model_used', 'user_satisfaction',
            'user_feedback', 'created_at', 'processed_at'
        ]
        read_only_fields = ['message_id', 'created_at', 'processed_at']

class AIResponseSerializer(serializers.Serializer):
    """AI response serializer"""
    
    message = serializers.CharField()
    conversation_id = serializers.CharField(required=False)
    language = serializers.CharField(default='en')
    user_location = serializers.DictField(required=False)
    conversation_context = serializers.DictField(required=False)

class LanguageDetectionSerializer(serializers.Serializer):
    """Language detection serializer"""
    
    text = serializers.CharField()

class TranslationSerializer(serializers.Serializer):
    """Translation serializer"""
    
    text = serializers.CharField()
    target_language = serializers.CharField()
    source_language = serializers.CharField(required=False)

class QueryAnalysisSerializer(serializers.Serializer):
    """Query analysis serializer"""
    
    query = serializers.CharField()
    user_context = serializers.DictField(required=False)

class SearchSuggestionSerializer(serializers.Serializer):
    """Search suggestion serializer"""
    
    partial_query = serializers.CharField()
    language = serializers.CharField(default='en')
    category = serializers.CharField(required=False)

class IntentClassificationSerializer(serializers.ModelSerializer):
    """Intent classification serializer"""
    
    class Meta:
        model = IntentClassification
        fields = [
            'intent_name', 'description', 'category', 'example_phrases',
            'keywords', 'related_business_categories', 'kinyarwanda_phrases',
            'french_phrases', 'accuracy_score', 'usage_count', 'is_active'
        ]

class UserPreferenceProfileSerializer(serializers.ModelSerializer):
    """User preference profile serializer"""
    
    class Meta:
        model = UserPreferenceProfile
        fields = [
            'preferred_business_types', 'preferred_locations',
            'preferred_price_ranges', 'dietary_restrictions',
            'transportation_preferences', 'typical_search_times',
            'conversation_style', 'response_preference',
            'frequently_used_phrases', 'language_mixing_pattern',
            'successful_recommendations', 'rejected_suggestions',
            'preference_confidence'
        ]
        read_only_fields = ['preference_confidence']

