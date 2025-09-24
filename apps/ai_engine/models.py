# apps/ai_engine/models.py
import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

class ConversationSession(models.Model):
    """Manages AI conversation sessions"""
    
    CONVERSATION_STATES = [
        ('active', 'Active'),
        ('waiting', 'Waiting for Response'),
        ('completed', 'Completed'),
        ('timeout', 'Timeout'),
    ]
    
    session_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='ai_conversations')
    
    # Conversation Context
    current_intent = models.CharField(max_length=100, blank=True)
    conversation_state = models.CharField(max_length=20, choices=CONVERSATION_STATES, default='active')
    user_language = models.CharField(max_length=10, default='en')
    
    # Location Context
    user_latitude = models.DecimalField(max_digits=10, decimal_places=8, null=True, blank=True)
    user_longitude = models.DecimalField(max_digits=11, decimal_places=8, null=True, blank=True)
    location_context = models.JSONField(default=dict)
    
    # AI Memory & Context
    conversation_memory = models.JSONField(default=dict)  # Stores user preferences, history
    session_context = models.JSONField(default=list)  # Current conversation history
    
    # Analytics
    total_messages = models.PositiveIntegerField(default=0)
    satisfaction_score = models.FloatField(null=True, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    last_activity = models.DateTimeField(auto_now=True)
    ended_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'ai_conversation_sessions'
        indexes = [
            models.Index(fields=['user', 'conversation_state']),
            models.Index(fields=['created_at']),
            models.Index(fields=['last_activity']),
        ]

class ConversationMessage(models.Model):
    """Individual messages in AI conversations"""
    
    MESSAGE_TYPES = [
        ('user', 'User Message'),
        ('ai', 'AI Response'),
        ('system', 'System Message'),
    ]
    
    PROCESSING_STATES = [
        ('received', 'Received'),
        ('processing', 'Processing'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    message_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    conversation = models.ForeignKey(ConversationSession, on_delete=models.CASCADE, related_name='messages')
    
    # Message Content
    message_type = models.CharField(max_length=10, choices=MESSAGE_TYPES)
    content = models.TextField()
    original_language = models.CharField(max_length=10, default='en')
    translated_content = models.JSONField(default=dict)  # Translations to other languages
    
    # AI Processing
    processing_state = models.CharField(max_length=20, choices=PROCESSING_STATES, default='received')
    intent_detected = models.CharField(max_length=100, blank=True)
    entities_extracted = models.JSONField(default=list)
    confidence_score = models.FloatField(default=0.0)
    
    # Response Generation
    response_time_ms = models.PositiveIntegerField(null=True)  # Time taken to generate response
    ai_model_used = models.CharField(max_length=100, blank=True)
    
    # User Feedback
    user_satisfaction = models.IntegerField(null=True, blank=True)  # 1-5 rating
    user_feedback = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    processed_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        db_table = 'ai_conversation_messages'
        ordering = ['created_at']
        indexes = [
            models.Index(fields=['conversation', 'created_at']),
            models.Index(fields=['message_type']),
            models.Index(fields=['intent_detected']),
        ]

class IntentClassification(models.Model):
    """Stores trained intent classifications for improvement"""
    
    intent_name = models.CharField(max_length=100, unique=True)
    description = models.TextField()
    category = models.CharField(max_length=50)
    
    # Training Data
    example_phrases = models.JSONField(default=list)
    keywords = models.JSONField(default=list)
    
    # Business Categories Related
    related_business_categories = models.JSONField(default=list)
    
    # Language Support
    kinyarwanda_phrases = models.JSONField(default=list)
    french_phrases = models.JSONField(default=list)
    
    # Performance Metrics
    accuracy_score = models.FloatField(default=0.0)
    usage_count = models.PositiveIntegerField(default=0)
    
    is_active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        db_table = 'ai_intent_classifications'

class UserPreferenceProfile(models.Model):
    """AI-learned user preferences for personalized recommendations"""
    
    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name='ai_preferences')
    
    # Learned Preferences
    preferred_business_types = models.JSONField(default=list)
    preferred_locations = models.JSONField(default=list)
    preferred_price_ranges = models.JSONField(default=list)
    dietary_restrictions = models.JSONField(default=list)
    transportation_preferences = models.JSONField(default=list)
    
    # Behavioral Patterns
    typical_search_times = models.JSONField(default=list)
    conversation_style = models.CharField(max_length=50, default='friendly')  # formal, casual, friendly
    response_preference = models.CharField(max_length=20, default='detailed')  # brief, detailed, comprehensive
    
    # Language Patterns
    frequently_used_phrases = models.JSONField(default=dict)
    language_mixing_pattern = models.JSONField(default=dict)  # How user mixes languages
    
    # Interaction History
    successful_recommendations = models.JSONField(default=list)
    rejected_suggestions = models.JSONField(default=list)
    
    # Learning Metrics
    preference_confidence = models.FloatField(default=0.0)
    last_updated = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'user_ai_preferences'