
# apps/ai_engine/urls.py
from django.urls import path
from . import views

app_name = 'ai_engine'

urlpatterns = [
    # AI Chat
    path('chat/', views.AIConversationView.as_view(), name='ai-chat'),
    path('recommendations/', views.AIRecommendationsView.as_view(), name='ai-recommendations'),
    
    # Language Services
    path('detect-language/', views.LanguageDetectionView.as_view(), name='detect-language'),
    path('translate/', views.TranslationView.as_view(), name='translate'),
    path('analyze-query/', views.QueryAnalysisView.as_view(), name='analyze-query'),
    
    # Voice Services
    path('voice/speech-to-text/', views.SpeechToTextView.as_view(), name='speech-to-text'),
    path('voice/text-to-speech/', views.TextToSpeechView.as_view(), name='text-to-speech'),
    
    # Context Management
    path('conversation/context/', views.ConversationContextView.as_view(), name='conversation-context'),
    
    # Note: Some views are commented out for development
    # path('conversation/memory/', views.ConversationMemoryView.as_view(), name='conversation-memory'),
    # path('emotion/detect/', views.EmotionDetectionView.as_view(), name='emotion-detect'),
    # path('intent/analyze-advanced/', views.AdvancedIntentAnalysisView.as_view(), name='advanced-intent'),
    # path('recommendations/smart/', views.SmartRecommendationsView.as_view(), name='smart-recommendations'),
    
    # Search Suggestions
    path('search-suggestions/', views.SearchSuggestionsView.as_view(), name='search-suggestions'),
    
    # Business Insights (Frontend expects these)
    path('business-insights/', views.BusinessInsightsView.as_view(), name='business-insights'),
    path('market-trends/', views.MarketTrendsView.as_view(), name='market-trends'),
    
    # Voice Conversation
    path('voice/start/', views.StartVoiceConversationView.as_view(), name='start-voice-conversation'),
    path('voice/continue/', views.ContinueVoiceConversationView.as_view(), name='continue-voice-conversation'),
    path('voice/end/', views.EndVoiceConversationView.as_view(), name='end-voice-conversation'),
    path('voice/message/', views.VoiceMessageView.as_view(), name='voice-message'),
]