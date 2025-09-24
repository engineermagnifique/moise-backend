# apps/search/models.py
import uuid
from django.db import models
from django.contrib.auth import get_user_model
from django.utils import timezone

User = get_user_model()

class SearchQuery(models.Model):
    """Store user search queries for analytics and improvement"""
    
    query_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    user = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True)
    
    # Search Details
    query_text = models.TextField()
    original_language = models.CharField(max_length=10, default='en')
    processed_query = models.TextField(blank=True)  # After NLP processing
    
    # Search Context
    user_location = models.JSONField(null=True, blank=True)
    search_filters = models.JSONField(default=dict)
    search_type = models.CharField(max_length=50, default='general')  # general, voice, ai_chat
    
    # Results
    results_count = models.PositiveIntegerField(default=0)
    clicked_business_ids = models.JSONField(default=list)
    user_satisfaction = models.IntegerField(null=True, blank=True)  # 1-5 rating
    
    # Analytics
    response_time_ms = models.PositiveIntegerField(null=True)
    search_session_id = models.CharField(max_length=100, blank=True)
    
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'search_queries'
        indexes = [
            models.Index(fields=['user', 'created_at']),
            models.Index(fields=['query_text']),
            models.Index(fields=['search_type']),
        ]

class PopularSearch(models.Model):
    """Track popular search terms"""
    
    search_term = models.CharField(max_length=200, unique=True)
    search_count = models.PositiveIntegerField(default=1)
    language = models.CharField(max_length=10, default='en')
    category = models.CharField(max_length=50, blank=True)
    
    # Trending metrics
    searches_this_week = models.PositiveIntegerField(default=0)
    searches_this_month = models.PositiveIntegerField(default=0)
    trend_score = models.FloatField(default=0.0)
    
    last_searched = models.DateTimeField(auto_now=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'popular_searches'