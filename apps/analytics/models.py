# apps/analytics/models.py
import uuid
from django.db import models
from django.contrib.auth import get_user_model
from apps.common.models import TimestampedModel
from apps.businesses.models import Business

User = get_user_model()


class MarketIntelligence(TimestampedModel):
    """Market intelligence data for business categories"""

    intelligence_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    category_name = models.CharField(max_length=100)
    location = models.CharField(max_length=100)  # Province or district

    # Market overview
    total_businesses = models.PositiveIntegerField(default=0)
    category_growth_rate = models.FloatField(default=0.0)  # Monthly growth %
    market_saturation = models.CharField(
        max_length=20, default="medium"
    )  # low, medium, high
    competition_level = models.FloatField(default=0.0)  # 0.0 to 1.0

    # Customer behavior
    peak_search_times = models.JSONField(default=list)
    popular_search_terms = models.JSONField(default=list)
    seasonal_trends = models.JSONField(default=dict)

    # Pricing insights
    average_price_range = models.CharField(max_length=20, default="medium")
    price_sensitivity = models.FloatField(default=0.0)  # 0.0 to 1.0
    recommended_pricing = models.JSONField(default=dict)

    # Opportunities
    underserved_areas = models.JSONField(default=list)
    emerging_trends = models.JSONField(default=list)
    recommended_improvements = models.JSONField(default=list)

    # Data freshness
    data_period_start = models.DateTimeField()
    data_period_end = models.DateTimeField()

    def __str__(self):
        return f"Market Intelligence: {self.category_name} in {self.location}"

    class Meta:
        db_table = "market_intelligence"
        unique_together = ["category_name", "location"]
        indexes = [
            models.Index(fields=["category_name", "location"]),
            models.Index(fields=["data_period_end"]),
        ]


class CustomerInsight(TimestampedModel):
    """Customer insights for businesses"""

    insight_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="customer_insights"
    )

    # Customer segments
    customer_segments = models.JSONField(default=list)

    # Satisfaction metrics
    overall_satisfaction = models.FloatField(default=0.0)
    service_satisfaction = models.FloatField(default=0.0)
    value_satisfaction = models.FloatField(default=0.0)
    improvement_areas = models.JSONField(default=list)

    # Predictive insights
    growth_potential = models.FloatField(default=0.0)  # 0.0 to 1.0
    churn_risk = models.FloatField(default=0.0)  # 0.0 to 1.0
    revenue_forecast = models.JSONField(default=dict)

    # Analysis period
    analysis_period_days = models.PositiveIntegerField(default=30)
    confidence_score = models.FloatField(default=0.0)  # 0.0 to 1.0

    def __str__(self):
        return f"Customer Insights for {self.business.business_name}"

    class Meta:
        db_table = "customer_insights"
        indexes = [
            models.Index(fields=["business", "created_at"]),
        ]


class CompetitiveAnalysis(TimestampedModel):
    """Competitive analysis for businesses"""

    analysis_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="competitive_analysis"
    )

    # Competitors data
    competitors = models.JSONField(default=list)

    # Competitive position
    market_rank = models.PositiveIntegerField(null=True, blank=True)
    unique_advantages = models.JSONField(default=list)
    areas_for_improvement = models.JSONField(default=list)
    differentiation_score = models.FloatField(default=0.0)

    # Recommendations
    strategic_recommendations = models.JSONField(default=list)

    # Analysis scope
    radius_km = models.FloatField(default=5.0)
    category_focus = models.CharField(max_length=100)

    def __str__(self):
        return f"Competitive Analysis for {self.business.business_name}"

    class Meta:
        db_table = "competitive_analysis"
        indexes = [
            models.Index(fields=["business", "created_at"]),
            models.Index(fields=["category_focus"]),
        ]


class RevenueOptimization(TimestampedModel):
    """Revenue optimization suggestions"""

    optimization_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="revenue_optimizations"
    )

    # Current metrics
    current_metrics = models.JSONField(default=dict)

    # Optimization strategies
    optimization_strategies = models.JSONField(default=list)

    # Predicted outcomes
    predicted_outcomes = models.JSONField(default=dict)

    # Implementation timeline
    implementation_timeline = models.CharField(max_length=100, blank=True)
    priority_level = models.CharField(
        max_length=20, default="medium"
    )  # low, medium, high

    def __str__(self):
        return f"Revenue Optimization for {self.business.business_name}"

    class Meta:
        db_table = "revenue_optimizations"
        indexes = [
            models.Index(fields=["business", "created_at"]),
            models.Index(fields=["priority_level"]),
        ]


class BusinessPerformanceMetric(TimestampedModel):
    """Business performance metrics over time"""

    metric_id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    business = models.ForeignKey(
        Business, on_delete=models.CASCADE, related_name="performance_metrics"
    )

    # Time period
    date = models.DateField()
    metric_type = models.CharField(max_length=50)  # views, clicks, reviews, etc.

    # Metric values
    value = models.FloatField()
    previous_value = models.FloatField(null=True, blank=True)
    change_percentage = models.FloatField(null=True, blank=True)

    # Context
    source = models.CharField(max_length=50, default="system")
    notes = models.TextField(blank=True)

    def __str__(self):
        return f"{self.business.business_name} - {self.metric_type}: {self.value}"

    class Meta:
        db_table = "business_performance_metrics"
        unique_together = ["business", "date", "metric_type"]
        indexes = [
            models.Index(fields=["business", "date"]),
            models.Index(fields=["metric_type", "date"]),
        ]


class SearchAnalytics(TimestampedModel):
    """Search analytics and trends"""

    analytics_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )

    # Search details
    search_term = models.CharField(max_length=200)
    search_category = models.CharField(max_length=100, blank=True)
    location = models.CharField(max_length=100, blank=True)

    # Metrics
    search_count = models.PositiveIntegerField(default=0)
    result_count = models.PositiveIntegerField(default=0)
    click_through_rate = models.FloatField(default=0.0)

    # Time period
    date = models.DateField()
    hour = models.PositiveIntegerField(null=True, blank=True)

    # Trend analysis
    trend_score = models.FloatField(default=0.0)  # -1.0 to 1.0
    is_trending = models.BooleanField(default=False)

    def __str__(self):
        return f"Search Analytics: {self.search_term} - {self.date}"

    class Meta:
        db_table = "search_analytics"
        unique_together = ["search_term", "date", "hour"]
        indexes = [
            models.Index(fields=["search_term", "date"]),
            models.Index(fields=["date", "is_trending"]),
            models.Index(fields=["trend_score"]),
        ]


class UserBehaviorAnalytics(TimestampedModel):
    """User behavior analytics"""

    analytics_id = models.UUIDField(
        primary_key=True, default=uuid.uuid4, editable=False
    )

    # User segment (anonymized)
    user_segment = models.CharField(max_length=50)  # young_professional, family, etc.
    location = models.CharField(max_length=100)

    # Behavior metrics
    session_duration_minutes = models.FloatField(default=0.0)
    pages_viewed = models.PositiveIntegerField(default=0)
    searches_performed = models.PositiveIntegerField(default=0)
    businesses_contacted = models.PositiveIntegerField(default=0)

    # Time period
    date = models.DateField()

    # Engagement scores
    engagement_score = models.FloatField(default=0.0)  # 0.0 to 1.0
    conversion_score = models.FloatField(default=0.0)  # 0.0 to 1.0

    def __str__(self):
        return f"User Behavior: {self.user_segment} - {self.date}"

    class Meta:
        db_table = "user_behavior_analytics"
        unique_together = ["user_segment", "location", "date"]
        indexes = [
            models.Index(fields=["user_segment", "date"]),
            models.Index(fields=["engagement_score"]),
        ]
