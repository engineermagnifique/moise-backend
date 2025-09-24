# apps/analytics/tasks.py
from celery import shared_task
from django.utils import timezone
from django.db.models import Count, Avg, Sum, Q
from datetime import timedelta
import logging

from apps.businesses.models import Business, BusinessAnalytics
from apps.search.models import SearchQuery, PopularSearch

logger = logging.getLogger(__name__)


@shared_task
def update_business_analytics():
    """Update business analytics data"""

    try:
        updated_count = 0

        for business in Business.objects.filter(is_active=True):
            analytics, created = BusinessAnalytics.objects.get_or_create(
                business=business
            )

            # Update view counts (you'd get this from actual view tracking)
            analytics.total_views = business.view_count

            # Calculate metrics for recent periods
            now = timezone.now()
            week_ago = now - timedelta(days=7)
            month_ago = now - timedelta(days=30)

            # Views this week/month (would be from actual tracking data)
            analytics.views_this_week = business.view_count // 10  # Mock data
            analytics.views_this_month = business.view_count // 3  # Mock data

            # Search appearances from SearchQuery
            analytics.search_appearances = SearchQuery.objects.filter(
                query_text__icontains=business.business_name, created_at__gte=month_ago
            ).count()

            # Contact clicks (would be from actual click tracking)
            analytics.contact_clicks = analytics.total_views // 20

            # Review velocity
            recent_reviews = business.reviews.filter(created_at__gte=month_ago)
            analytics.review_velocity = recent_reviews.count()

            # Conversion rates
            if analytics.total_views > 0:
                analytics.view_to_contact_rate = (
                    analytics.contact_clicks / analytics.total_views
                )

            if analytics.search_appearances > 0:
                analytics.search_to_view_rate = (
                    analytics.total_views / analytics.search_appearances
                )

            analytics.save()
            updated_count += 1

        logger.info(f"Updated analytics for {updated_count} businesses")
        return f"Updated {updated_count} business analytics"

    except Exception as e:
        logger.error(f"Error updating business analytics: {e}")
        return f"Error: {str(e)}"


@shared_task
def update_search_trends():
    """Update search trends and popular searches"""

    try:
        # Get recent search queries
        week_ago = timezone.now() - timedelta(days=7)
        month_ago = timezone.now() - timedelta(days=30)

        # Update popular searches
        recent_searches = SearchQuery.objects.filter(created_at__gte=week_ago)

        search_counts = {}
        for search in recent_searches:
            query = search.query_text.lower().strip()
            if len(query) > 2:  # Ignore very short queries
                search_counts[query] = search_counts.get(query, 0) + 1

        # Update PopularSearch records
        for query, count in search_counts.items():
            popular_search, created = PopularSearch.objects.get_or_create(
                search_term=query, defaults={"search_count": 0}
            )

            if created:
                popular_search.search_count = count
            else:
                popular_search.search_count += count

            # Update weekly/monthly counts
            popular_search.searches_this_week = count
            if not created:
                # Get monthly count from existing data
                monthly_searches = SearchQuery.objects.filter(
                    query_text__icontains=query, created_at__gte=month_ago
                ).count()
                popular_search.searches_this_month = monthly_searches

            # Calculate trend score
            popular_search.trend_score = (
                popular_search.searches_this_week * 0.7
                + popular_search.searches_this_month * 0.3
            )

            popular_search.save()

        logger.info(f"Updated search trends for {len(search_counts)} queries")
        return f"Updated {len(search_counts)} search trends"

    except Exception as e:
        logger.error(f"Error updating search trends: {e}")
        return f"Error: {str(e)}"


@shared_task
def calculate_business_performance_metrics():
    """Calculate comprehensive business performance metrics"""

    try:
        # Get date ranges for analysis
        now = timezone.now()
        last_week = now - timedelta(days=7)
        last_month = now - timedelta(days=30)
        last_quarter = now - timedelta(days=90)

        businesses = Business.objects.filter(is_active=True)
        metrics_updated = 0

        for business in businesses:
            analytics, created = BusinessAnalytics.objects.get_or_create(
                business=business
            )

            # Calculate performance scores
            # Business completeness score
            completeness_score = 0
            if business.description:
                completeness_score += 20
            if business.phone_number:
                completeness_score += 15
            if business.email:
                completeness_score += 10
            if business.website:
                completeness_score += 10
            if business.images.exists():
                completeness_score += 15
            if business.working_hours:
                completeness_score += 10
            if business.services:
                completeness_score += 20

            analytics.completeness_score = completeness_score

            # Engagement metrics
            reviews = business.reviews.all()
            if reviews.exists():
                analytics.average_rating = (
                    reviews.aggregate(avg=Avg("rating"))["avg"] or 0
                )
                analytics.total_reviews = reviews.count()

                # Recent engagement
                recent_reviews = reviews.filter(created_at__gte=last_month)
                analytics.recent_engagement = recent_reviews.count()

            # Search visibility score
            search_mentions = SearchQuery.objects.filter(
                Q(query_text__icontains=business.business_name)
                | Q(
                    query_text__icontains=(
                        business.category.name if business.category else ""
                    )
                )
            ).count()

            analytics.search_visibility_score = min(search_mentions * 5, 100)

            # Calculate overall performance score
            performance_factors = [
                analytics.completeness_score * 0.3,
                analytics.average_rating
                * 20
                * 0.25,  # Convert 5-star to 100-point scale
                analytics.search_visibility_score * 0.2,
                min(analytics.total_reviews * 2, 100) * 0.15,  # Review count factor
                min(analytics.recent_engagement * 10, 100)
                * 0.1,  # Recent activity factor
            ]

            analytics.performance_score = sum(performance_factors)

            # Update timestamps
            analytics.last_calculated = now
            analytics.save()

            metrics_updated += 1

        logger.info(f"Updated performance metrics for {metrics_updated} businesses")
        return f"Updated performance metrics for {metrics_updated} businesses"

    except Exception as e:
        logger.error(f"Error calculating business performance metrics: {e}")
        return f"Error: {str(e)}"


@shared_task
def generate_trending_categories():
    """Generate trending business categories based on search data"""

    try:
        # Analyze search patterns for the last week
        week_ago = timezone.now() - timedelta(days=7)

        # Get search queries and analyze for category mentions
        recent_searches = SearchQuery.objects.filter(created_at__gte=week_ago)

        category_mentions = {}

        # Common category keywords mapping
        category_keywords = {
            "restaurant": ["restaurant", "kurya", "food", "manger", "eat"],
            "hotel": ["hotel", "accommodation", "lodge", "guesthouse"],
            "hospital": ["hospital", "clinic", "medical", "doctor", "ubuvuzi"],
            "shop": ["shop", "store", "market", "shopping", "gura"],
            "transport": ["transport", "taxi", "bus", "car", "ubwikorezi"],
            "school": ["school", "education", "ishuri", "university"],
            "bank": ["bank", "atm", "money", "amafaranga", "banque"],
            "pharmacy": ["pharmacy", "medicine", "imiti", "pharmacie"],
        }

        # Count category mentions in search queries
        for search in recent_searches:
            query_lower = search.query_text.lower()
            for category, keywords in category_keywords.items():
                for keyword in keywords:
                    if keyword in query_lower:
                        category_mentions[category] = (
                            category_mentions.get(category, 0) + 1
                        )
                        break  # Count each search only once per category

        # Update or create trending data
        from apps.businesses.models import BusinessCategory

        for category_name, mention_count in category_mentions.items():
            try:
                category = BusinessCategory.objects.filter(
                    name__icontains=category_name
                ).first()

                if category:
                    # Update category trend data (you might want to add a trend field to the model)
                    category.search_trend_score = mention_count
                    category.save()

            except Exception as e:
                logger.warning(
                    f"Could not update trend for category {category_name}: {e}"
                )

        logger.info(f"Generated trends for {len(category_mentions)} categories")
        return f"Generated trends for {len(category_mentions)} categories"

    except Exception as e:
        logger.error(f"Error generating trending categories: {e}")
        return f"Error: {str(e)}"


@shared_task
def cleanup_old_analytics_data():
    """Clean up old analytics data to maintain database performance"""

    try:
        # Define retention periods
        search_retention_days = 90  # Keep search queries for 90 days
        analytics_retention_days = 365  # Keep detailed analytics for 1 year

        cutoff_search = timezone.now() - timedelta(days=search_retention_days)
        cutoff_analytics = timezone.now() - timedelta(days=analytics_retention_days)

        # Clean up old search queries
        old_searches = SearchQuery.objects.filter(created_at__lt=cutoff_search)
        search_count = old_searches.count()
        old_searches.delete()

        # Archive old analytics data (instead of deleting, you might want to aggregate)
        # For now, we'll just log what would be cleaned
        old_analytics = BusinessAnalytics.objects.filter(
            last_calculated__lt=cutoff_analytics
        )
        analytics_count = old_analytics.count()

        # Instead of deleting, update them with summary data
        for analytics in old_analytics:
            # Archive the data or create summary records
            # This is where you'd implement data archiving logic
            pass

        logger.info(
            f"Cleaned up {search_count} old search queries, "
            f"processed {analytics_count} old analytics records"
        )

        return f"Cleaned {search_count} searches, processed {analytics_count} analytics"

    except Exception as e:
        logger.error(f"Error cleaning up analytics data: {e}")
        return f"Error: {str(e)}"


@shared_task
def generate_business_insights():
    """Generate actionable insights for businesses"""

    try:
        businesses = Business.objects.filter(is_active=True)
        insights_generated = 0

        for business in businesses:
            analytics = BusinessAnalytics.objects.filter(business=business).first()
            if not analytics:
                continue

            insights = []

            # Completeness insights
            if analytics.completeness_score < 50:
                insights.append(
                    {
                        "type": "completeness",
                        "priority": "high",
                        "message": "Complete your business profile to improve visibility",
                        "action": "Add missing information like description, contact details, and photos",
                    }
                )

            # Review insights
            if analytics.total_reviews < 5:
                insights.append(
                    {
                        "type": "reviews",
                        "priority": "medium",
                        "message": "Encourage customers to leave reviews",
                        "action": "Ask satisfied customers to share their experience online",
                    }
                )
            elif analytics.average_rating < 3.5:
                insights.append(
                    {
                        "type": "quality",
                        "priority": "high",
                        "message": "Focus on improving customer satisfaction",
                        "action": "Address customer concerns mentioned in recent reviews",
                    }
                )

            # Visibility insights
            if analytics.search_visibility_score < 30:
                insights.append(
                    {
                        "type": "visibility",
                        "priority": "medium",
                        "message": "Your business has low search visibility",
                        "action": "Update your category and add relevant keywords to your description",
                    }
                )

            # Performance insights
            if analytics.performance_score < 60:
                insights.append(
                    {
                        "type": "performance",
                        "priority": "medium",
                        "message": "Overall business performance can be improved",
                        "action": "Focus on profile completion, customer reviews, and regular updates",
                    }
                )

            # Store insights (you might want to create an Insights model)
            # For now, we'll just log them
            if insights:
                logger.info(
                    f"Generated {len(insights)} insights for {business.business_name}"
                )
                insights_generated += len(insights)

        logger.info(f"Generated {insights_generated} total business insights")
        return f"Generated {insights_generated} business insights"

    except Exception as e:
        logger.error(f"Error generating business insights: {e}")
        return f"Error: {str(e)}"
