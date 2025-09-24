# apps/search/tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import logging

from .models import SearchQuery

logger = logging.getLogger(__name__)


@shared_task
def cleanup_old_search_queries():
    """Clean up old search queries to save space"""

    try:
        # Keep search queries for 30 days only
        cutoff_date = timezone.now() - timedelta(days=30)

        old_queries = SearchQuery.objects.filter(created_at__lt=cutoff_date)
        count = old_queries.count()
        old_queries.delete()

        logger.info(f"Cleaned up {count} old search queries")
        return f"Cleaned {count} old search queries"

    except Exception as e:
        logger.error(f"Error cleaning search queries: {e}")
        return f"Error: {str(e)}"


@shared_task
def update_search_index():
    """Update search index for better performance"""

    try:
        from apps.businesses.models import Business
        from django.contrib.postgres.search import SearchVector

        # Update search vectors for businesses
        businesses = Business.objects.filter(is_active=True)
        updated_count = 0

        for business in businesses:
            # Create comprehensive search vector
            search_vector = (
                SearchVector("business_name", weight="A")
                + SearchVector("description", weight="B")
                + SearchVector("address", weight="C")
                + SearchVector("services", weight="D")
            )

            business.search_vector = search_vector
            business.save(update_fields=["search_vector"])
            updated_count += 1

        logger.info(f"Updated search index for {updated_count} businesses")
        return f"Updated search index for {updated_count} businesses"

    except Exception as e:
        logger.error(f"Error updating search index: {e}")
        return f"Error: {str(e)}"


@shared_task
def analyze_search_performance():
    """Analyze search performance and optimize queries"""

    try:
        # Analyze recent search queries
        recent_date = timezone.now() - timedelta(days=7)
        recent_searches = SearchQuery.objects.filter(created_at__gte=recent_date)

        if recent_searches.count() == 0:
            return "No recent searches to analyze"

        # Calculate performance metrics
        total_searches = recent_searches.count()
        searches_with_results = recent_searches.filter(results_count__gt=0).count()
        avg_results = (
            recent_searches.aggregate(avg_results=models.Avg("results_count"))[
                "avg_results"
            ]
            or 0
        )

        success_rate = (
            (searches_with_results / total_searches) * 100 if total_searches > 0 else 0
        )

        # Identify problematic search patterns
        zero_result_searches = recent_searches.filter(results_count=0)
        common_failed_searches = {}

        for search in zero_result_searches:
            query = search.query_text.lower().strip()
            if len(query) > 2:  # Ignore very short queries
                common_failed_searches[query] = common_failed_searches.get(query, 0) + 1

        # Sort by frequency
        failed_patterns = sorted(
            common_failed_searches.items(), key=lambda x: x[1], reverse=True
        )[:10]

        logger.info(f"Search Performance Analysis:")
        logger.info(f"Total searches: {total_searches}")
        logger.info(f"Success rate: {success_rate:.1f}%")
        logger.info(f"Average results: {avg_results:.1f}")
        logger.info(f"Common failed searches: {failed_patterns[:5]}")

        return f"Analyzed {total_searches} searches, {success_rate:.1f}% success rate"

    except Exception as e:
        logger.error(f"Error analyzing search performance: {e}")
        return f"Error: {str(e)}"


@shared_task
def optimize_search_suggestions():
    """Optimize search suggestions based on user behavior"""

    try:
        from .models import PopularSearch

        # Get recent successful searches
        week_ago = timezone.now() - timedelta(days=7)
        successful_searches = SearchQuery.objects.filter(
            created_at__gte=week_ago, results_count__gt=0
        )

        # Build suggestion mappings
        suggestion_map = {}

        for search in successful_searches:
            query = search.query_text.lower().strip()
            if len(query) >= 3:  # Minimum query length
                words = query.split()

                # Create suggestions for partial matches
                for i in range(1, len(words) + 1):
                    partial = " ".join(words[:i])
                    if len(partial) >= 2:
                        if partial not in suggestion_map:
                            suggestion_map[partial] = []

                        if query not in suggestion_map[partial]:
                            suggestion_map[partial].append(query)

        # Update suggestion cache or database
        suggestions_created = 0
        for partial, full_queries in suggestion_map.items():
            # Limit to top 5 suggestions per partial query
            top_suggestions = full_queries[:5]

            # You might want to store these in a SuggestionCache model
            # For now, we'll just log the optimization
            logger.debug(f"Partial: '{partial}' -> Suggestions: {top_suggestions}")
            suggestions_created += len(top_suggestions)

        logger.info(f"Optimized search suggestions: {suggestions_created} mappings")
        return f"Optimized {suggestions_created} search suggestion mappings"

    except Exception as e:
        logger.error(f"Error optimizing search suggestions: {e}")
        return f"Error: {str(e)}"


@shared_task
def generate_search_reports():
    """Generate comprehensive search reports"""

    try:
        # Generate reports for different time periods
        time_periods = [("daily", 1), ("weekly", 7), ("monthly", 30)]

        reports_generated = 0

        for period_name, days in time_periods:
            start_date = timezone.now() - timedelta(days=days)
            period_searches = SearchQuery.objects.filter(created_at__gte=start_date)

            if period_searches.count() == 0:
                continue

            # Generate report data
            report_data = {
                "period": period_name,
                "total_searches": period_searches.count(),
                "unique_queries": period_searches.values("query_text")
                .distinct()
                .count(),
                "avg_results_per_search": period_searches.aggregate(
                    avg=models.Avg("results_count")
                )["avg"]
                or 0,
                "top_languages": list(
                    period_searches.values("original_language")
                    .annotate(count=Count("original_language"))
                    .order_by("-count")[:5]
                ),
                "search_success_rate": (
                    (
                        period_searches.filter(results_count__gt=0).count()
                        / period_searches.count()
                        * 100
                    )
                    if period_searches.count() > 0
                    else 0
                ),
                "generated_at": timezone.now().isoformat(),
            }

            # Store report (you might want to create a SearchReport model)
            logger.info(f"{period_name.title()} Search Report Generated:")
            logger.info(f"  Total searches: {report_data['total_searches']}")
            logger.info(f"  Success rate: {report_data['search_success_rate']:.1f}%")
            logger.info(
                f"  Top languages: {[lang['original_language'] for lang in report_data['top_languages']]}"
            )

            reports_generated += 1

        return f"Generated {reports_generated} search reports"

    except Exception as e:
        logger.error(f"Error generating search reports: {e}")
        return f"Error: {str(e)}"
