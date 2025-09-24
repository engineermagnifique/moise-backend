# apps/ai_engine/tasks.py
from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import logging

from .models import ConversationSession, ConversationMessage
from apps.businesses.models import Business
from apps.search.models import SearchQuery

logger = logging.getLogger(__name__)


@shared_task
def clean_expired_conversations():
    """Clean up expired conversation sessions"""

    try:
        # Delete conversations older than 7 days with no activity
        cutoff_date = timezone.now() - timedelta(days=7)

        expired_sessions = ConversationSession.objects.filter(
            last_activity__lt=cutoff_date,
            conversation_state__in=["completed", "timeout"],
        )

        count = expired_sessions.count()
        expired_sessions.delete()

        logger.info(f"Cleaned up {count} expired conversation sessions")
        return f"Cleaned {count} expired sessions"

    except Exception as e:
        logger.error(f"Error cleaning expired conversations: {e}")
        return f"Error: {str(e)}"


@shared_task
def process_conversation_analytics():
    """Process conversation analytics and insights"""

    try:
        # Analyze conversation patterns
        recent_conversations = ConversationSession.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=1)
        )

        # Update conversation statistics
        for conversation in recent_conversations:
            if conversation.total_messages > 0:
                # Calculate satisfaction if not set
                if not conversation.satisfaction_score:
                    # Simple heuristic based on conversation length
                    if conversation.total_messages >= 4:
                        conversation.satisfaction_score = 4.5
                    elif conversation.total_messages >= 2:
                        conversation.satisfaction_score = 4.0
                    else:
                        conversation.satisfaction_score = 3.5

                    conversation.save()

        logger.info("Processed conversation analytics")
        return "Analytics processed successfully"

    except Exception as e:
        logger.error(f"Error processing conversation analytics: {e}")
        return f"Error: {str(e)}"


@shared_task
def update_ai_model_performance():
    """Update AI model performance metrics"""

    try:
        # Analyze recent messages for accuracy
        recent_messages = ConversationMessage.objects.filter(
            created_at__gte=timezone.now() - timedelta(hours=24), message_type="ai"
        )

        total_messages = recent_messages.count()
        if total_messages == 0:
            return "No messages to analyze"

        # Calculate average confidence
        avg_confidence = (
            sum(msg.confidence_score for msg in recent_messages if msg.confidence_score)
            / total_messages
        )

        # Log performance metrics
        logger.info(
            f"AI Performance - Messages: {total_messages}, Avg Confidence: {avg_confidence:.2f}"
        )

        return (
            f"Analyzed {total_messages} messages, avg confidence: {avg_confidence:.2f}"
        )

    except Exception as e:
        logger.error(f"Error updating AI model performance: {e}")
        return f"Error: {str(e)}"


@shared_task
def analyze_user_feedback():
    """Analyze user feedback patterns for AI improvement"""

    try:
        # Get recent conversations with feedback
        recent_date = timezone.now() - timedelta(days=7)
        conversations_with_feedback = ConversationSession.objects.filter(
            created_at__gte=recent_date, satisfaction_score__isnull=False
        )

        if conversations_with_feedback.count() == 0:
            return "No feedback data to analyze"

        # Calculate metrics
        total_conversations = conversations_with_feedback.count()
        avg_satisfaction = conversations_with_feedback.aggregate(
            avg_score=models.Avg("satisfaction_score")
        )["avg_score"]

        # Identify low satisfaction conversations for improvement
        low_satisfaction = conversations_with_feedback.filter(
            satisfaction_score__lt=3.0
        ).count()

        improvement_rate = (
            (total_conversations - low_satisfaction) / total_conversations * 100
        )

        logger.info(
            f"Feedback Analysis - Total: {total_conversations}, "
            f"Avg Satisfaction: {avg_satisfaction:.2f}, "
            f"Improvement Rate: {improvement_rate:.1f}%"
        )

        return f"Analyzed {total_conversations} feedback entries"

    except Exception as e:
        logger.error(f"Error analyzing user feedback: {e}")
        return f"Error: {str(e)}"


@shared_task
def optimize_ai_responses():
    """Optimize AI response patterns based on success metrics"""

    try:
        # Analyze successful conversation patterns
        successful_conversations = ConversationSession.objects.filter(
            created_at__gte=timezone.now() - timedelta(days=30),
            satisfaction_score__gte=4.0,
            total_messages__gte=2,
        )

        # Extract successful response patterns
        successful_patterns = []
        for conversation in successful_conversations[:50]:  # Limit for performance
            messages = conversation.messages.filter(message_type="ai")
            for message in messages:
                if message.confidence_score and message.confidence_score > 0.8:
                    successful_patterns.append(
                        {
                            "intent": message.detected_intent,
                            "language": message.language,
                            "response_length": len(message.message_content),
                            "confidence": message.confidence_score,
                        }
                    )

        # Log optimization insights
        if successful_patterns:
            avg_length = sum(p["response_length"] for p in successful_patterns) / len(
                successful_patterns
            )
            avg_confidence = sum(p["confidence"] for p in successful_patterns) / len(
                successful_patterns
            )

            logger.info(
                f"AI Optimization - Successful patterns: {len(successful_patterns)}, "
                f"Avg response length: {avg_length:.0f} chars, "
                f"Avg confidence: {avg_confidence:.2f}"
            )

        return f"Analyzed {len(successful_patterns)} successful response patterns"

    except Exception as e:
        logger.error(f"Error optimizing AI responses: {e}")
        return f"Error: {str(e)}"
