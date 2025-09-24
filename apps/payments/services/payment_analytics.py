# apps/payments/services/payment_analytics.py
import logging
from typing import Dict, Any, List
from decimal import Decimal
from django.db.models import Sum, Count, Avg, Q
from django.utils import timezone
from datetime import timedelta
from apps.payments.models import PaymentTransaction, PaymentMethod, MobileMoneyProvider
from apps.businesses.models import Business
from apps.authentication.models import User

logger = logging.getLogger(__name__)

class PaymentAnalyticsService:
    """
    Service for generating payment analytics and insights.
    """

    @staticmethod
    def get_business_payment_analytics(
        business_id: str, 
        period: str = 'month'
    ) -> Dict[str, Any]:
        """
        Get payment analytics for a specific business.
        """
        try:
            business = Business.objects.get(business_id=business_id)
            
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
            elif period == 'quarter':
                start_date = end_date - timedelta(days=90)
            elif period == 'year':
                start_date = end_date - timedelta(days=365)
            else:
                start_date = end_date - timedelta(days=30)

            # Get transactions for the business in the period
            transactions = PaymentTransaction.objects.filter(
                business=business,
                created_at__gte=start_date,
                created_at__lte=end_date
            )

            # Calculate metrics
            total_transactions = transactions.count()
            successful_transactions = transactions.filter(status='successful').count()
            failed_transactions = transactions.filter(status='failed').count()
            pending_transactions = transactions.filter(status='pending').count()

            # Calculate revenue
            total_revenue = transactions.filter(
                status='successful'
            ).aggregate(Sum('amount'))['amount__sum'] or Decimal('0.00')

            # Calculate average transaction value
            avg_transaction_value = transactions.filter(
                status='successful'
            ).aggregate(Avg('amount'))['amount__avg'] or Decimal('0.00')

            # Success rate
            success_rate = (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0

            # Payment method breakdown
            payment_method_breakdown = transactions.filter(
                status='successful'
            ).values(
                'payment_method__name'
            ).annotate(
                count=Count('transaction_id'),
                revenue=Sum('amount')
            ).order_by('-revenue')

            # Daily revenue trend
            daily_revenue = transactions.filter(
                status='successful'
            ).extra(
                select={'day': "DATE_TRUNC('day', created_at)"}
            ).values('day').annotate(
                revenue=Sum('amount'),
                count=Count('transaction_id')
            ).order_by('day')

            return {
                'business_id': str(business.business_id),
                'business_name': business.business_name,
                'period': period,
                'date_range': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'metrics': {
                    'total_transactions': total_transactions,
                    'successful_transactions': successful_transactions,
                    'failed_transactions': failed_transactions,
                    'pending_transactions': pending_transactions,
                    'success_rate': round(success_rate, 2),
                    'total_revenue': float(total_revenue),
                    'average_transaction_value': float(avg_transaction_value)
                },
                'payment_method_breakdown': list(payment_method_breakdown),
                'daily_revenue_trend': [
                    {
                        'date': item['day'].isoformat(),
                        'revenue': float(item['revenue'] or 0),
                        'transaction_count': item['count']
                    }
                    for item in daily_revenue
                ]
            }

        except Business.DoesNotExist:
            return {'error': f'Business with ID {business_id} not found'}
        except Exception as e:
            logger.exception(f"Error generating business payment analytics: {e}")
            return {'error': str(e)}

    @staticmethod
    def get_system_payment_analytics(period: str = 'month') -> Dict[str, Any]:
        """
        Get overall system payment analytics.
        """
        try:
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
            elif period == 'quarter':
                start_date = end_date - timedelta(days=90)
            elif period == 'year':
                start_date = end_date - timedelta(days=365)
            else:
                start_date = end_date - timedelta(days=30)

            # Get all transactions in the period
            transactions = PaymentTransaction.objects.filter(
                created_at__gte=start_date,
                created_at__lte=end_date
            )

            # Calculate metrics
            total_transactions = transactions.count()
            successful_transactions = transactions.filter(status='successful').count()
            failed_transactions = transactions.filter(status='failed').count()
            pending_transactions = transactions.filter(status='pending').count()

            # Calculate total volume
            total_volume = transactions.filter(
                status='successful'
            ).aggregate(Sum('amount'))['amount__sum'] or Decimal('0.00')

            # Calculate average transaction value
            avg_transaction_value = transactions.filter(
                status='successful'
            ).aggregate(Avg('amount'))['amount__avg'] or Decimal('0.00')

            # Success rate
            success_rate = (successful_transactions / total_transactions * 100) if total_transactions > 0 else 0

            # Payment method popularity
            payment_method_stats = transactions.values(
                'payment_method__name'
            ).annotate(
                count=Count('transaction_id'),
                volume=Sum('amount', filter=Q(status='successful'))
            ).order_by('-count')

            # Mobile money provider breakdown
            mobile_money_stats = transactions.filter(
                payment_method__mobile_money_provider__isnull=False
            ).values(
                'payment_method__mobile_money_provider__name'
            ).annotate(
                count=Count('transaction_id'),
                volume=Sum('amount', filter=Q(status='successful'))
            ).order_by('-count')

            # Transaction type breakdown
            transaction_type_stats = transactions.values(
                'transaction_type'
            ).annotate(
                count=Count('transaction_id'),
                volume=Sum('amount', filter=Q(status='successful'))
            ).order_by('-count')

            return {
                'period': period,
                'date_range': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'metrics': {
                    'total_transactions': total_transactions,
                    'successful_transactions': successful_transactions,
                    'failed_transactions': failed_transactions,
                    'pending_transactions': pending_transactions,
                    'success_rate': round(success_rate, 2),
                    'total_volume': float(total_volume),
                    'average_transaction_value': float(avg_transaction_value)
                },
                'payment_method_stats': [
                    {
                        'method': item['payment_method__name'],
                        'transaction_count': item['count'],
                        'volume': float(item['volume'] or 0)
                    }
                    for item in payment_method_stats
                ],
                'mobile_money_provider_stats': [
                    {
                        'provider': item['payment_method__mobile_money_provider__name'],
                        'transaction_count': item['count'],
                        'volume': float(item['volume'] or 0)
                    }
                    for item in mobile_money_stats
                ],
                'transaction_type_stats': [
                    {
                        'type': item['transaction_type'],
                        'transaction_count': item['count'],
                        'volume': float(item['volume'] or 0)
                    }
                    for item in transaction_type_stats
                ]
            }

        except Exception as e:
            logger.exception(f"Error generating system payment analytics: {e}")
            return {'error': str(e)}

    @staticmethod
    def get_user_payment_history(
        user_id: str, 
        period: str = 'month',
        limit: int = 50
    ) -> Dict[str, Any]:
        """
        Get payment history for a specific user.
        """
        try:
            user = User.objects.get(id=user_id)
            
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
            elif period == 'quarter':
                start_date = end_date - timedelta(days=90)
            elif period == 'year':
                start_date = end_date - timedelta(days=365)
            else:
                start_date = end_date - timedelta(days=30)

            # Get user's transactions
            transactions = PaymentTransaction.objects.filter(
                user=user,
                created_at__gte=start_date,
                created_at__lte=end_date
            ).order_by('-created_at')[:limit]

            # Calculate summary metrics
            total_spent = PaymentTransaction.objects.filter(
                user=user,
                status='successful',
                created_at__gte=start_date,
                created_at__lte=end_date
            ).aggregate(Sum('amount'))['amount__sum'] or Decimal('0.00')

            total_transactions = transactions.count()
            successful_transactions = transactions.filter(status='successful').count()

            # Format transaction history
            transaction_history = []
            for txn in transactions:
                transaction_history.append({
                    'transaction_id': str(txn.transaction_id),
                    'amount': float(txn.amount),
                    'currency': txn.currency,
                    'status': txn.status,
                    'payment_method': txn.payment_method.name,
                    'transaction_type': txn.transaction_type,
                    'business_name': txn.business.business_name if txn.business else None,
                    'created_at': txn.created_at.isoformat(),
                    'completed_at': txn.completed_at.isoformat() if txn.completed_at else None
                })

            return {
                'user_id': str(user.id),
                'user_name': user.get_full_name(),
                'period': period,
                'date_range': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'summary': {
                    'total_spent': float(total_spent),
                    'total_transactions': total_transactions,
                    'successful_transactions': successful_transactions
                },
                'transactions': transaction_history
            }

        except User.DoesNotExist:
            return {'error': f'User with ID {user_id} not found'}
        except Exception as e:
            logger.exception(f"Error generating user payment history: {e}")
            return {'error': str(e)}

    @staticmethod
    def get_payment_failure_analysis(period: str = 'month') -> Dict[str, Any]:
        """
        Analyze payment failures to identify common issues.
        """
        try:
            # Calculate date range
            end_date = timezone.now()
            if period == 'day':
                start_date = end_date - timedelta(days=1)
            elif period == 'week':
                start_date = end_date - timedelta(weeks=1)
            elif period == 'month':
                start_date = end_date - timedelta(days=30)
            else:
                start_date = end_date - timedelta(days=30)

            # Get failed transactions
            failed_transactions = PaymentTransaction.objects.filter(
                status='failed',
                created_at__gte=start_date,
                created_at__lte=end_date
            )

            total_failed = failed_transactions.count()
            
            # Analyze by payment method
            failure_by_method = failed_transactions.values(
                'payment_method__name'
            ).annotate(
                count=Count('transaction_id')
            ).order_by('-count')

            # Analyze by provider (for mobile money)
            failure_by_provider = failed_transactions.filter(
                payment_method__mobile_money_provider__isnull=False
            ).values(
                'payment_method__mobile_money_provider__name'
            ).annotate(
                count=Count('transaction_id')
            ).order_by('-count')

            # Common failure reasons (from provider responses)
            # This would need to be customized based on actual provider response formats
            failure_reasons = []

            return {
                'period': period,
                'date_range': {
                    'start_date': start_date.isoformat(),
                    'end_date': end_date.isoformat()
                },
                'total_failed_transactions': total_failed,
                'failure_by_payment_method': list(failure_by_method),
                'failure_by_mobile_money_provider': list(failure_by_provider),
                'common_failure_reasons': failure_reasons
            }

        except Exception as e:
            logger.exception(f"Error generating payment failure analysis: {e}")
            return {'error': str(e)}




