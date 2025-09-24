# apps/payments/management/commands/cleanup_old_transactions.py
from django.core.management.base import BaseCommand
from apps.payments.models import PaymentTransaction
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Clean up old payment transactions'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=365,
            help='Number of days to keep completed transactions'
        )
        parser.add_argument(
            '--failed-days',
            type=int,
            default=90,
            help='Number of days to keep failed transactions'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )
    
    def handle(self, *args, **options):
        days = options['days']
        failed_days = options['failed_days']
        dry_run = options['dry_run']
        
        completed_cutoff = timezone.now() - timedelta(days=days)
        failed_cutoff = timezone.now() - timedelta(days=failed_days)
        
        # Find old completed transactions
        old_completed = PaymentTransaction.objects.filter(
            status='successful',
            completed_at__lt=completed_cutoff
        )
        
        # Find old failed transactions
        old_failed = PaymentTransaction.objects.filter(
            status__in=['failed', 'cancelled'],
            created_at__lt=failed_cutoff
        )
        
        completed_count = old_completed.count()
        failed_count = old_failed.count()
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(
                    f'Would delete {completed_count} old completed transactions '
                    f'and {failed_count} old failed transactions (dry run)'
                )
            )
        else:
            # Delete old transactions
            deleted_completed, _ = old_completed.delete()
            deleted_failed, _ = old_failed.delete()
            
            self.stdout.write(
                self.style.SUCCESS(
                    f'Successfully deleted {deleted_completed} completed transactions '
                    f'and {deleted_failed} failed transactions'
                )
            )




