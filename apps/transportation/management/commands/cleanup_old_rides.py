# apps/transportation/management/commands/cleanup_old_rides.py
from django.core.management.base import BaseCommand
from apps.transportation.models import Ride
from django.utils import timezone
from datetime import timedelta

class Command(BaseCommand):
    help = 'Clean up old completed and cancelled rides'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--days',
            type=int,
            default=30,
            help='Number of days to keep completed rides'
        )
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='Show what would be deleted without actually deleting'
        )
    
    def handle(self, *args, **options):
        days = options['days']
        dry_run = options['dry_run']
        
        cutoff_date = timezone.now() - timedelta(days=days)
        
        # Find old completed and cancelled rides
        old_rides = Ride.objects.filter(
            status__in=['completed', 'cancelled'],
            created_at__lt=cutoff_date
        )
        
        count = old_rides.count()
        
        if dry_run:
            self.stdout.write(
                self.style.WARNING(f'Would delete {count} old rides (dry run)')
            )
        else:
            # Delete old rides
            deleted_count, _ = old_rides.delete()
            self.stdout.write(
                self.style.SUCCESS(f'Successfully deleted {deleted_count} old rides')
            )




