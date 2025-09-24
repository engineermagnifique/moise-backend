# apps/transportation/management/commands/update_driver_locations.py
from django.core.management.base import BaseCommand
from apps.transportation.models import Driver
from django.utils import timezone

class Command(BaseCommand):
    help = 'Update driver locations and availability status'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--offline-threshold',
            type=int,
            default=300,  # 5 minutes
            help='Time in seconds after which a driver is considered offline'
        )
    
    def handle(self, *args, **options):
        offline_threshold = options['offline_threshold']
        current_time = timezone.now()
        
        # Find drivers who haven't updated their location recently
        offline_drivers = Driver.objects.filter(
            is_online=True,
            last_location_update__lt=current_time - timezone.timedelta(seconds=offline_threshold)
        )
        
        # Mark them as offline
        count = offline_drivers.update(
            is_online=False,
            is_available=False
        )
        
        self.stdout.write(
            self.style.SUCCESS(f'Successfully marked {count} drivers as offline')
        )




