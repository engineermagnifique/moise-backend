# apps/transportation/management/commands/generate_analytics.py
from django.core.management.base import BaseCommand
from apps.transportation.services.analytics_service import AnalyticsService
from django.utils import timezone

class Command(BaseCommand):
    help = 'Generate transportation analytics reports'
    
    def add_arguments(self, parser):
        parser.add_argument(
            '--period',
            type=str,
            choices=['day', 'week', 'month'],
            default='week',
            help='Time period for analytics'
        )
        parser.add_argument(
            '--driver-id',
            type=str,
            help='Generate analytics for specific driver'
        )
        parser.add_argument(
            '--user-id',
            type=str,
            help='Generate analytics for specific user'
        )
    
    def handle(self, *args, **options):
        period = options['period']
        driver_id = options.get('driver_id')
        user_id = options.get('user_id')
        
        analytics_service = AnalyticsService()
        
        if driver_id:
            # Generate driver analytics
            analytics = analytics_service.get_driver_analytics(driver_id, period)
            self.stdout.write(f'Driver Analytics: {analytics}')
            
        elif user_id:
            # Generate user analytics
            analytics = analytics_service.get_passenger_analytics(user_id, period)
            self.stdout.write(f'User Analytics: {analytics}')
            
        else:
            # Generate system analytics
            analytics = analytics_service.get_system_analytics(period)
            self.stdout.write(f'System Analytics: {analytics}')
            
            # Generate trends
            trends = analytics_service.get_ride_trends(period)
            self.stdout.write(f'Ride Trends: {trends}')
        
        self.stdout.write(
            self.style.SUCCESS('Analytics generated successfully')
        )




