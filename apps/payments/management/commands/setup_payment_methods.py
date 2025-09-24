# apps/payments/management/commands/setup_payment_methods.py
from django.core.management.base import BaseCommand
from apps.payments.models import MobileMoneyProvider, PaymentMethod

class Command(BaseCommand):
    help = 'Set up initial payment methods and mobile money providers'
    
    def handle(self, *args, **options):
        # Create Mobile Money Providers
        mtn_momo, created = MobileMoneyProvider.objects.get_or_create(
            code='MTN_MOMO',
            defaults={
                'name': 'MTN Mobile Money',
                'is_active': True,
                'api_endpoint': 'https://sandbox.momodeveloper.mtn.com',
                'callback_url_template': 'https://yourdomain.com/api/payments/mobile-money/callback/mtn_momo/'
            }
        )
        if created:
            self.stdout.write(f'Created MTN Mobile Money provider')
        
        airtel_money, created = MobileMoneyProvider.objects.get_or_create(
            code='AIRTEL_MONEY',
            defaults={
                'name': 'Airtel Money',
                'is_active': True,
                'api_endpoint': 'https://openapi.airtel.africa',
                'callback_url_template': 'https://yourdomain.com/api/payments/mobile-money/callback/airtel_money/'
            }
        )
        if created:
            self.stdout.write(f'Created Airtel Money provider')
        
        # Create Payment Methods
        mtn_method, created = PaymentMethod.objects.get_or_create(
            code='mtn_momo',
            defaults={
                'name': 'MTN Mobile Money',
                'description': 'Pay using MTN Mobile Money',
                'is_active': True,
                'requires_external_integration': True,
                'mobile_money_provider': mtn_momo,
                'api_config': {
                    'environment': 'sandbox',
                    'currency': 'RWF',
                    'callback_required': True
                }
            }
        )
        if created:
            self.stdout.write(f'Created MTN MoMo payment method')
        
        airtel_method, created = PaymentMethod.objects.get_or_create(
            code='airtel_money',
            defaults={
                'name': 'Airtel Money',
                'description': 'Pay using Airtel Money',
                'is_active': True,
                'requires_external_integration': True,
                'mobile_money_provider': airtel_money,
                'api_config': {
                    'environment': 'sandbox',
                    'currency': 'RWF',
                    'callback_required': True
                }
            }
        )
        if created:
            self.stdout.write(f'Created Airtel Money payment method')
        
        # Create other payment methods
        cash_method, created = PaymentMethod.objects.get_or_create(
            code='cash',
            defaults={
                'name': 'Cash Payment',
                'description': 'Pay with cash on delivery/pickup',
                'is_active': True,
                'requires_external_integration': False,
                'api_config': {}
            }
        )
        if created:
            self.stdout.write(f'Created Cash payment method')
        
        self.stdout.write(
            self.style.SUCCESS('Successfully set up payment methods and providers')
        )




