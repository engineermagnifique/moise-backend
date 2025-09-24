# Create this file: apps/common/management/commands/test_communications.py
# First create the directories if they don't exist:
# mkdir -p apps/common/management/commands

from django.core.management.base import BaseCommand
from django.conf import settings
from django.core.mail import send_mail
from twilio.rest import Client
from apps.common.utils import test_email_configuration, test_sms_configuration
import sys

class Command(BaseCommand):
    help = 'Test email and SMS configuration'

    def add_arguments(self, parser):
        parser.add_argument(
            '--email',
            type=str,
            help='Test email address to send to',
        )
        parser.add_argument(
            '--phone',
            type=str,
            help='Test phone number to send SMS to (format: +250XXXXXXXXX)',
        )
        parser.add_argument(
            '--test-connection-only',
            action='store_true',
            help='Only test connections, don\'t send actual messages',
        )

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Testing BusiMap Rwanda Communications Setup'))
        self.stdout.write('=' * 60)

        # Test Email Configuration
        self.stdout.write('\n1. Testing Email Configuration:')
        self.stdout.write('-' * 30)
        
        try:
            # Check settings
            email_settings = {
                'EMAIL_HOST': getattr(settings, 'EMAIL_HOST', 'Not set'),
                'EMAIL_PORT': getattr(settings, 'EMAIL_PORT', 'Not set'),
                'EMAIL_USE_TLS': getattr(settings, 'EMAIL_USE_TLS', 'Not set'),
                'EMAIL_HOST_USER': getattr(settings, 'EMAIL_HOST_USER', 'Not set'),
                'EMAIL_HOST_PASSWORD': '***' if getattr(settings, 'EMAIL_HOST_PASSWORD', None) else 'Not set',
                'EMAIL_BACKEND': getattr(settings, 'EMAIL_BACKEND', 'Not set'),
                'DEFAULT_FROM_EMAIL': getattr(settings, 'DEFAULT_FROM_EMAIL', 'Not set'),
            }
            
            self.stdout.write('Email Settings:')
            for key, value in email_settings.items():
                color = self.style.SUCCESS if value != 'Not set' else self.style.ERROR
                self.stdout.write(f'  {key}: {color(str(value))}')

            # Test connection
            if test_email_configuration():
                self.stdout.write(self.style.SUCCESS('✓ Email connection test passed'))
            else:
                self.stdout.write(self.style.ERROR('✗ Email connection test failed'))

            # Send test email if requested
            if options['email'] and not options['test_connection_only']:
                self.stdout.write(f'\nSending test email to {options["email"]}...')
                try:
                    result = send_mail(
                        subject='BusiMap Rwanda - Test Email',
                        message='This is a test email from BusiMap Rwanda. Email configuration is working!',
                        from_email=getattr(settings, 'DEFAULT_FROM_EMAIL', settings.EMAIL_HOST_USER),
                        recipient_list=[options['email']],
                        fail_silently=False
                    )
                    if result:
                        self.stdout.write(self.style.SUCCESS('✓ Test email sent successfully'))
                    else:
                        self.stdout.write(self.style.ERROR('✗ Test email failed'))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'✗ Test email failed: {str(e)}'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Email configuration error: {str(e)}'))

        # Test SMS Configuration
        self.stdout.write('\n\n2. Testing SMS Configuration:')
        self.stdout.write('-' * 30)
        
        try:
            # Check settings
            sms_settings = {
                'TWILIO_ACCOUNT_SID': getattr(settings, 'TWILIO_ACCOUNT_SID', 'Not set'),
                'TWILIO_AUTH_TOKEN': '***' if getattr(settings, 'TWILIO_AUTH_TOKEN', None) else 'Not set',
                'TWILIO_PHONE_NUMBER': getattr(settings, 'TWILIO_PHONE_NUMBER', 'Not set'),
            }
            
            self.stdout.write('SMS Settings:')
            for key, value in sms_settings.items():
                color = self.style.SUCCESS if value != 'Not set' else self.style.ERROR
                self.stdout.write(f'  {key}: {color(str(value))}')

            # Test connection
            if test_sms_configuration():
                self.stdout.write(self.style.SUCCESS('✓ SMS connection test passed'))
            else:
                self.stdout.write(self.style.ERROR('✗ SMS connection test failed'))

            # Send test SMS if requested
            if options['phone'] and not options['test_connection_only']:
                self.stdout.write(f'\nSending test SMS to {options["phone"]}...')
                try:
                    client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                    message = client.messages.create(
                        body='Test message from BusiMap Rwanda. SMS configuration is working!',
                        from_=settings.TWILIO_PHONE_NUMBER,
                        to=options['phone']
                    )
                    self.stdout.write(self.style.SUCCESS(f'✓ Test SMS sent successfully (SID: {message.sid})'))
                except Exception as e:
                    self.stdout.write(self.style.ERROR(f'✗ Test SMS failed: {str(e)}'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'SMS configuration error: {str(e)}'))

        # Summary and recommendations
        self.stdout.write('\n\n3. Recommendations:')
        self.stdout.write('-' * 20)
        
        recommendations = []
        
        if not getattr(settings, 'EMAIL_HOST_PASSWORD', None):
            recommendations.append('• Generate a Gmail App Password and update EMAIL_HOST_PASSWORD')
            
        if getattr(settings, 'EMAIL_BACKEND', '').endswith('console.EmailBackend'):
            recommendations.append('• Set FORCE_EMAIL_SMTP=True in your .env to use SMTP instead of console backend')
            
        if not getattr(settings, 'TWILIO_ACCOUNT_SID', None):
            recommendations.append('• Configure Twilio credentials for SMS functionality')
            
        # Check if using trial Twilio account
        try:
            if hasattr(settings, 'TWILIO_ACCOUNT_SID') and settings.TWILIO_ACCOUNT_SID.startswith('AC'):
                client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
                account = client.api.accounts(settings.TWILIO_ACCOUNT_SID).fetch()
                if account.status == 'trial':
                    recommendations.append('• Upgrade Twilio account from trial to send SMS to unverified numbers')
        except:
            pass
            
        if recommendations:
            for rec in recommendations:
                self.stdout.write(self.style.WARNING(rec))
        else:
            self.stdout.write(self.style.SUCCESS('✓ Configuration looks good!'))

        self.stdout.write('\n' + '=' * 60)
        self.stdout.write('Test completed!')

