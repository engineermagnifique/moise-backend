# apps/common/utils.py - FIXED VERSION
from django.conf import settings
from twilio.rest import Client
from twilio.base.exceptions import TwilioRestException
import logging
import requests

logger = logging.getLogger(__name__)

def get_client_ip(request):
    """Get client IP address from request"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def send_sms(phone_number, message):
    """Send SMS using Twilio - FIXED VERSION"""
    try:
        # Check if Twilio is configured
        if not all([settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN, settings.TWILIO_PHONE_NUMBER]):
            logger.error("Twilio not configured properly. Missing credentials.")
            return False
            
        # Validate phone number format (Rwanda)
        if not phone_number.startswith('+250'):
            logger.error(f"Invalid Rwanda phone number format: {phone_number}")
            return False
            
        logger.info(f"Attempting to send SMS to {phone_number}")

        # Initialize Twilio client
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        
        # Send SMS
        message_obj = client.messages.create(
            body=message,
            from_=settings.TWILIO_PHONE_NUMBER,
            to=phone_number
        )
        
        logger.info(f"SMS sent successfully to {phone_number}, SID: {message_obj.sid}")
        return True
        
    except TwilioRestException as e:
        logger.error(f"Twilio error sending SMS to {phone_number}: {e.msg}")
        logger.error(f"Twilio error code: {e.code}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error sending SMS to {phone_number}: {str(e)}")
        return False

def send_email_verification(user, verification_url):
    """Send email verification - FIXED VERSION"""
    from django.core.mail import send_mail
    from django.template.loader import render_to_string
    
    try:
        subject = 'Verify your BusiMap Rwanda account'
        
        # Check if email settings are configured
        if not all([settings.EMAIL_HOST, settings.EMAIL_HOST_USER, settings.EMAIL_HOST_PASSWORD]):
            logger.error("Email settings not configured properly")
            return False
            
        # Render HTML template
        html_message = render_to_string('emails/email_verification.html', {
            'user': user,
            'verification_url': verification_url,
            'expires_hours': 24
        })
        
        # Plain text fallback
        plain_message = f"""
        Hello {user.first_name},

        Welcome to BusiMap Rwanda!

        Please verify your email address by clicking the link below:
        {verification_url}

        This link will expire in 24 hours.

        If you didn't create an account, please ignore this email.

        Best regards,
        The BusiMap Rwanda Team
        """
        
        # Send email
        send_mail(
            subject=subject,
            message=plain_message,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[user.email],
            html_message=html_message,
            fail_silently=False
        )
        
        logger.info(f"Email verification sent successfully to {user.email}")
        return True
        
    except Exception as e:
        logger.error(f"Failed to send email verification to {user.email}: {str(e)}")
        return False

# Add a test function
def test_email_sms_configuration():
    """Test email and SMS configuration"""
    results = {
        'email_configured': bool(settings.EMAIL_HOST and settings.EMAIL_HOST_USER),
        'sms_configured': bool(settings.TWILIO_ACCOUNT_SID and settings.TWILIO_AUTH_TOKEN),
        'frontend_url': getattr(settings, 'FRONTEND_URL', 'NOT SET'),
    }
    
    logger.info(f"Configuration test: {results}")
    return results


from django.core.mail import get_connection

def test_email_configuration():
    """Check if email settings work by opening a connection."""
    try:
        conn = get_connection()
        conn.open()
        conn.close()
        return True
    except Exception as e:
        logger.error(f"Email configuration test failed: {e}")
        return False

def test_sms_configuration():
    """Check if Twilio settings are valid by fetching account info."""
    try:
        client = Client(settings.TWILIO_ACCOUNT_SID, settings.TWILIO_AUTH_TOKEN)
        account = client.api.accounts(settings.TWILIO_ACCOUNT_SID).fetch()
        return account.status in ["active", "trial"]
    except Exception as e:
        logger.error(f"SMS configuration test failed: {e}")
        return False
