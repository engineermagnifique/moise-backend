
# apps/common/validators.py
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
import re

def validate_rwanda_phone_number(value):
    """Validate Rwanda phone number"""
    pattern = r'^\+250[7][0-9]{8}$'
    if not re.match(pattern, value):
        raise ValidationError('Phone number must be in format +250XXXXXXXX')

def validate_rwanda_location(value):
    """Validate Rwanda location data"""
    required_fields = ['province', 'district']
    for field in required_fields:
        if field not in value:
            raise ValidationError(f'Location must include {field}')

rwanda_phone_validator = RegexValidator(
    regex=r'^\+250[7][0-9]{8}$',
    message='Phone number must be in format +250XXXXXXXX'
)

def validate_business_hours(value):
    """Validate business hours format"""
    if not isinstance(value, dict):
        raise ValidationError('Business hours must be a dictionary')
    
    valid_days = ['monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday']
    time_pattern = r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]-([0-1]?[0-9]|2[0-3]):[0-5][0-9]$'
    
    for day, hours in value.items():
        if day.lower() not in valid_days:
            raise ValidationError(f'Invalid day: {day}')
        
        if hours and not re.match(time_pattern, hours):
            raise ValidationError(f'Invalid time format for {day}. Use HH:MM-HH:MM')
