

# apps/common/exceptions.py
from rest_framework.views import exception_handler
from rest_framework.response import Response
from django.http import Http404
from django.core.exceptions import PermissionDenied
import logging

logger = logging.getLogger(__name__)

def custom_exception_handler(exc, context):
    """Custom exception handler with detailed error responses"""
    
    # Call REST framework's default exception handler first
    response = exception_handler(exc, context)
    
    if response is not None:
        custom_response_data = {
            'error': True,
            'message': 'An error occurred',
            'details': response.data
        }
        
        # Customize based on exception type
        if isinstance(exc, Http404):
            custom_response_data['error_code'] = 'not_found'
            custom_response_data['message'] = 'The requested resource was not found'
            
        elif isinstance(exc, PermissionDenied):
            custom_response_data['error_code'] = 'permission_denied'
            custom_response_data['message'] = 'You do not have permission to perform this action'
            
        else:
            custom_response_data['error_code'] = 'validation_error'
            custom_response_data['message'] = 'Invalid input data provided'
        
        response.data = custom_response_data
        
        # Log the error
        logger.error(f"API Error: {exc}", extra={
            'request': context.get('request'),
            'view': context.get('view')
        })
    
    return response

class BusiMapException(Exception):
    """Base exception for BusiMap Rwanda application"""
    pass

class AIProcessingError(BusiMapException):
    """Exception for AI processing errors"""
    pass

class BusinessNotFoundError(BusiMapException):
    """Exception for business not found errors"""
    pass

class LocationServiceError(BusiMapException):
    """Exception for location service errors"""
    pass