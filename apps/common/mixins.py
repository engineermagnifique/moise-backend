
# apps/common/mixins.py
from django.db import models
from django.utils import timezone
from rest_framework import status
from rest_framework.response import Response

class TimestampMixin(models.Model):
    """Mixin to add timestamp fields"""
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True

class SoftDeleteMixin(models.Model):
    """Mixin to add soft delete functionality"""
    
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        abstract = True
    
    def delete(self, using=None, keep_parents=False):
        """Soft delete by setting is_deleted=True"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save(using=using)
    
    def hard_delete(self):
        """Permanently delete the record"""
        super().delete()

class ViewCountMixin(models.Model):
    """Mixin to add view counting functionality"""
    
    view_count = models.PositiveIntegerField(default=0)
    last_viewed = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        abstract = True
    
    def increment_views(self):
        """Increment view count atomically"""
        self.__class__.objects.filter(pk=self.pk).update(
            view_count=models.F('view_count') + 1,
            last_viewed=timezone.now()
        )

class ResponseMixin:
    """Mixin for consistent API responses"""
    
    def success_response(self, data=None, message="Success", status_code=status.HTTP_200_OK):
        """Return success response"""
        return Response({
            'success': True,
            'message': message,
            'data': data
        }, status=status_code)
    
    def error_response(self, message="An error occurred", errors=None, status_code=status.HTTP_400_BAD_REQUEST):
        """Return error response"""
        return Response({
            'success': False,
            'message': message,
            'errors': errors
        }, status=status_code)