# apps/common/models.py
import uuid
from django.db import models
from django.utils import timezone

class TimestampedModel(models.Model):
    """Abstract base class with timestamp fields"""
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        abstract = True

class BaseModel(TimestampedModel):
    """Base model with common fields"""
    
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    is_active = models.BooleanField(default=True)
    
    class Meta:
        abstract = True

class SoftDeleteModel(models.Model):
    """Abstract model for soft deletion"""
    
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        abstract = True
    
    def soft_delete(self):
        """Soft delete the instance"""
        self.is_deleted = True
        self.deleted_at = timezone.now()
        self.save()
    
    def restore(self):
        """Restore the soft deleted instance"""
        self.is_deleted = False
        self.deleted_at = None
        self.save()

class AuditModel(TimestampedModel):
    """Model with audit fields"""
    
    created_by = models.ForeignKey(
        'authentication.User', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='created_%(class)s'
    )
    updated_by = models.ForeignKey(
        'authentication.User', 
        on_delete=models.SET_NULL, 
        null=True, 
        blank=True,
        related_name='updated_%(class)s'
    )
    
    class Meta:
        abstract = True