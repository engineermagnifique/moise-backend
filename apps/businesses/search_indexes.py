# apps/search/search_indexes.py
from django_elasticsearch_dsl import Document, fields
from django_elasticsearch_dsl.registries import registry
from apps.businesses.models import Business

@registry.register_document
class BusinessDocument(Document):
    """Elasticsearch document for Business model"""
    
    category = fields.ObjectField(properties={
        'name': fields.TextField(),
        'description': fields.TextField(),
    })
    
    subcategories = fields.NestedField(properties={
        'name': fields.TextField(),
        'description': fields.TextField(),
    })
    
    class Index:
        name = 'businesses'
        settings = {
            'number_of_shards': 1,
            'number_of_replicas': 0
        }
    
    class Django:
        model = Business
        fields = [
            'business_id',
            'business_name',
            'business_name_kinyarwanda',
            'description',
            'description_kinyarwanda',
            'province',
            'district',
            'sector',
            'cell',
            'address',
            'phone_number',
            'secondary_phone',
            'email',
            'website',
            'price_range',
            'amenities',
            'services_offered',
            'payment_methods',
            'verification_status',
            'is_active',
            'is_featured',
            'view_count',
            'contact_clicks',
            'created_at',
            'updated_at'
        ]
    
    def get_queryset(self):
        return super().get_queryset().select_related('category').prefetch_related('subcategories', 'images')
    
    def prepare_latitude(self, instance):
        return float(instance.latitude) if instance.latitude else None
    
    def prepare_longitude(self, instance):
        return float(instance.longitude) if instance.longitude else None
    
    def prepare_rating(self, instance):
        return instance.average_rating
    
    def prepare_total_reviews(self, instance):
        return instance.total_reviews