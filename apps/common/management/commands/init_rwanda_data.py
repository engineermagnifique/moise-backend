

# management/commands/init_rwanda_data.py
from django.core.management.base import BaseCommand
from apps.locations.models import RwandaProvince, RwandaDistrict, RwandaSector
from apps.businesses.models import BusinessCategory

class Command(BaseCommand):
    """Initialize Rwanda geographic data and business categories"""
    
    help = 'Initialize Rwanda provinces, districts, sectors and business categories'

    def handle(self, *args, **options):
        self.stdout.write('Initializing Rwanda data...')
        
        # Create provinces
        self.create_provinces()
        
        # Create districts
        self.create_districts()
        
        # Create business categories
        self.create_business_categories()
        
        self.stdout.write(self.style.SUCCESS('Successfully initialized Rwanda data'))

    def create_provinces(self):
        """Create Rwanda provinces"""
        
        provinces_data = [
            {
                'name': 'Kigali',
                'name_kinyarwanda': 'Kigali',
                'name_french': 'Kigali',
                'latitude': -1.9441,
                'longitude': 30.0619,
                'area_km2': 730,
                'population': 1132686
            },
            {
                'name': 'Eastern',
                'name_kinyarwanda': 'Iburasirazuba',
                'name_french': 'Est',
                'latitude': -2.0000,
                'longitude': 30.5000,
                'area_km2': 9458,
                'population': 2595703
            },
            {
                'name': 'Western',
                'name_kinyarwanda': 'Iburengerazuba',
                'name_french': 'Ouest',
                'latitude': -2.2000,
                'longitude': 29.5000,
                'area_km2': 5883,
                'population': 2471239
            },
            {
                'name': 'Northern',
                'name_kinyarwanda': 'Amajyaruguru',
                'name_french': 'Nord',
                'latitude': -1.5000,
                'longitude': 29.8000,
                'area_km2': 3276,
                'population': 1726370
            },
            {
                'name': 'Southern',
                'name_kinyarwanda': 'Amajyepfo',
                'name_french': 'Sud',
                'latitude': -2.6000,
                'longitude': 29.8000,
                'area_km2': 5963,
                'population': 2589975
            }
        ]
        
        for province_data in provinces_data:
            province, created = RwandaProvince.objects.get_or_create(
                name=province_data['name'],
                defaults=province_data
            )
            if created:
                self.stdout.write(f'Created province: {province.name}')

    def create_districts(self):
        """Create Rwanda districts"""
        
        # Sample districts for each province
        districts_data = {
            'Kigali': [
                {'name': 'Nyarugenge', 'name_kinyarwanda': 'Nyarugenge', 'name_french': 'Nyarugenge', 'latitude': -1.9536, 'longitude': 30.0605, 'area_km2': 134},
                {'name': 'Gasabo', 'name_kinyarwanda': 'Gasabo', 'name_french': 'Gasabo', 'latitude': -1.9200, 'longitude': 30.1000, 'area_km2': 430},
                {'name': 'Kicukiro', 'name_kinyarwanda': 'Kicukiro', 'name_french': 'Kicukiro', 'latitude': -1.9800, 'longitude': 30.1000, 'area_km2': 166}
            ],
            'Eastern': [
                {'name': 'Rwamagana', 'name_kinyarwanda': 'Rwamagana', 'name_french': 'Rwamagana', 'latitude': -1.9486, 'longitude': 30.4347, 'area_km2': 1222},
                {'name': 'Kayonza', 'name_kinyarwanda': 'Kayonza', 'name_french': 'Kayonza', 'latitude': -1.8833, 'longitude': 30.6167, 'area_km2': 1233},
                {'name': 'Gatsibo', 'name_kinyarwanda': 'Gatsibo', 'name_french': 'Gatsibo', 'latitude': -1.5833, 'longitude': 30.4167, 'area_km2': 1584}
            ],
            'Western': [
                {'name': 'Karongi', 'name_kinyarwanda': 'Karongi', 'name_french': 'Karongi', 'latitude': -2.0000, 'longitude': 29.3833, 'area_km2': 1041},
                {'name': 'Rusizi', 'name_kinyarwanda': 'Rusizi', 'name_french': 'Rusizi', 'latitude': -2.4667, 'longitude': 28.9167, 'area_km2': 1250},
                {'name': 'Rubavu', 'name_kinyarwanda': 'Rubavu', 'name_french': 'Rubavu', 'latitude': -1.6833, 'longitude': 29.2667, 'area_km2': 388}
            ],
            'Northern': [
                {'name': 'Musanze', 'name_kinyarwanda': 'Musanze', 'name_french': 'Musanze', 'latitude': -1.5000, 'longitude': 29.6333, 'area_km2': 530},
                {'name': 'Burera', 'name_kinyarwanda': 'Burera', 'name_french': 'Burera', 'latitude': -1.4667, 'longitude': 29.8667, 'area_km2': 1043},
                {'name': 'Gakenke', 'name_kinyarwanda': 'Gakenke', 'name_french': 'Gakenke', 'latitude': -1.6833, 'longitude': 29.8167, 'area_km2': 717}
            ],
            'Southern': [
                {'name': 'Muhanga', 'name_kinyarwanda': 'Muhanga', 'name_french': 'Muhanga', 'latitude': -2.0833, 'longitude': 29.7500, 'area_km2': 637},
                {'name': 'Kamonyi', 'name_kinyarwanda': 'Kamonyi', 'name_french': 'Kamonyi', 'latitude': -2.0333, 'longitude': 29.9833, 'area_km2': 656},
                {'name': 'Ruhango', 'name_kinyarwanda': 'Ruhango', 'name_french': 'Ruhango', 'latitude': -2.1667, 'longitude': 29.8333, 'area_km2': 629}
            ]
        }
        
        for province_name, districts in districts_data.items():
            try:
                province = RwandaProvince.objects.get(name=province_name)
                for district_data in districts:
                    district, created = RwandaDistrict.objects.get_or_create(
                        province=province,
                        name=district_data['name'],
                        defaults=district_data
                    )
                    if created:
                        self.stdout.write(f'Created district: {district.name}')
            except RwandaProvince.DoesNotExist:
                self.stdout.write(f'Province {province_name} not found')

    def create_business_categories(self):
        """Create business categories"""
        
        categories_data = [
            {
                'name': 'Restaurant',
                'name_kinyarwanda': 'Restaurant',
                'name_french': 'Restaurant',
                'description': 'Food and dining establishments',
                'description_kinyarwanda': 'Amahuriro n\'ibiryo',
                'description_french': 'Établissements de restauration',
                'icon': 'restaurant',
                'color_code': '#f97316'
            },
            {
                'name': 'Hotel',
                'name_kinyarwanda': 'Hotel',
                'name_french': 'Hôtel',
                'description': 'Accommodation and lodging',
                'description_kinyarwanda': 'Aho gusengera n\'aho kurara',
                'description_french': 'Hébergement et logement',
                'icon': 'hotel',
                'color_code': '#3b82f6'
            },
            {
                'name': 'Healthcare',
                'name_kinyarwanda': 'Ubuzima',
                'name_french': 'Santé',
                'description': 'Medical services and healthcare',
                'description_kinyarwanda': 'Serivisi z\'ubuvuzi n\'ubuzima',
                'description_french': 'Services médicaux et de santé',
                'icon': 'medical',
                'color_code': '#10b981'
            },
            {
                'name': 'Shopping',
                'name_kinyarwanda': 'Guhaha',
                'name_french': 'Shopping',
                'description': 'Retail stores and shopping centers',
                'description_kinyarwanda': 'Amaduka n\'amasoko',
                'description_french': 'Magasins et centres commerciaux',
                'icon': 'shopping',
                'color_code': '#8b5cf6'
            },
            {
                'name': 'Transportation',
                'name_kinyarwanda': 'Ubwikorezi',
                'name_french': 'Transport',
                'description': 'Transport and mobility services',
                'description_kinyarwanda': 'Serivisi z\'ubwikorezi',
                'description_french': 'Services de transport et mobilité',
                'icon': 'car',
                'color_code': '#ef4444'
            },
            {
                'name': 'Financial Services',
                'name_kinyarwanda': 'Serivisi z\'amafaranga',
                'name_french': 'Services financiers',
                'description': 'Banks, insurance, and financial services',
                'description_kinyarwanda': 'Amabanki, ubwishingizi n\'indi serivisi z\'amafaranga',
                'description_french': 'Banques, assurance et services financiers',
                'icon': 'bank',
                'color_code': '#059669'
            },
            {
                'name': 'Education',
                'name_kinyarwanda': 'Uburezi',
                'name_french': 'Éducation',
                'description': 'Schools and educational institutions',
                'description_kinyarwanda': 'Amashuri n\'ibigo by\'uburezi',
                'description_french': 'Écoles et institutions éducatives',
                'icon': 'school',
                'color_code': '#dc2626'
            },
            {
                'name': 'Entertainment',
                'name_kinyarwanda': 'Kwishimira',
                'name_french': 'Divertissement',
                'description': 'Entertainment and recreation',
                'description_kinyarwanda': 'Kwishimira n\'imyidagaduro',
                'description_french': 'Divertissement et loisirs',
                'icon': 'entertainment',
                'color_code': '#7c3aed'
            },
            {
                'name': 'Automotive',
                'name_kinyarwanda': 'Ibyamamodoka',
                'name_french': 'Automobile',
                'description': 'Car services, repair, and sales',
                'description_kinyarwanda': 'Serivisi z\'imodoka, gusana n\'kugurisha',
                'description_french': 'Services automobile, réparation et vente',
                'icon': 'car-repair',
                'color_code': '#ea580c'
            },
            {
                'name': 'Beauty & Wellness',
                'name_kinyarwanda': 'Ubwiza n\'ubuzima',
                'name_french': 'Beauté et bien-être',
                'description': 'Beauty salons, spas, and wellness centers',
                'description_kinyarwanda': 'Salon z\'ubwiza, spa n\'ibigo by\'ubuzima',
                'description_french': 'Salons de beauté, spas et centres de bien-être',
                'icon': 'beauty',
                'color_code': '#db2777'
            }
        ]
        
        for category_data in categories_data:
            category, created = BusinessCategory.objects.get_or_create(
                name=category_data['name'],
                defaults=category_data
            )
            if created:
                self.stdout.write(f'Created category: {category.name}')


