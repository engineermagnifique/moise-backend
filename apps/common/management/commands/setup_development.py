# management/commands/setup_development.py
from django.core.management.base import BaseCommand
from django.contrib.auth import get_user_model
from apps.businesses.models import BusinessCategory
from apps.locations.models import RwandaProvince, RwandaDistrict
import logging

User = get_user_model()
logger = logging.getLogger(__name__)


class Command(BaseCommand):
    help = "Setup development environment with test data"

    def handle(self, *args, **options):
        self.stdout.write("Setting up development environment...")

        # Create superuser if it doesn't exist
        self.create_superuser()

        # Create test users
        self.create_test_users()

        # Create sample data
        self.create_sample_data()

        self.stdout.write(self.style.SUCCESS("Development environment setup complete!"))

    def create_superuser(self):
        """Create superuser if it doesn't exist"""
        try:
            if not User.objects.filter(email="admin@busimap.rw").exists():
                User.objects.create_superuser(
                    email="admin@busimap.rw",
                    password="admin123",
                    first_name="Admin",
                    last_name="User",
                    phone_number="+250788000000",
                )
                self.stdout.write("Created superuser: admin@busimap.rw / admin123")
            else:
                self.stdout.write("Superuser already exists")
        except Exception as e:
            self.stdout.write(f"Error creating superuser: {e}")

    def create_test_users(self):
        """Create test users for different scenarios"""
        test_users = [
            {
                "email": "customer@test.rw",
                "password": "test123",
                "first_name": "Jean",
                "last_name": "Uwimana",
                "phone_number": "+250788111111",
                "user_type": "customer",
                "preferred_language": "rw",
            },
            {
                "email": "business@test.rw",
                "password": "test123",
                "first_name": "Marie",
                "last_name": "Mukamana",
                "phone_number": "+250788222222",
                "user_type": "business_owner",
                "preferred_language": "en",
            },
        ]

        for user_data in test_users:
            try:
                if not User.objects.filter(email=user_data["email"]).exists():
                    User.objects.create_user(**user_data)
                    self.stdout.write(
                        f"Created test user: {user_data['email']} / test123"
                    )
            except Exception as e:
                self.stdout.write(f"Error creating user {user_data['email']}: {e}")

    def create_sample_data(self):
        """Create sample businesses and categories"""
        try:
            # Ensure we have at least one province and category
            kigali, created = RwandaProvince.objects.get_or_create(
                name="Kigali",
                defaults={
                    "name_kinyarwanda": "Kigali",
                    "name_french": "Kigali",
                    "latitude": -1.9441,
                    "longitude": 30.0619,
                    "area_km2": 730,
                    "population": 1132686,
                },
            )

            restaurant_category, created = BusinessCategory.objects.get_or_create(
                name="Restaurant",
                defaults={
                    "name_kinyarwanda": "Restaurant",
                    "name_french": "Restaurant",
                    "description": "Food and dining establishments",
                    "icon": "restaurant",
                    "color_code": "#f97316",
                },
            )

            self.stdout.write("Sample data created successfully")

        except Exception as e:
            self.stdout.write(f"Error creating sample data: {e}")
