# BusiMap Backend

A comprehensive Django REST API backend for the BusiMap business discovery platform, designed specifically for Rwanda's business ecosystem.

## 🌟 Features

### Core Functionality
- **Business Discovery**: Advanced search and filtering for local businesses
- **User Management**: Custom user authentication with phone and email verification
- **AI-Powered Search**: Intelligent business recommendations and natural language processing
- **Multi-language Support**: English, French, and Kinyarwanda support
- **Geolocation Services**: Location-based business discovery and mapping
- **Review System**: Comprehensive business rating and review management

### Advanced Features
- **Transportation Integration**: Ride-hailing and logistics coordination
- **Mobile Money Payments**: MTN MoMo and Airtel Money integration
- **Real-time Analytics**: Business insights and market intelligence
- **API Documentation**: Comprehensive OpenAPI/Swagger documentation
- **Elasticsearch Integration**: Advanced search capabilities
- **Celery Task Queue**: Asynchronous task processing
- **WebSocket Support**: Real-time notifications and updates

## 🏗️ Architecture

### Technology Stack
- **Framework**: Django 5.2.6 with Django REST Framework 3.16.1
- **Database**: PostgreSQL with PostGIS for geospatial data
- **Cache & Message Broker**: Redis
- **Search Engine**: Elasticsearch
- **Task Queue**: Celery with Redis broker
- **Authentication**: JWT-based with phone number support
- **File Storage**: AWS S3 with CloudFront CDN
- **Containerization**: Docker with Docker Compose

### Key Components
- **Authentication App**: User management and JWT authentication
- **Businesses App**: Business listings, categories, and reviews
- **AI Engine App**: Intelligent search and recommendations
- **Search App**: Advanced search functionality with Elasticsearch
- **Locations App**: Rwanda's administrative divisions and geolocation
- **Analytics App**: Business intelligence and market insights
- **Payments App**: Mobile money and payment processing
- **Transportation App**: Ride-hailing and logistics services

## 🚀 Quick Start

### Prerequisites
- Docker and Docker Compose
- Git
- Python 3.11+ (for local development)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/your-org/bizmap-backend.git
   cd bizmap-backend
   ```

2. **Set up environment variables**
   ```bash
   cp env.example .env
   # Edit .env with your configuration
   ```

3. **Deploy with Docker**
   ```bash
   # Development deployment
   ./scripts/deploy.sh development
   
   # Production deployment
   ./scripts/deploy.sh production
   ```

4. **Access the application**
   - API: http://localhost:8000
   - API Documentation: http://localhost:8000/api/docs/
   - Admin Panel: http://localhost:8000/admin/

### Development Setup

1. **Create virtual environment**
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up database**
   ```bash
   python manage.py migrate
   python manage.py setup_payment_methods
   python manage.py createsuperuser
   ```

4. **Run development server**
   ```bash
   python manage.py runserver
   ```

## 📚 API Documentation

### Authentication
The API uses JWT (JSON Web Tokens) for authentication. Users can authenticate using either email or phone number.

**Authentication Endpoints:**
- `POST /api/auth/register/` - User registration
- `POST /api/auth/login/` - User login
- `POST /api/auth/refresh/` - Token refresh
- `POST /api/auth/verify-phone/` - Phone verification
- `POST /api/auth/reset-password/` - Password reset

### Core Endpoints

**Business Discovery:**
- `GET /api/businesses/` - List businesses with filtering
- `GET /api/businesses/{id}/` - Business details
- `POST /api/businesses/` - Create business (authenticated)
- `GET /api/businesses/nearby/` - Find nearby businesses
- `GET /api/businesses/categories/` - Business categories

**Search:**
- `POST /api/search/intelligent/` - AI-powered search
- `GET /api/search/suggestions/` - Search suggestions
- `GET /api/search/trending/` - Trending searches

**AI Features:**
- `POST /api/ai/conversation/` - AI chat conversation
- `POST /api/ai/recommendations/` - Get recommendations
- `POST /api/ai/analyze/` - Query analysis

**Analytics:**
- `GET /api/analytics/business-performance/` - Business metrics
- `GET /api/analytics/market-trends/` - Market insights
- `GET /api/analytics/customer-insights/{business_id}/` - Customer analysis

**Transportation:**
- `GET /api/transport/vehicle-types/` - Available vehicle types
- `POST /api/transport/ride-requests/create/` - Request a ride
- `GET /api/transport/rides/` - User's rides

**Payments:**
- `GET /api/payments/methods/` - Payment methods
- `POST /api/payments/mobile-money/initiate/` - Start mobile money payment
- `GET /api/payments/transactions/` - Payment history

### Response Format
All API responses follow a consistent format:

```json
{
  "success": true,
  "data": {
    // Response data
  },
  "message": "Success message",
  "meta": {
    "pagination": {
      "page": 1,
      "pages": 10,
      "per_page": 20,
      "total": 200
    }
  }
}
```

## 🔧 Configuration

### Environment Variables

Key environment variables that need to be configured:

```bash
# Django Settings
SECRET_KEY=your-secret-key
DEBUG=False
ALLOWED_HOSTS=localhost,yourdomain.com

# Database
DATABASE_URL=postgres://user:password@localhost:5432/bizmap_db

# Redis
REDIS_URL=redis://localhost:6379/0

# Elasticsearch
ELASTICSEARCH_URL=http://localhost:9200

# Mobile Money
MTN_MOMO_API_KEY=your-mtn-api-key
AIRTEL_MONEY_CLIENT_ID=your-airtel-client-id

# AI Services
OPENAI_API_KEY=your-openai-key

# AWS (for file storage)
AWS_ACCESS_KEY_ID=your-aws-key
AWS_SECRET_ACCESS_KEY=your-aws-secret
AWS_STORAGE_BUCKET_NAME=your-s3-bucket
```

### Mobile Money Configuration

The platform supports Rwanda's major mobile money providers:

**MTN Mobile Money:**
- Sandbox: `https://sandbox.momodeveloper.mtn.com`
- Production: `https://momodeveloper.mtn.com`

**Airtel Money:**
- Sandbox: `https://openapi.airtel.africa`
- Production: `https://openapi.airtel.africa`

## 🗄️ Database Schema

### Key Models

**User Model:**
- Custom user model supporting email and phone authentication
- Profile information with preferences
- Location data for personalized services

**Business Model:**
- Comprehensive business information
- Geolocation data with PostGIS
- Category classification
- Media attachments and verification status

**Review Model:**
- User reviews and ratings
- Moderation capabilities
- Response system for business owners

**Payment Transaction:**
- Mobile money transaction tracking
- Multi-provider support
- Audit trail and reporting

## 🔍 Search & AI

### Elasticsearch Integration
- Business indexing for fast search
- Multi-language search support
- Geospatial queries
- Faceted search and filtering

### AI Features
- Natural language query processing
- Business recommendations based on user behavior
- Intent analysis and entity extraction
- Multi-language support (English, French, Kinyarwanda)

## 📊 Analytics & Reporting

### Business Analytics
- Performance metrics and KPIs
- Customer insights and demographics
- Competitive analysis
- Revenue optimization suggestions

### System Analytics
- User behavior tracking
- Search analytics
- Market trends and insights
- Payment transaction analysis

## 🚚 Transportation Services

### Ride-Hailing Integration
- Vehicle type management (Moto, Car, Bus)
- Driver profile and verification
- Ride request and matching system
- Real-time tracking and notifications

### Logistics Support
- Delivery service integration
- Route optimization
- Fare calculation algorithms
- Driver analytics and performance

## 💳 Payment Integration

### Mobile Money Support
- MTN Mobile Money integration
- Airtel Money support
- Transaction tracking and reconciliation
- Webhook handling for payment confirmations

### Payment Analytics
- Transaction reporting
- Revenue analytics
- Failure analysis and optimization
- Fraud detection capabilities

## 🔒 Security

### Authentication & Authorization
- JWT-based authentication
- Role-based access control
- API rate limiting
- CORS configuration

### Data Protection
- Input validation and sanitization
- SQL injection prevention
- XSS protection
- Secure file upload handling

## 🐳 Deployment

### Docker Deployment
The application is fully containerized with Docker:

```bash
# Development
docker-compose up -d

# Production
docker-compose -f docker-compose.prod.yml up -d
```

### Services
- **Web**: Django application server
- **PostgreSQL**: Primary database
- **Redis**: Cache and message broker
- **Elasticsearch**: Search engine
- **Celery Worker**: Background task processing
- **Celery Beat**: Scheduled task execution
- **Nginx**: Reverse proxy and static file serving

### Scaling
- Horizontal scaling support
- Load balancer configuration
- Database read replicas
- CDN integration for static assets

## 🛠️ Management Commands

### Database Management
```bash
# Setup initial data
python manage.py setup_payment_methods

# Clean up old data
python manage.py cleanup_old_transactions
python manage.py cleanup_old_rides

# Generate analytics
python manage.py generate_analytics --period week
```

### Maintenance Scripts
```bash
# Deploy application
./scripts/deploy.sh [environment]

# Backup database and media
./scripts/backup.sh

# Restore from backup
./scripts/restore.sh [backup_date]

# Run maintenance tasks
./scripts/maintenance.sh
```

## 📈 Monitoring & Logging

### Health Checks
- Application health endpoint: `/api/health/`
- Database connection monitoring
- External service status checks

### Logging
- Structured logging with JSON format
- Centralized log aggregation
- Error tracking with Sentry integration
- Performance monitoring

## 🧪 Testing

### Test Coverage
```bash
# Run tests
python manage.py test

# Run with coverage
coverage run manage.py test
coverage report
```

### API Testing
- Comprehensive test suite for all endpoints
- Integration tests for external services
- Performance testing for search and analytics

## 🤝 Contributing

### Development Workflow
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

### Code Standards
- Follow PEP 8 style guidelines
- Use type hints where appropriate
- Write comprehensive docstrings
- Maintain test coverage above 80%

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- API Documentation: http://localhost:8000/api/docs/
- ReDoc Documentation: http://localhost:8000/api/redoc/

### Community
- GitHub Issues: Report bugs and request features
- Discussions: Community support and questions

### Professional Support
For enterprise support and custom development, contact the development team.

---

**Built with ❤️ for Rwanda's business ecosystem**




