# Import base settings
from .settings.base import *

# Override for development
DEBUG = True
ALLOWED_HOSTS = ['localhost', '127.0.0.1', '0.0.0.0']
