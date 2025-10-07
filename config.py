#!/usr/bin/env python3
"""
ZowTiCheck Configuration Management
Handles environment variables and application settings
"""

import os
import logging
from typing import Optional
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

class Config:
    """Application configuration with environment variable support"""
    
    # Application Settings
    APP_ENV = os.getenv('APP_ENV', 'development')
    DEBUG = os.getenv('DEBUG', 'false').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', '5000'))
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-key-change-in-production')
    
    # Security Settings
    RATE_LIMIT_PER_MINUTE = int(os.getenv('RATE_LIMIT_PER_MINUTE', '60'))
    RATE_LIMIT_PER_HOUR = int(os.getenv('RATE_LIMIT_PER_HOUR', '1000'))
    VALIDATE_SSL = os.getenv('VALIDATE_SSL', 'true').lower() == 'true'
    SECURITY_HEADERS_STRICT = os.getenv('SECURITY_HEADERS_STRICT', 'false').lower() == 'true'
    
    # Timeouts (seconds)
    REQUEST_TIMEOUT = int(os.getenv('REQUEST_TIMEOUT', '10'))
    PING_TIMEOUT = int(os.getenv('PING_TIMEOUT', '5'))
    PAGESPEED_TIMEOUT = int(os.getenv('PAGESPEED_TIMEOUT', '30'))
    
    # PageSpeed API
    PAGESPEED_API_KEY = os.getenv('PAGESPEED_API_KEY')
    PAGESPEED_STRATEGY = os.getenv('PAGESPEED_STRATEGY', 'desktop')
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO').upper()
    LOG_FORMAT = os.getenv('LOG_FORMAT', 'json')
    LOG_FILE = os.getenv('LOG_FILE', 'logs/zowticheck.log')
    
    # Database (future use)
    DATABASE_URL = os.getenv('DATABASE_URL', 'sqlite:///zowticheck.db')
    
    @classmethod
    def is_production(cls) -> bool:
        """Check if running in production environment"""
        return cls.APP_ENV == 'production'
    
    @classmethod
    def is_development(cls) -> bool:
        """Check if running in development environment"""
        return cls.APP_ENV == 'development'
    
    @classmethod
    def validate_config(cls) -> dict:
        """Validate configuration and return status"""
        issues = []
        warnings = []
        
        # Critical validations
        if cls.is_production() and cls.SECRET_KEY == 'dev-key-change-in-production':
            issues.append("SECRET_KEY must be changed in production")
        
        if cls.is_production() and cls.DEBUG:
            issues.append("DEBUG should be false in production")
        
        if cls.PAGESPEED_API_KEY is None:
            warnings.append("PAGESPEED_API_KEY not set - rate limiting may occur")
        
        if cls.RATE_LIMIT_PER_MINUTE > 100:
            warnings.append("High rate limit may cause resource issues")
        
        return {
            'valid': len(issues) == 0,
            'issues': issues,
            'warnings': warnings
        }

# Global config instance
config = Config()