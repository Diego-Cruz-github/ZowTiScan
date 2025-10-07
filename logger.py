#!/usr/bin/env python3
"""
ZowTiCheck Structured Logging System
JSON-based logging with error tracking and context
"""

import logging
import json
import os
import sys
import traceback
import time
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path

class StructuredFormatter(logging.Formatter):
    """JSON formatter for structured logging"""
    
    def format(self, record: logging.LogRecord) -> str:
        """Format log record as JSON"""
        
        # Base log structure
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_data['exception'] = {
                'type': record.exc_info[0].__name__,
                'message': str(record.exc_info[1]),
                'traceback': traceback.format_exception(*record.exc_info)
            }
        
        # Add extra context from record
        extra_fields = ['request_id', 'user_ip', 'target_url', 'scan_module', 'duration', 'status_code']
        for field in extra_fields:
            if hasattr(record, field):
                log_data[field] = getattr(record, field)
        
        return json.dumps(log_data)

class ZowTiLogger:
    """ZowTiCheck logging system with context management"""
    
    def __init__(self, name: str = 'zowticheck'):
        self.logger = logging.getLogger(name)
        self.setup_logging()
    
    def setup_logging(self):
        """Setup logging configuration"""
        from config import config
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # Set level
        level = getattr(logging, config.LOG_LEVEL, logging.INFO)
        self.logger.setLevel(level)
        
        # Console handler
        console_handler = logging.StreamHandler(sys.stdout)
        
        # File handler
        log_file = Path(config.LOG_FILE)
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file)
        
        # Format handlers
        if config.LOG_FORMAT == 'json':
            formatter = StructuredFormatter()
        else:
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
        
        console_handler.setFormatter(formatter)
        file_handler.setFormatter(formatter)
        
        self.logger.addHandler(console_handler)
        self.logger.addHandler(file_handler)
    
    def with_context(self, **context) -> 'ContextLogger':
        """Create logger with additional context"""
        return ContextLogger(self.logger, context)
    
    def info(self, message: str, **extra):
        """Log info message"""
        self.logger.info(message, extra=extra)
    
    def warning(self, message: str, **extra):
        """Log warning message"""
        self.logger.warning(message, extra=extra)
    
    def error(self, message: str, **extra):
        """Log error message"""
        self.logger.error(message, extra=extra)
    
    def exception(self, message: str, **extra):
        """Log exception with traceback"""
        self.logger.exception(message, extra=extra)
    
    def debug(self, message: str, **extra):
        """Log debug message"""
        self.logger.debug(message, extra=extra)

class ContextLogger:
    """Logger with pre-set context"""
    
    def __init__(self, logger: logging.Logger, context: Dict[str, Any]):
        self.logger = logger
        self.context = context
    
    def _log(self, level: str, message: str, **extra):
        """Internal log method with context"""
        combined_extra = {**self.context, **extra}
        getattr(self.logger, level)(message, extra=combined_extra)
    
    def info(self, message: str, **extra):
        self._log('info', message, **extra)
    
    def warning(self, message: str, **extra):
        self._log('warning', message, **extra)
    
    def error(self, message: str, **extra):
        self._log('error', message, **extra)
    
    def exception(self, message: str, **extra):
        self._log('exception', message, **extra)
    
    def debug(self, message: str, **extra):
        self._log('debug', message, **extra)

class ErrorTracker:
    """Track and categorize errors for monitoring"""
    
    def __init__(self):
        self.errors = {}  # {error_type: count}
        self.recent_errors = []  # Recent error details
        self.max_recent = 100
    
    def track_error(self, error_type: str, message: str, context: Optional[Dict] = None):
        """Track an error occurrence"""
        # Count by type
        self.errors[error_type] = self.errors.get(error_type, 0) + 1
        
        # Store recent error
        error_info = {
            'timestamp': datetime.utcnow().isoformat(),
            'type': error_type,
            'message': message,
            'context': context or {}
        }
        
        self.recent_errors.append(error_info)
        
        # Keep only recent errors
        if len(self.recent_errors) > self.max_recent:
            self.recent_errors = self.recent_errors[-self.max_recent:]
    
    def get_error_stats(self) -> Dict[str, Any]:
        """Get error statistics"""
        return {
            'total_errors': sum(self.errors.values()),
            'error_types': self.errors,
            'recent_count': len(self.recent_errors),
            'last_error': self.recent_errors[-1] if self.recent_errors else None
        }

def handle_exception(func):
    """Decorator for graceful exception handling"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            logger.exception(f"Exception in {func.__name__}: {str(e)}")
            error_tracker.track_error(
                error_type=type(e).__name__,
                message=str(e),
                context={'function': func.__name__, 'args_count': len(args)}
            )
            raise
    return wrapper

def log_performance(func):
    """Decorator to log function performance"""
    def wrapper(*args, **kwargs):
        start_time = time.time()
        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.debug(f"{func.__name__} completed", duration=duration)
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(f"{func.__name__} failed", duration=duration, error=str(e))
            raise
    return wrapper

# Global instances
logger = ZowTiLogger()
error_tracker = ErrorTracker()

# Health check utilities
def get_health_status() -> Dict[str, Any]:
    """Get application health status"""
    try:
        from config import config
        
        # Check log file writability
        log_file = Path(config.LOG_FILE)
        log_writable = log_file.parent.exists() and os.access(log_file.parent, os.W_OK)
        
        # Get error stats
        error_stats = error_tracker.get_error_stats()
        
        # Determine health status
        is_healthy = (
            log_writable and
            error_stats['total_errors'] < 100  # Arbitrary threshold
        )
        
        return {
            'status': 'healthy' if is_healthy else 'degraded',
            'timestamp': datetime.utcnow().isoformat(),
            'checks': {
                'logging': log_writable,
                'error_rate': error_stats['total_errors'] < 100
            },
            'errors': error_stats,
            'config_valid': config.validate_config()['valid']
        }
    except Exception as e:
        return {
            'status': 'unhealthy',
            'timestamp': datetime.utcnow().isoformat(),
            'error': str(e)
        }