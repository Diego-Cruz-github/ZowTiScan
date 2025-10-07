#!/usr/bin/env python3
"""
ZowTiCheck Response Helpers
Utilities for creating consistent API responses using Pydantic models
"""

from typing import Any, Dict, List, Optional
from flask import jsonify, g
from pydantic import ValidationError
from models import (
    ErrorResponseModel, 
    ValidationErrorResponseModel,
    ScanResponseModel,
    PerformanceResponseModel,
    AuditResponseModel,
    SecurityReportModel,
    PerformanceModel,
    FullAuditReportModel,
    DisplayInfoModel,
    URLInfoModel,
    create_error_response,
    create_validation_error_response
)

class ResponseBuilder:
    """Builder for consistent API responses"""
    
    @staticmethod
    def success_response(data: Any, status_code: int = 200):
        """Create successful JSON response"""
        if hasattr(data, 'dict'):
            # Pydantic model
            response_data = data.dict()
        else:
            response_data = data
        
        return jsonify(response_data), status_code
    
    @staticmethod
    def error_response(
        error_type: str, 
        message: str, 
        status_code: int = 400,
        details: Optional[List[Dict[str, Any]]] = None
    ):
        """Create error JSON response"""
        request_id = getattr(g, 'request_id', None)
        
        error_model = create_error_response(
            error_type=error_type,
            message=message,
            details=details,
            request_id=request_id
        )
        
        return jsonify(error_model.dict()), status_code
    
    @staticmethod
    def validation_error_response(validation_error: ValidationError, status_code: int = 422):
        """Create validation error response from Pydantic ValidationError"""
        request_id = getattr(g, 'request_id', None)
        
        # Convert Pydantic errors to our format
        formatted_errors = []
        for error in validation_error.errors():
            formatted_errors.append({
                'field': '.'.join(str(x) for x in error['loc']),
                'message': error['msg'],
                'type': error['type'],
                'input': error.get('input')
            })
        
        error_model = create_validation_error_response(
            validation_errors=formatted_errors,
            request_id=request_id
        )
        
        return jsonify(error_model.dict()), status_code
    
    @staticmethod
    def scan_response(
        security_report: SecurityReportModel,
        display_info: DisplayInfoModel,
        parsed_url: URLInfoModel
    ):
        """Create security scan response"""
        request_id = getattr(g, 'request_id', None)
        
        response = ScanResponseModel(
            data=security_report,
            display=display_info,
            parsed_url=parsed_url,
            request_id=request_id
        )
        
        return ResponseBuilder.success_response(response)
    
    @staticmethod
    def performance_response(performance_data: PerformanceModel):
        """Create performance analysis response"""
        request_id = getattr(g, 'request_id', None)
        
        response = PerformanceResponseModel(
            performance=performance_data,
            request_id=request_id
        )
        
        return ResponseBuilder.success_response(response)
    
    @staticmethod
    def audit_response(audit_data: FullAuditReportModel):
        """Create full audit response"""
        request_id = getattr(g, 'request_id', None)
        
        response = AuditResponseModel(
            data=audit_data,
            request_id=request_id
        )
        
        return ResponseBuilder.success_response(response)

def handle_pydantic_error(func):
    """Decorator to handle Pydantic validation errors"""
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValidationError as e:
            return ResponseBuilder.validation_error_response(e)
        except Exception as e:
            # Log the error
            if hasattr(g, 'logger'):
                g.logger.exception(f"Unexpected error in {func.__name__}: {str(e)}")
            
            return ResponseBuilder.error_response(
                error_type="internal_error",
                message="An unexpected error occurred",
                status_code=500
            )
    return wrapper

def validate_request_json(model_class):
    """Decorator to validate request JSON against Pydantic model"""
    def decorator(func):
        def wrapper(*args, **kwargs):
            from flask import request
            
            # Check content type
            if not request.is_json:
                return ResponseBuilder.error_response(
                    error_type="invalid_content_type",
                    message="Content-Type must be application/json",
                    status_code=400
                )
            
            # Get JSON data
            try:
                json_data = request.get_json()
                if json_data is None:
                    return ResponseBuilder.error_response(
                        error_type="invalid_json",
                        message="Request body must contain valid JSON",
                        status_code=400
                    )
            except Exception:
                return ResponseBuilder.error_response(
                    error_type="invalid_json",
                    message="Request body contains invalid JSON",
                    status_code=400
                )
            
            # Validate against model
            try:
                validated_data = model_class(**json_data)
                # Add validated data to kwargs
                kwargs['validated_data'] = validated_data
                return func(*args, **kwargs)
            except ValidationError as e:
                return ResponseBuilder.validation_error_response(e)
        
        wrapper.__name__ = func.__name__
        return wrapper
    return decorator

# Risk emoji mapping
RISK_EMOJIS = {
    'CRITICAL': '🚨',
    'HIGH': '⚠️', 
    'MEDIUM': '⚡',
    'LOW': '✅',
    'CONNECTION_ERROR': '❌'
}

def get_risk_emoji(risk_level: str) -> str:
    """Get emoji for risk level"""
    return RISK_EMOJIS.get(risk_level, '❓')