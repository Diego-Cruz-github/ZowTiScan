#!/usr/bin/env python3
"""
ZowTiCheck Data Models
Pydantic models for type safety and validation
"""

from datetime import datetime
from enum import Enum
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, validator, HttpUrl
import uuid

# ========================
# ENUMS FOR TYPE SAFETY
# ========================

class SeverityLevel(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

class RiskLevel(str, Enum):
    """Overall risk assessment levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    CONNECTION_ERROR = "CONNECTION_ERROR"

class ScanModule(str, Enum):
    """Available security scan modules"""
    XSS = "xss"
    CSRF = "csrf"
    INJECTION = "injection"
    NOSQL_INJECTION = "nosql_injection"
    BROKEN_PAGES = "broken_pages"
    HEADERS = "headers"
    INFO_DISCLOSURE = "info_disclosure"
    AUTHENTICATION = "authentication"
    ACCESS_CONTROL = "access_control"
    FILE_UPLOAD = "file_upload"
    TECH_STACK = "tech_stack"
    DIRECTORY_TRAVERSAL = "directory_traversal"
    BEST_PRACTICES = "best_practices"
    SEO = "seo"
    ALL = "all"

class PerformanceLevel(str, Enum):
    """Performance assessment levels"""
    GOOD = "GOOD"
    NEEDS_IMPROVEMENT = "NEEDS_IMPROVEMENT"
    POOR = "POOR"

# ========================
# CORE DATA MODELS
# ========================

class VulnerabilityModel(BaseModel):
    """Security vulnerability data model"""
    type: str = Field(..., description="Type of vulnerability")
    severity: SeverityLevel = Field(..., description="Severity level")
    description: str = Field(..., description="Vulnerability description")
    location: str = Field(..., description="Where the vulnerability was found")
    evidence: Optional[str] = Field(None, description="Evidence or proof")
    
    class Config:
        use_enum_values = True

class URLInfoModel(BaseModel):
    """Parsed URL information"""
    scheme: str = Field(..., description="URL scheme (http/https)")
    hostname: str = Field(..., description="Hostname")
    port: int = Field(..., description="Port number")
    path: str = Field(..., description="URL path")
    domain: str = Field(..., description="Domain name")
    subdomain: Optional[str] = Field(None, description="Subdomain")
    suffix: str = Field(..., description="TLD suffix")
    full_domain: str = Field(..., description="Full domain with TLD")

class CoreWebVitalsModel(BaseModel):
    """Core Web Vitals metrics"""
    lcp: Optional[str] = Field(None, description="Largest Contentful Paint")
    fid: Optional[str] = Field(None, description="First Input Delay")
    cls: Optional[str] = Field(None, description="Cumulative Layout Shift")

class PerformanceMetricsModel(BaseModel):
    """Performance metrics from PageSpeed"""
    first_contentful_paint: Optional[str] = Field(None, alias="first-contentful-paint")
    speed_index: Optional[str] = Field(None, alias="speed-index")
    total_blocking_time: Optional[str] = Field(None, alias="total-blocking-time")
    interactive: Optional[str] = Field(None, description="Time to Interactive")
    
    class Config:
        validate_by_name = True

class PerformanceModel(BaseModel):
    """Performance analysis results"""
    score: int = Field(..., ge=0, le=100, description="Performance score 0-100")
    core_vitals: CoreWebVitalsModel = Field(..., description="Core Web Vitals")
    metrics: PerformanceMetricsModel = Field(..., description="Performance metrics")
    risk_level: PerformanceLevel = Field(..., description="Performance risk level")
    recommendations_count: int = Field(..., ge=0, description="Number of recommendations")
    
    class Config:
        use_enum_values = True

class SEOMetricsModel(BaseModel):
    """SEO analysis results (for future implementation)"""
    score: int = Field(..., ge=0, le=100, description="SEO score 0-100")
    title_length: Optional[int] = Field(None, description="Title tag length")
    meta_description_length: Optional[int] = Field(None, description="Meta description length")
    h1_count: int = Field(0, description="Number of H1 tags")
    h2_count: int = Field(0, description="Number of H2 tags")
    alt_text_missing: int = Field(0, description="Images missing alt text")
    internal_links: int = Field(0, description="Number of internal links")
    external_links: int = Field(0, description="Number of external links")
    
    @validator('score')
    def validate_score_range(cls, v):
        if not 0 <= v <= 100:
            raise ValueError('SEO score must be between 0 and 100')
        return v

# ========================
# REQUEST/RESPONSE MODELS
# ========================

class ScanRequestModel(BaseModel):
    """Request model for security scan"""
    url: str = Field(..., description="URL to scan")
    modules: Optional[List[ScanModule]] = Field(None, description="Specific modules to run")
    
    @validator('url')
    def validate_and_fix_url(cls, v):
        """Validate URL and auto-prepend scheme if missing"""
        if not v or not v.strip():
            raise ValueError('URL cannot be empty')
        
        url = v.strip()
        
        # If URL doesn't start with scheme, prepend https://
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        # Validate the final URL format
        try:
            from pydantic import HttpUrl
            validated_url = HttpUrl(url)
            return str(validated_url)
        except Exception:
            raise ValueError(f'Invalid URL format: {v}')
    
    @validator('modules')
    def validate_modules_not_empty(cls, v):
        if v is not None and len(v) == 0:
            raise ValueError('Modules list cannot be empty')
        return v
    
    class Config:
        use_enum_values = True

class PerformanceRequestModel(BaseModel):
    """Request model for performance analysis"""
    url: str = Field(..., description="URL to analyze")
    
    @validator('url')
    def validate_and_fix_url(cls, v):
        """Validate URL and auto-prepend scheme if missing"""
        if not v or not v.strip():
            raise ValueError('URL cannot be empty')
        
        url = v.strip()
        
        # If URL doesn't start with scheme, prepend https://
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        # Validate the final URL format
        try:
            from pydantic import HttpUrl
            validated_url = HttpUrl(url)
            return str(validated_url)
        except Exception:
            raise ValueError(f'Invalid URL format: {v}')

class AuditRequestModel(BaseModel):
    """Request model for full audit"""
    url: str = Field(..., description="URL to audit")
    modules: Optional[List[ScanModule]] = Field(None, description="Security modules to run")
    
    @validator('url')
    def validate_and_fix_url(cls, v):
        """Validate URL and auto-prepend scheme if missing"""
        if not v or not v.strip():
            raise ValueError('URL cannot be empty')
        
        url = v.strip()
        
        # If URL doesn't start with scheme, prepend https://
        if not url.startswith(('http://', 'https://')):
            url = f'https://{url}'
        
        # Validate the final URL format
        try:
            from pydantic import HttpUrl
            validated_url = HttpUrl(url)
            return str(validated_url)
        except Exception:
            raise ValueError(f'Invalid URL format: {v}')
    
    class Config:
        use_enum_values = True

class DisplayInfoModel(BaseModel):
    """Display formatting information"""
    risk_emoji: str = Field(..., description="Emoji for risk level")
    modules_analyzed: int = Field(..., ge=0, description="Number of modules analyzed")
    formatted_score: str = Field(..., description="Formatted score string")
    scan_time_formatted: str = Field(..., description="Formatted scan time")

class SecurityReportModel(BaseModel):
    """Security scan report"""
    target_url: str = Field(..., description="Scanned URL")
    security_score: int = Field(..., ge=0, le=100, description="Security score 0-100")
    risk_level: RiskLevel = Field(..., description="Overall risk level")
    total_vulnerabilities: int = Field(..., ge=0, description="Total vulnerabilities found")
    vulnerabilities_by_severity: Dict[str, int] = Field(..., description="Vulnerabilities grouped by severity")
    vulnerabilities: List[VulnerabilityModel] = Field(..., description="List of vulnerabilities")
    scan_duration: float = Field(..., ge=0, description="Scan duration in seconds")
    modules_scanned: List[str] = Field(..., description="Modules that were scanned")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Scan timestamp")
    
    class Config:
        use_enum_values = True

class FullAuditReportModel(BaseModel):
    """Combined security + performance audit report"""
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()), description="Unique request ID")
    target: str = Field(..., description="Target URL")
    security: SecurityReportModel = Field(..., description="Security scan results")
    performance: PerformanceModel = Field(..., description="Performance analysis results")
    seo: Optional[SEOMetricsModel] = Field(None, description="SEO analysis results")
    audit_duration: float = Field(..., ge=0, description="Total audit duration")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Audit timestamp")
    success: bool = Field(True, description="Whether audit completed successfully")

# ========================
# ERROR MODELS
# ========================

class ErrorDetailModel(BaseModel):
    """Detailed error information"""
    type: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    field: Optional[str] = Field(None, description="Field that caused error")
    code: Optional[str] = Field(None, description="Error code")

class ErrorResponseModel(BaseModel):
    """Standardized error response"""
    success: bool = Field(False, description="Always false for errors")
    error: str = Field(..., description="Error category")
    message: str = Field(..., description="Human-readable error message")
    details: Optional[List[ErrorDetailModel]] = Field(None, description="Detailed error information")
    request_id: Optional[str] = Field(None, description="Request ID for tracking")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")

class ValidationErrorResponseModel(BaseModel):
    """Validation error response"""
    success: bool = Field(False)
    error: str = Field("validation_error")
    message: str = Field("Input validation failed")
    validation_errors: List[Dict[str, Any]] = Field(..., description="Pydantic validation errors")
    request_id: Optional[str] = Field(None)
    timestamp: datetime = Field(default_factory=datetime.utcnow)

# ========================
# SUCCESS RESPONSE MODELS
# ========================

class SuccessResponseModel(BaseModel):
    """Base success response"""
    success: bool = Field(True, description="Always true for success")
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=datetime.utcnow)

class ScanResponseModel(SuccessResponseModel):
    """Security scan response"""
    data: SecurityReportModel = Field(..., description="Security scan results")
    display: DisplayInfoModel = Field(..., description="Display formatting info")
    parsed_url: URLInfoModel = Field(..., description="Parsed URL information")

class PerformanceResponseModel(SuccessResponseModel):
    """Performance analysis response"""
    performance: PerformanceModel = Field(..., description="Performance analysis results")

class AuditResponseModel(SuccessResponseModel):
    """Full audit response"""
    data: FullAuditReportModel = Field(..., description="Complete audit results")

class HealthCheckModel(BaseModel):
    """Health check response"""
    status: str = Field(..., description="Health status")
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    checks: Dict[str, bool] = Field(..., description="Individual health checks")
    errors: Dict[str, Any] = Field(..., description="Error statistics")
    config_valid: bool = Field(..., description="Configuration validity")

# ========================
# UTILITY FUNCTIONS
# ========================

def create_error_response(
    error_type: str, 
    message: str, 
    details: Optional[List[ErrorDetailModel]] = None,
    request_id: Optional[str] = None
) -> ErrorResponseModel:
    """Create standardized error response"""
    return ErrorResponseModel(
        error=error_type,
        message=message,
        details=details or [],
        request_id=request_id
    )

def create_validation_error_response(
    validation_errors: List[Dict[str, Any]],
    request_id: Optional[str] = None
) -> ValidationErrorResponseModel:
    """Create validation error response from Pydantic errors"""
    return ValidationErrorResponseModel(
        validation_errors=validation_errors,
        request_id=request_id
    )