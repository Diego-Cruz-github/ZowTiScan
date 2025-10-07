#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZowTiCheck Flask Backend
Enhanced with security, validation, and structured logging
"""

import sys
import os
import time
import json
import uuid
from flask import Flask, request, jsonify, send_from_directory, g

# Import our new modules
from config import config
from logger import logger, handle_exception, log_performance, get_health_status
from validators import SecurityValidator, rate_limiter
from scanner import SecurityScanner
from models import (
    ScanRequestModel, PerformanceRequestModel, AuditRequestModel,
    SecurityReportModel, PerformanceModel, FullAuditReportModel,
    DisplayInfoModel, URLInfoModel, VulnerabilityModel
)
from response_helpers import ResponseBuilder, validate_request_json, get_risk_emoji

app = Flask(__name__)
app.config.from_object(config)

# Configure CORS with security headers
from flask_cors import CORS
CORS(app, origins="*" if config.is_development() else ["https://yourdomain.com"])

# Request middleware
@app.before_request
def before_request():
    """Setup request context and validation"""
    g.request_id = str(uuid.uuid4())
    g.start_time = time.time()
    g.client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
    
    # Create request logger with context
    g.logger = logger.with_context(
        request_id=g.request_id,
        user_ip=g.client_ip,
        method=request.method,
        path=request.path
    )
    
    g.logger.info("Request started")
    
    # Rate limiting for API endpoints
    if request.path.startswith('/api/'):
        allowed, message = rate_limiter.is_allowed(
            g.client_ip, 
            config.RATE_LIMIT_PER_MINUTE, 
            config.RATE_LIMIT_PER_HOUR
        )
        if not allowed:
            g.logger.warning(f"Rate limit exceeded: {message}")
            return jsonify({
                'success': False,
                'error': 'Rate limit exceeded',
                'message': message
            }), 429

@app.after_request
def after_request(response):
    """Log request completion"""
    duration = time.time() - g.start_time
    g.logger.info(
        "Request completed",
        status_code=response.status_code,
        duration=duration
    )
    
    # Add security headers
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    
    if config.is_production():
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    
    return response

# Health check endpoint
@app.route('/health')
def health_check():
    """Application health check with Pydantic validation"""
    from models import HealthCheckModel
    
    health_status = get_health_status()
    
    # Convert to Pydantic model for validation
    health_model = HealthCheckModel(**health_status)
    
    status_code = 200 if health_model.status == 'healthy' else 503
    return ResponseBuilder.success_response(health_model, status_code)

@app.route('/')
def index():
    """Serve the frontend"""
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('frontend', filename)

@app.route('/api/scan', methods=['POST'])
@validate_request_json(ScanRequestModel)
@handle_exception
@log_performance
def scan_endpoint(validated_data: ScanRequestModel):
    """Enhanced API endpoint for scanning URLs with Pydantic validation"""
    
    # Extract validated data
    target_url = str(validated_data.url)
    modules = validated_data.modules if validated_data.modules else None
    
    g.logger.info("Starting security scan", target_url=target_url, modules=modules)
    
    # Initialize scanner with config
    scanner = SecurityScanner(config)
    
    # Perform scan with enhanced logging
    start_time = time.time()
    try:
        vulnerabilities = scanner.scan_url(target_url, modules)
        duration = time.time() - start_time
        
        g.logger.info(
            "Security scan completed", 
            target_url=target_url,
            vulnerabilities_found=len(vulnerabilities),
            duration=duration
        )
        
        # Calculate security score first to handle connection errors
        security_score = scanner.calculate_security_score(vulnerabilities)
        
        # Handle connection errors (score = -1)
        if security_score == -1:
            return ResponseBuilder.error_response(
                "connection_error",
                f"Unable to connect to {target_url}. Please check the URL and try again."
            )
        
        # SPECIAL CASE: If scanning ONLY SEO module, use Google PageSpeed SEO score
        if modules and len(modules) == 1 and modules[0] == 'seo':
            try:
                seo_data = get_pagespeed_seo_data(target_url)
                if 'seo_score' in seo_data:
                    security_score = seo_data['seo_score']
            except Exception:
                pass  # Keep original security_score if SEO API fails
        
        # Convert vulnerabilities to Pydantic models
        vuln_models = [
            VulnerabilityModel(
                type=v.type,
                severity=v.severity,
                description=v.description,
                location=v.location,
                evidence=v.evidence or ""
            ) for v in vulnerabilities
        ]
        
        # Generate enhanced report using Pydantic model
        security_report = SecurityReportModel(
            target_url=target_url,
            security_score=security_score,
            risk_level=scanner.get_risk_level(vulnerabilities),
            total_vulnerabilities=len(vulnerabilities),
            vulnerabilities_by_severity=scanner.get_vulnerabilities_by_severity(vulnerabilities),
            vulnerabilities=vuln_models,
            scan_duration=round(duration, 2),
            modules_scanned=modules or ['all']
        )
        
        # Create display info
        display_info = DisplayInfoModel(
            risk_emoji=get_risk_emoji(security_report.risk_level),
            modules_analyzed=len(modules) if modules else 12,
            formatted_score=f"{security_report.security_score}/100",
            scan_time_formatted=f"{duration:.2f}s"
        )
        
        # Create URL info (simplified for now)
        from urllib.parse import urlparse
        parsed = urlparse(target_url)
        url_info = URLInfoModel(
            scheme=parsed.scheme,
            hostname=parsed.hostname,
            port=parsed.port or (443 if parsed.scheme == 'https' else 80),
            path=parsed.path or '/',
            domain=parsed.hostname.split('.')[-2] if '.' in parsed.hostname else parsed.hostname,
            subdomain='.'.join(parsed.hostname.split('.')[:-2]) if parsed.hostname.count('.') > 1 else None,
            suffix=parsed.hostname.split('.')[-1] if '.' in parsed.hostname else '',
            full_domain=parsed.hostname
        )
        
        return ResponseBuilder.scan_response(security_report, display_info, url_info)
        
    except Exception as e:
        duration = time.time() - start_time
        g.logger.exception(
            "Security scan failed", 
            target_url=target_url,
            duration=duration,
            error=str(e)
        )
        return ResponseBuilder.error_response(
            error_type="scan_failed",
            message="Internal error during security scan",
            status_code=500
        )

def get_risk_emoji(risk_level):
    """Get emoji for risk level - shared with scanner.py"""
    risk_emojis = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️', 
        'MEDIUM': '⚡',
        'LOW': '✅',
        'CONNECTION_ERROR': '❌'
    }
    return risk_emojis.get(risk_level, '❓')

@app.route('/api/smart-detect', methods=['POST'])
def smart_detect_endpoint():
    """API endpoint for smart URL detection"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({
                'error': 'Domain is required'
            }), 400
        
        # Initialize scanner
        scanner = SecurityScanner()
        
        # Perform smart detection
        working_url, error = scanner._smart_url_detection(domain)
        
        if error:
            return jsonify({
                'success': False,
                'error': error
            })
        
        # Extract protocol
        protocol = 'https' if working_url.startswith('https://') else 'http'
        
        return jsonify({
            'success': True,
            'protocol': protocol,
            'finalUrl': working_url,
            'error': None
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Detection failed: {str(e)}'
        })

@app.route('/api/performance', methods=['POST'])
def performance_endpoint():
    """API endpoint for PageSpeed performance analysis"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        # Get performance data from PageSpeed API
        performance_data = get_pagespeed_data(url)
        
        if performance_data.get('error'):
            return jsonify({
                'success': False,
                'error': performance_data['error']
            })
        
        return jsonify({
            'success': True,
            'performance': performance_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Performance analysis failed: {str(e)}'
        })

@app.route('/api/seo', methods=['POST'])
def seo_endpoint():
    """API endpoint for PageSpeed SEO analysis using Google API"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        # Get SEO data from PageSpeed API
        seo_data = get_pagespeed_seo_data(url)
        
        if 'error' in seo_data:
            return jsonify({
                'success': False,
                'error': seo_data['error']
            }), 400
        
        return jsonify({
            'success': True,
            'seo': seo_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'SEO analysis failed: {str(e)}'
        }), 500

@app.route('/api/web-patterns', methods=['POST'])
def web_development_patterns_endpoint():
    """API endpoint for Web Development Patterns analysis using Google Best Practices"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        # Get Web Development Patterns data from PageSpeed API
        patterns_data = get_pagespeed_best_practices_data(url)
        
        if 'error' in patterns_data:
            return jsonify({
                'success': False,
                'error': patterns_data['error']
            }), 400
        
        return jsonify({
            'success': True,
            'web_patterns': patterns_data
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Web Development Patterns analysis failed: {str(e)}'
        }), 500

@app.route('/api/generate-pdf', methods=['POST'])
def generate_pdf_endpoint():
    """Generate PDF reports (Executive Summary or Technical Report)"""
    try:
        data = request.get_json()
        report_data = data.get('data', {})
        report_type = data.get('report_type', 'summary')
        
        if not report_data:
            return jsonify({
                'success': False,
                'error': 'Report data is required'
            }), 400
        
        # Generate PDF based on type
        if report_type == 'summary':
            pdf_buffer = generate_executive_summary_pdf(report_data)
            filename = f"zowticheck-executive-summary-{int(time.time())}.pdf"
        else:
            pdf_buffer = generate_technical_report_pdf(report_data)
            filename = f"zowticheck-technical-report-{int(time.time())}.pdf"
        
        # Return PDF as response
        from flask import Response
        return Response(
            pdf_buffer.getvalue(),
            mimetype='application/pdf',
            headers={
                'Content-Disposition': f'attachment; filename="{filename}"',
                'Content-Type': 'application/pdf'
            }
        )
        
    except Exception as e:
        g.logger.exception("PDF generation failed", error=str(e))
        return jsonify({
            'success': False,
            'error': f'PDF generation failed: {str(e)}'
        }), 500

@app.route('/api/audit', methods=['POST'])
def full_audit_endpoint():
    """Complete 4-module audit: Security + Performance + SEO + Web Development Patterns"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'success': False,
                'error': 'URL is required'
            }), 400
        
        # Security scan (ZowTi modules only)
        scanner = SecurityScanner()
        start_time = time.time()
        vulnerabilities = scanner.scan_url(url)
        security_duration = time.time() - start_time
        security_report = scanner.generate_report(url, vulnerabilities)
        
        # Performance scan
        performance_start = time.time()
        performance_data = get_pagespeed_data(url)
        performance_duration = time.time() - performance_start
        
        # SEO scan
        seo_start = time.time()
        seo_data = get_pagespeed_seo_data(url)
        seo_duration = time.time() - seo_start
        
        # Web Development Patterns scan
        patterns_start = time.time()
        g.logger.info(f"Starting Web Development Patterns analysis for {url}")
        patterns_data = get_pagespeed_best_practices_data(url)
        patterns_duration = time.time() - patterns_start
        g.logger.info(f"Web Development Patterns completed in {patterns_duration:.2f}s")
        
        # Combined report
        combined_report = {
            'success': True,
            'target': url,
            'security': security_report,
            'performance': performance_data,
            'seo': seo_data,
            'web_patterns': patterns_data,
            'audit_duration': round(security_duration + performance_duration + seo_duration + patterns_duration, 2),
            'timestamp': time.strftime("%Y-%m-%d %H:%M:%S")
        }
        
        return jsonify(combined_report)
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Audit failed: {str(e)}'
        })

def get_pagespeed_single(url, strategy='desktop'):
    """Get PageSpeed data from Google API for a specific strategy (mobile/desktop)"""
    import requests as req
    
    try:
        # PageSpeed Insights API (Free tier: 25,000 requests/day)
        api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
        params = {
            'url': url,
            'strategy': strategy,
            'category': 'performance'
        }
        
        # Add API key if available
        if config and config.PAGESPEED_API_KEY:
            params['key'] = config.PAGESPEED_API_KEY
        
        response = req.get(api_url, params=params, timeout=30)
        
        if response.status_code != 200:
            # Handle specific error cases
            if response.status_code == 429:
                try:
                    error_data = response.json()
                    if 'quota exceeded' in error_data.get('error', {}).get('message', '').lower():
                        return {'error': 'PageSpeed API quota exceeded - Try again tomorrow or upgrade your API plan'}
                except:
                    pass
                return {'error': 'PageSpeed API rate limit exceeded - Please try again later'}
            elif response.status_code == 400:
                return {'error': 'Invalid URL or PageSpeed API request'}
            elif response.status_code == 403:
                return {'error': 'PageSpeed API key invalid or permissions insufficient'}
            else:
                return {'error': f'PageSpeed API error: {response.status_code}'}
        
        data = response.json()
        
        # Extract relevant metrics
        lighthouse_result = data.get('lighthouseResult', {})
        categories = lighthouse_result.get('categories', {})
        performance = categories.get('performance', {})
        
        audits = lighthouse_result.get('audits', {})
        
        # Core Web Vitals
        core_vitals = {}
        if 'largest-contentful-paint' in audits:
            core_vitals['lcp'] = audits['largest-contentful-paint'].get('displayValue', 'N/A')
        if 'first-input-delay' in audits:
            core_vitals['fid'] = audits['first-input-delay'].get('displayValue', 'N/A')
        if 'cumulative-layout-shift' in audits:
            core_vitals['cls'] = audits['cumulative-layout-shift'].get('displayValue', 'N/A')
        
        # Performance score - ensure it's always a valid number
        raw_score = performance.get('score', 0)
        perf_score = int(raw_score * 100) if raw_score is not None and raw_score != 0 else 0
        
        # Get specific metrics
        metrics = {}
        metric_keys = [
            'first-contentful-paint',
            'speed-index',
            'total-blocking-time',
            'interactive'
        ]
        
        for key in metric_keys:
            if key in audits:
                metrics[key] = audits[key].get('displayValue', 'N/A')
        
        return {
            'score': perf_score,
            'core_vitals': core_vitals,
            'metrics': metrics,
            'risk_level': get_performance_risk_level(perf_score),
            'recommendations_count': len([
                audit for audit in audits.values() 
                if audit.get('score') is not None and 
                isinstance(audit.get('score'), (int, float)) and 
                audit.get('score') < 0.9
            ])
        }
        
    except Exception as e:
        return {'error': f'Failed to get PageSpeed data: {str(e)}'}

def get_pagespeed_data(url):
    """Get PageSpeed data for both mobile and desktop"""
    import time
    
    try:
        g.logger.info(f"Starting dual PageSpeed analysis for {url}")
        
        # Get mobile data
        mobile_start = time.time()
        mobile_data = get_pagespeed_single(url, 'mobile')
        mobile_duration = time.time() - mobile_start
        
        if 'error' in mobile_data:
            g.logger.warning(f"Mobile PageSpeed failed: {mobile_data['error']}")
            return {'error': mobile_data['error']}
        
        g.logger.info(f"Mobile PageSpeed completed in {mobile_duration:.2f}s")
        
        # Get desktop data
        desktop_start = time.time()
        desktop_data = get_pagespeed_single(url, 'desktop')
        desktop_duration = time.time() - desktop_start
        
        if 'error' in desktop_data:
            g.logger.warning(f"Desktop PageSpeed failed: {desktop_data['error']}")
            return {'error': desktop_data['error']}
            
        g.logger.info(f"Desktop PageSpeed completed in {desktop_duration:.2f}s")
        
        # Combine results
        combined_data = {
            'mobile': {
                **mobile_data,
                'strategy': 'mobile',
                'analysis_time': f"{mobile_duration:.1f}s"
            },
            'desktop': {
                **desktop_data,
                'strategy': 'desktop', 
                'analysis_time': f"{desktop_duration:.1f}s"
            },
            'total_time': f"{mobile_duration + desktop_duration:.1f}s",
            'summary': {
                'mobile_score': mobile_data.get('score', 0),
                'desktop_score': desktop_data.get('score', 0),
                'score_difference': abs(desktop_data.get('score', 0) - mobile_data.get('score', 0))
            }
        }
        
        g.logger.info(f"Dual PageSpeed analysis completed - Mobile: {mobile_data.get('score', 0)}/100, Desktop: {desktop_data.get('score', 0)}/100")
        
        return combined_data
        
    except Exception as e:
        g.logger.error(f"Dual PageSpeed analysis failed: {str(e)}")
        return {'error': f'Failed to get dual PageSpeed data: {str(e)}'}

def get_pagespeed_best_practices_data(url):
    """Get Best Practices data from Google PageSpeed API"""
    import requests as req
    
    try:
        g.logger.info(f"Starting Best Practices API call for {url}")
        # PageSpeed Insights API
        api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
        params = {
            'url': url,
            'strategy': config.PAGESPEED_STRATEGY if config else 'desktop',
            'category': 'best-practices'  # Focus on Best Practices category
        }
        
        # Add API key if available
        if config and config.PAGESPEED_API_KEY:
            params['key'] = config.PAGESPEED_API_KEY
        
        response = req.get(api_url, params=params, timeout=30)
        
        if response.status_code != 200:
            # Handle specific error cases
            if response.status_code == 429:
                try:
                    error_data = response.json()
                    if 'quota exceeded' in error_data.get('error', {}).get('message', '').lower():
                        return {'error': 'PageSpeed API quota exceeded - Try again tomorrow or upgrade your API plan'}
                except:
                    pass
                return {'error': 'PageSpeed API rate limit exceeded - Please try again later'}
            elif response.status_code == 400:
                return {'error': 'Invalid URL or PageSpeed API request'}
            elif response.status_code == 403:
                return {'error': 'PageSpeed API key invalid or permissions insufficient'}
            else:
                return {'error': f'PageSpeed API error: {response.status_code}'}
        
        data = response.json()
        
        # Extract Best Practices data
        lighthouse_result = data.get('lighthouseResult', {})
        categories = lighthouse_result.get('categories', {})
        best_practices_category = categories.get('best-practices', {})
        
        audits = lighthouse_result.get('audits', {})
        
        # Best Practices score
        best_practices_score = int(best_practices_category.get('score', 0) * 100) if best_practices_category.get('score') is not None else 0
        
        # Extract specific Best Practices audits
        best_practices_audits = {}
        best_practices_audit_keys = [
            'is-on-https',
            'uses-http2', 
            'no-vulnerable-libraries',
            'errors-in-console',
            'image-aspect-ratio',
            'image-size-responsive',
            'preload-fonts',
            'charset'
        ]
        
        issues_found = []
        for key in best_practices_audit_keys:
            if key in audits:
                audit = audits[key]
                if audit.get('score') is not None and audit.get('score') < 1:
                    issues_found.append({
                        'type': audit.get('title', key),
                        'description': audit.get('description', 'Best practice issue detected'),
                        'severity': 'medium' if audit.get('score', 1) < 0.5 else 'low'
                    })
        
        return {
            'best_practices_score': best_practices_score,
            'issues': issues_found,
            'source': 'ZowTiCheck Web Development Analysis',
            'total_issues': len(issues_found)
        }
        
    except Exception as e:
        return {'error': f'Failed to get PageSpeed Best Practices data: {str(e)}'}

def get_pagespeed_seo_single(url, strategy='desktop'):
    """Get SEO data from Google PageSpeed API for a specific strategy (mobile/desktop)"""
    import requests as req
    
    try:
        # PageSpeed Insights API
        api_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed"
        params = {
            'url': url,
            'strategy': strategy,
            'category': 'seo'  # Focus on SEO category
        }
        
        # Add API key if available
        if config and config.PAGESPEED_API_KEY:
            params['key'] = config.PAGESPEED_API_KEY
        
        response = req.get(api_url, params=params, timeout=30)
        
        if response.status_code != 200:
            # Handle specific error cases
            if response.status_code == 429:
                try:
                    error_data = response.json()
                    if 'quota exceeded' in error_data.get('error', {}).get('message', '').lower():
                        return {'error': 'PageSpeed API quota exceeded - Try again tomorrow or upgrade your API plan'}
                except:
                    pass
                return {'error': 'PageSpeed API rate limit exceeded - Please try again later'}
            elif response.status_code == 400:
                return {'error': 'Invalid URL or PageSpeed API request'}
            elif response.status_code == 403:
                return {'error': 'PageSpeed API key invalid or permissions insufficient'}
            else:
                return {'error': f'PageSpeed API error: {response.status_code}'}
        
        data = response.json()
        
        # Extract SEO data
        lighthouse_result = data.get('lighthouseResult', {})
        categories = lighthouse_result.get('categories', {})
        seo_category = categories.get('seo', {})
        
        audits = lighthouse_result.get('audits', {})
        
        # SEO score
        seo_score = int(seo_category.get('score', 0) * 100) if seo_category.get('score') is not None else 0
        
        # Extract specific SEO audits
        seo_audit_keys = [
            'document-title',
            'meta-description', 
            'heading-order',
            'image-alt',
            'crawlable-anchors',
            'robots-txt',
            'canonical'
        ]
        
        issues_found = []
        for key in seo_audit_keys:
            if key in audits:
                audit = audits[key]
                if audit.get('score') is not None and audit.get('score') < 1:
                    issues_found.append({
                        'type': audit.get('title', key),
                        'description': audit.get('description', 'SEO issue detected'),
                        'severity': 'medium' if audit.get('score', 1) < 0.5 else 'low'
                    })
        
        return {
            'seo_score': seo_score,
            'issues': issues_found,
            'source': f'ZowTiCheck SEO Analysis ({strategy.title()})',
            'total_issues': len(issues_found),
            'risk_level': get_seo_risk_level(seo_score)
        }
        
    except Exception as e:
        return {'error': f'Failed to get PageSpeed SEO data: {str(e)}'}

def get_pagespeed_seo_data(url):
    """Get SEO data for both mobile and desktop"""
    import time
    
    try:
        g.logger.info(f"Starting dual SEO analysis for {url}")
        
        # Get mobile SEO data
        mobile_start = time.time()
        mobile_data = get_pagespeed_seo_single(url, 'mobile')
        mobile_duration = time.time() - mobile_start
        
        if 'error' in mobile_data:
            g.logger.warning(f"Mobile SEO failed: {mobile_data['error']}")
            return {'error': mobile_data['error']}
        
        g.logger.info(f"Mobile SEO completed in {mobile_duration:.2f}s")
        
        # Get desktop SEO data
        desktop_start = time.time()
        desktop_data = get_pagespeed_seo_single(url, 'desktop')
        desktop_duration = time.time() - desktop_start
        
        if 'error' in desktop_data:
            g.logger.warning(f"Desktop SEO failed: {desktop_data['error']}")
            return {'error': desktop_data['error']}
            
        g.logger.info(f"Desktop SEO completed in {desktop_duration:.2f}s")
        
        # Combine results
        combined_data = {
            'mobile': {
                **mobile_data,
                'strategy': 'mobile',
                'analysis_time': f"{mobile_duration:.1f}s"
            },
            'desktop': {
                **desktop_data,
                'strategy': 'desktop', 
                'analysis_time': f"{desktop_duration:.1f}s"
            },
            'total_time': f"{mobile_duration + desktop_duration:.1f}s",
            'summary': {
                'mobile_score': mobile_data.get('seo_score', 0),
                'desktop_score': desktop_data.get('seo_score', 0),
                'score_difference': abs(desktop_data.get('seo_score', 0) - mobile_data.get('seo_score', 0)),
                'total_issues': mobile_data.get('total_issues', 0) + desktop_data.get('total_issues', 0)
            }
        }
        
        g.logger.info(f"Dual SEO analysis completed - Mobile: {mobile_data.get('seo_score', 0)}/100, Desktop: {desktop_data.get('seo_score', 0)}/100")
        
        return combined_data
        
    except Exception as e:
        g.logger.error(f"Dual SEO analysis failed: {str(e)}")
        return {'error': f'Failed to get dual SEO data: {str(e)}'}

def get_seo_risk_level(score):
    """Get SEO risk level based on score"""
    # Handle None or invalid scores
    if score is None or not isinstance(score, (int, float)):
        return 'POOR'
    
    if score >= 90:
        return 'EXCELLENT'
    elif score >= 80:
        return 'GOOD'
    elif score >= 60:
        return 'NEEDS_IMPROVEMENT'
    else:
        return 'POOR'

def get_performance_risk_level(score):
    """Get performance risk level based on score"""
    # Handle None or invalid scores
    if score is None or not isinstance(score, (int, float)):
        return 'POOR'
    
    if score >= 90:
        return 'GOOD'
    elif score >= 50:
        return 'NEEDS_IMPROVEMENT'
    else:
        return 'POOR'

def generate_executive_summary_pdf(data):
    """Generate executive summary PDF for client presentation - Professional business report"""
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from datetime import datetime
    import io
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=72)
    
    # Professional styles
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle(
        'ExecutiveTitle',
        parent=styles['Heading1'],
        fontSize=26,
        spaceAfter=30,
        textColor=HexColor('#1a365d'),
        alignment=1,
        fontName='Helvetica-Bold'
    )
    
    subtitle_style = ParagraphStyle(
        'ExecutiveSubtitle',
        parent=styles['Heading2'],
        fontSize=16,
        spaceAfter=20,
        textColor=HexColor('#2d3748'),
        fontName='Helvetica-Bold'
    )
    
    header_style = ParagraphStyle(
        'HeaderStyle',
        parent=styles['Normal'],
        fontSize=12,
        spaceAfter=15,
        textColor=HexColor('#4a5568'),
        fontName='Helvetica'
    )
    
    content = []
    
    # Professional Header
    content.append(Paragraph("CYBERSECURITY ASSESSMENT", title_style))
    content.append(Paragraph("Executive Summary Report", subtitle_style))
    content.append(Spacer(1, 30))
    
    # Extract target properly
    target_url = data.get('target', data.get('data', {}).get('target_url', 'Unknown'))
    if isinstance(target_url, dict):
        target_url = target_url.get('target_url', 'Unknown')
    
    # Report metadata
    report_date = datetime.now().strftime("%B %d, %Y")
    content.append(Paragraph(f"<b>Target Website:</b> {target_url}", header_style))
    content.append(Paragraph(f"<b>Assessment Date:</b> {report_date}", header_style))
    content.append(Paragraph(f"<b>Report Type:</b> Executive Summary", header_style))
    content.append(Spacer(1, 30))
    
    # Extract scores from data structure
    security_score = 0
    perf_mobile = 0
    perf_desktop = 0
    seo_mobile = 0
    seo_desktop = 0
    web_patterns_score = 0
    
    # Handle different data structures - support both direct and nested data
    if 'security' in data:
        security_score = data['security'].get('security_score', 0)
    elif 'data' in data and 'security' in data['data']:
        security_score = data['data']['security'].get('security_score', 0)
    elif 'data' in data and 'data' in data['data']:
        security_score = data['data']['data'].get('security_score', 0)
    
    if 'performance' in data:
        perf_mobile = data['performance'].get('mobile', {}).get('score', 0)
        perf_desktop = data['performance'].get('desktop', {}).get('score', 0)
    
    if 'seo' in data:
        seo_mobile = data['seo'].get('mobile', {}).get('seo_score', 0)
        seo_desktop = data['seo'].get('desktop', {}).get('seo_score', 0)
    
    if 'web_patterns' in data:
        web_patterns_score = data['web_patterns'].get('best_practices_score', 0)
    
    # Overall Assessment Score
    overall_score = int((security_score + perf_mobile + perf_desktop + seo_mobile + seo_desktop + web_patterns_score) / 6)
    
    # Executive Summary Table
    summary_data = [
        ['Assessment Area', 'Score', 'Status', 'Priority'],
        ['Security Vulnerabilities', f"{security_score}/100", get_status_text(security_score), get_priority_text(security_score)],
        ['Mobile Performance', f"{perf_mobile}/100", get_status_text(perf_mobile), get_priority_text(perf_mobile)],
        ['Desktop Performance', f"{perf_desktop}/100", get_status_text(perf_desktop), get_priority_text(perf_desktop)],
        ['Mobile SEO', f"{seo_mobile}/100", get_status_text(seo_mobile), get_priority_text(seo_mobile)],
        ['Desktop SEO', f"{seo_desktop}/100", get_status_text(seo_desktop), get_priority_text(seo_desktop)],
        ['Web Standards', f"{web_patterns_score}/100", get_status_text(web_patterns_score), get_priority_text(web_patterns_score)],
        ['OVERALL SCORE', f"{overall_score}/100", get_status_text(overall_score), get_priority_text(overall_score)]
    ]
    
    summary_table = Table(summary_data, colWidths=[2.5*inch, 1*inch, 1*inch, 1.2*inch])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#1a365d')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 11),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
        ('TOPPADDING', (0, 0), (-1, 0), 12),
        ('BACKGROUND', (0, 1), (-1, -2), HexColor('#f7fafc')),
        ('BACKGROUND', (0, -1), (-1, -1), HexColor('#e2e8f0')),
        ('FONTNAME', (0, -1), (-1, -1), 'Helvetica-Bold'),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#cbd5e0'))
    ]))
    
    content.append(Paragraph("Assessment Overview", subtitle_style))
    content.append(summary_table)
    content.append(Spacer(1, 30))
    
    # Key Findings
    content.append(Paragraph("Key Findings & Recommendations", subtitle_style))
    
    # Security findings
    if security_score < 60:
        content.append(Paragraph("🔴 <b>CRITICAL:</b> Multiple security vulnerabilities identified requiring immediate attention", styles['Normal']))
    elif security_score < 80:
        content.append(Paragraph("🟡 <b>MODERATE:</b> Some security issues found that should be addressed", styles['Normal']))
    else:
        content.append(Paragraph("🟢 <b>GOOD:</b> Security posture is acceptable with minor improvements needed", styles['Normal']))
    
    # Performance findings
    avg_performance = (perf_mobile + perf_desktop) / 2
    if avg_performance < 60:
        content.append(Paragraph("🔴 <b>PERFORMANCE:</b> Website speed optimization critical for user experience", styles['Normal']))
    elif avg_performance < 80:
        content.append(Paragraph("🟡 <b>PERFORMANCE:</b> Performance improvements recommended", styles['Normal']))
    else:
        content.append(Paragraph("🟢 <b>PERFORMANCE:</b> Good performance metrics observed", styles['Normal']))
    
    # SEO findings
    avg_seo = (seo_mobile + seo_desktop) / 2
    if avg_seo < 60:
        content.append(Paragraph("🔴 <b>SEO:</b> Significant SEO improvements needed for search visibility", styles['Normal']))
    elif avg_seo < 80:
        content.append(Paragraph("🟡 <b>SEO:</b> SEO optimization opportunities identified", styles['Normal']))
    else:
        content.append(Paragraph("🟢 <b>SEO:</b> Good search engine optimization detected", styles['Normal']))
    
    content.append(Spacer(1, 30))
    
    # Next Steps
    content.append(Paragraph("Recommended Next Steps", subtitle_style))
    content.append(Paragraph("1. Review detailed technical report for specific remediation steps", styles['Normal']))
    content.append(Paragraph("2. Prioritize security vulnerabilities for immediate patching", styles['Normal']))
    content.append(Paragraph("3. Implement performance optimization recommendations", styles['Normal']))
    content.append(Paragraph("4. Schedule follow-up assessment in 30 days", styles['Normal']))
    content.append(Spacer(1, 20))
    
    content.append(Paragraph("5. Contact ZowTi team for professional remediation services", styles['Normal']))
    
    # Professional Footer
    content.append(Spacer(1, 50))
    footer_style = ParagraphStyle('Footer', parent=styles['Normal'], fontSize=9, textColor=HexColor('#718096'), alignment=1)
    content.append(Paragraph("Generated by ZowTiCheck Professional Cybersecurity Suite", footer_style))
    content.append(Paragraph("For technical support: support@zowti.com", footer_style))
    
    doc.build(content)
    buffer.seek(0)
    return buffer

def generate_technical_report_pdf(data):
    """Generate detailed technical PDF report with comprehensive analysis"""
    import json
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.colors import HexColor
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from datetime import datetime
    import io

    if 'data' in data and isinstance(data.get('data'), dict):
        report_content = data['data']
    else:
        report_content = data
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=60, leftMargin=60, topMargin=60, bottomMargin=60)
    
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle('TechnicalTitle', parent=styles['Heading1'], fontSize=22, spaceAfter=25, textColor=HexColor('#1a202c'), fontName='Helvetica-Bold', alignment=1)
    section_style = ParagraphStyle('SectionHeader', parent=styles['Heading2'], fontSize=14, spaceAfter=15, spaceBefore=20, textColor=HexColor('#2d3748'), fontName='Helvetica-Bold', backColor=HexColor('#f7fafc'), borderPadding=8)
    subsection_style = ParagraphStyle('SubsectionHeader', parent=styles['Heading3'], fontSize=12, spaceAfter=10, spaceBefore=15, textColor=HexColor('#4a5568'), fontName='Helvetica-Bold')
    
    content = []
    
    content.append(Paragraph("COMPLETE TECHNICAL AUDIT", title_style))
    content.append(Paragraph("Security + Performance + SEO + Web Patterns Analysis", subsection_style))
    content.append(Spacer(1, 20))
    
    target_url = report_content.get('target', 'Unknown')
    scan_duration = report_content.get('audit_duration', report_content.get('scan_duration', 0))
    
    report_date = datetime.now().strftime("%B %d, %Y at %H:%M")
    meta_data = [
        ['Report Parameter', 'Value'],
        ['Target Website', target_url],
        ['Assessment Date', report_date],
        ['Scan Duration', f"{scan_duration:.2f} seconds"],
        ['Report Type', 'Technical Analysis'],
        ['ZowTiCheck Version', 'Professional v2.0']
    ]
    
    meta_table = Table(meta_data, colWidths=[2*inch, 3.5*inch])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, 0), HexColor('#4a5568')),
        ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, 0), 10),
        ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
        ('BACKGROUND', (0, 1), (-1, -1), HexColor('#f8f9fa')),
        ('GRID', (0, 0), (-1, -1), 1, HexColor('#dee2e6'))
    ]))
    
    content.append(meta_table)
    content.append(Spacer(1, 30))

    security_data = report_content.get('security')
    if security_data:
        content.append(Paragraph("1. SECURITY VULNERABILITY ANALYSIS", section_style))
        security_score = security_data.get('security_score', 0)
        total_vulns = security_data.get('total_vulnerabilities', 0)
        risk_level = security_data.get('risk_level', 'Unknown')
        
        sec_summary = [
            ['Metric', 'Value', 'Assessment'],
            ['Security Score', f"{security_score}/100", get_status_text(security_score)],
            ['Total Vulnerabilities', str(total_vulns), f"{total_vulns} issues found"],
            ['Risk Level', risk_level, get_risk_description(risk_level)],
        ]
        sec_table = Table(sec_summary, colWidths=[1.8*inch, 1.5*inch, 2.2*inch])
        sec_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#e53e3e')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#fed7d7')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#c53030'))
        ]))
        content.append(sec_table)
        content.append(Spacer(1, 15))

        vulnerabilities = security_data.get('vulnerabilities', {})
        if isinstance(vulnerabilities, dict):
            severity_mapping = {
                'critical_high': 'CRITICAL/HIGH SEVERITY',
                'medium': 'MEDIUM SEVERITY', 
                'low': 'LOW SEVERITY'
            }
            for severity_key, severity_label in severity_mapping.items():
                if severity_key in vulnerabilities and vulnerabilities[severity_key]:
                    content.append(Paragraph(f"{severity_label} VULNERABILITIES:", subsection_style))
                    for i, vuln in enumerate(vulnerabilities[severity_key], 1):
                        content.append(Paragraph(f"<b>{i}. {vuln.get('type', 'Unknown')}</b>: {vuln.get('description', 'No description')}", styles['Normal']))
                        content.append(Spacer(1, 10))

    content.append(PageBreak())

    performance_data = report_content.get('performance')
    if performance_data:
        content.append(Paragraph("2. PERFORMANCE OPTIMIZATION ANALYSIS", section_style))
        mobile_data = performance_data.get('mobile', {})
        desktop_data = performance_data.get('desktop', {})
        perf_data = [
            ['Platform', 'Score', 'Status', 'Assessment'],
            ['Mobile', f"{mobile_data.get('score', 0)}/100", get_status_text(mobile_data.get('score', 0)), 'Mobile user experience'],
            ['Desktop', f"{desktop_data.get('score', 0)}/100", get_status_text(desktop_data.get('score', 0)), 'Desktop user experience']
        ]
        perf_table = Table(perf_data, colWidths=[1.2*inch, 1*inch, 1.3*inch, 2*inch])
        perf_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), HexColor('#38a169')),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('BACKGROUND', (0, 1), (-1, -1), HexColor('#c6f6d5')),
            ('GRID', (0, 0), (-1, -1), 1, HexColor('#2f855a'))
        ]))
        content.append(perf_table)
        content.append(Spacer(1, 15))

    content.append(Paragraph("3. SEARCH ENGINE OPTIMIZATION ANALYSIS", section_style))
    seo_data = report_content.get('seo')
    if seo_data and isinstance(seo_data, dict) and ('mobile' in seo_data or 'desktop' in seo_data):
        mobile_seo = seo_data.get('mobile', {})
        desktop_seo = seo_data.get('desktop', {})
        
        content.append(Paragraph(f"Mobile Score: {mobile_seo.get('seo_score', 'N/A')}/100 | Desktop Score: {desktop_seo.get('seo_score', 'N/A')}/100", subsection_style))
        
        all_issues = mobile_seo.get('issues', []) + desktop_seo.get('issues', [])
        unique_issues = {issue['type']: issue for issue in all_issues}.values()

        if unique_issues:
            content.append(Paragraph("SEO Issues Found:", subsection_style))
            for issue in unique_issues:
                content.append(Paragraph(f"• <b>{issue.get('type')}</b>: {issue.get('description')}", styles['Normal']))
            content.append(Spacer(1, 15))
        else:
            content.append(Paragraph("No significant SEO issues found.", styles['Normal']))
    else:
        content.append(Paragraph("<i>SEO data not available for this report.</i>", styles['Normal']))
    content.append(Spacer(1, 15))

    content.append(Paragraph("4. WEB DEVELOPMENT PATTERNS ANALYSIS", section_style))
    web_patterns_data = report_content.get('web_patterns')
    if web_patterns_data and isinstance(web_patterns_data, dict) and 'best_practices_score' in web_patterns_data:
        score = web_patterns_data.get('best_practices_score', 'N/A')
        content.append(Paragraph(f"Best Practices Score: {score}/100", subsection_style))
        
        issues = web_patterns_data.get('issues', [])
        if issues:
            content.append(Paragraph("Web Development Issues Found:", subsection_style))
            for issue in issues:
                content.append(Paragraph(f"• <b>{issue.get('type')}</b>: {issue.get('description')}", styles['Normal']))
            content.append(Spacer(1, 15))
        else:
            content.append(Paragraph("No significant Web Development issues found.", styles['Normal']))
    else:
        content.append(Paragraph("<i>Web Patterns data not available for this report.</i>", styles['Normal']))
    content.append(Spacer(1, 15))

    content.append(Paragraph("TECHNICAL RECOMMENDATIONS", section_style))
    recommendations = []
    priority_actions = []
    if security_data:
        if security_data.get('risk_level') == 'CRITICAL':
            priority_actions.append("CRITICAL SECURITY RISK: Address all vulnerabilities immediately.")
    if performance_data:
        if performance_data.get('mobile', {}).get('score', 100) < 50:
            priority_actions.append("PERFORMANCE: Mobile performance critically low - immediate optimization required.")
    if priority_actions:
        content.append(Paragraph("1. IMMEDIATE PRIORITY ACTIONS:", subsection_style))
        for action in priority_actions:
            content.append(Paragraph(f"• {action}", styles['Normal']))
        content.append(Spacer(1, 15))

    # Technical Footer
    content.append(Spacer(1, 40))
    footer_style = ParagraphStyle('TechFooter', parent=styles['Normal'], fontSize=8, textColor=HexColor('#6b7280'), alignment=1)
    content.append(Paragraph("ZowTiCheck Professional Cybersecurity Suite - Technical Analysis Report", footer_style))
    content.append(Paragraph("This report contains confidential security information - Handle according to security policies", footer_style))
    
    doc.build(content)
    buffer.seek(0)
    return buffer

def get_status_text(score):
    """Get status text based on score"""
    if score >= 80:
        return "Good"
    elif score >= 60:
        return "Fair"
    elif score >= 40:
        return "Poor"
    else:
        return "Critical"

def get_priority_text(score):
    """Get priority text based on score"""
    if score >= 80:
        return "Low"
    elif score >= 60:
        return "Medium"
    elif score >= 40:
        return "High"
    else:
        return "Critical"

def get_risk_description(risk_level):
    """Get risk description based on level"""
    risk_descriptions = {
        'LOW': 'Minimal security concerns',
        'MEDIUM': 'Some security issues need attention',
        'HIGH': 'Significant security vulnerabilities',
        'CRITICAL': 'Immediate security action required'
    }
    return risk_descriptions.get(risk_level.upper(), 'Unknown risk level')

def print_startup_banner():
    """Print professional startup banner"""
    banner = """
=================================================================
                   ZowTiCheck Backend v2.1                     
              Security + Performance Audit API                 
                     Server Status: ONLINE                     
=================================================================

Frontend Interface: http://localhost:5000
Security API: http://localhost:5000/api/scan  
Performance API: http://localhost:5000/api/performance
Full Audit API: http://localhost:5000/api/audit
PDF Reports: http://localhost:5000/api/generate-pdf
Security Mode: Defensive Analysis Only
Modules Available: 12 security + PageSpeed checks
Report Formats: JSON, Text, PDF
Ready for professional auditing!

-----------------------------------------------------------------
"""
    print(banner)

if __name__ == '__main__':
    print_startup_banner()
    app.run(debug=True, host='0.0.0.0', port=5000)