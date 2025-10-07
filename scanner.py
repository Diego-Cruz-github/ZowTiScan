#!/usr/bin/env python3
"""
ZowTiScan - Professional Security Scanner
Refactored for simplicity and effectiveness
"""

import requests
from bs4 import BeautifulSoup
import re
import time
import socket
import subprocess
import platform
from urllib.parse import urljoin, urlparse
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple
import argparse
import json


@dataclass
class Vulnerability:
    """Security vulnerability data structure"""
    type: str
    severity: str
    description: str
    location: str
    evidence: str = ""


class SecurityScanner:
    """Professional security scanner with 12 detection modules"""
    
    def __init__(self, config=None):
        self.config = config
        self.session = requests.Session()
        
        # Use config for timeouts if available
        timeout = getattr(config, 'REQUEST_TIMEOUT', 10) if config else 10
        self.session.timeout = timeout
        
        self.session.headers.update({
            'User-Agent': 'ZowTiCheck/2.1 (Security Scanner)'
        })
    
    def _ping_host(self, hostname: str) -> bool:
        """Check if host is reachable via ping"""
        try:
            # Remove protocol if present
            hostname = hostname.replace('http://', '').replace('https://', '')
            hostname = hostname.split('/')[0]  # Remove path
            
            # Platform-specific ping command
            if platform.system().lower() == "windows":
                cmd = ["ping", "-n", "1", hostname]
            else:
                cmd = ["ping", "-c", "1", hostname]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.returncode == 0
        except Exception:
            return False
    
    def _test_http_connectivity(self, hostname: str) -> Optional[str]:
        """Test HTTP and HTTPS connectivity, return working URL"""
        # Clean hostname
        hostname = hostname.replace('http://', '').replace('https://', '')
        hostname = hostname.split('/')[0]  # Remove path
        
        # Test protocols in order of preference (HTTPS first)
        protocols = ['https://', 'http://']
        
        for protocol in protocols:
            test_url = f"{protocol}{hostname}"
            try:
                # Use GET instead of HEAD since many servers block HEAD requests
                response = self.session.get(test_url, timeout=10, allow_redirects=True, stream=True)
                # Only read a small amount to avoid downloading large files
                response.raw.read(1024, decode_content=True)
                response.close()
                # Accept any response that indicates the server is responding
                # 403 means server is working but blocking access (still a valid connection)
                if response.status_code < 400 or response.status_code == 403:
                    return test_url
            except Exception:
                continue
        
        return None
    
    def _smart_url_detection(self, url: str) -> Tuple[Optional[str], Optional[str]]:
        """Smart URL detection with ping and protocol testing"""
        # Parse the input
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else f"http://{url}")
        hostname = parsed.hostname or parsed.netloc.split(':')[0]
        
        if not hostname:
            return None, "Invalid URL format"
        
        # Step 1: Check DNS/Ping
        if not self._ping_host(hostname):
            return None, f"Host '{hostname}' is not reachable (DNS resolution failed or host offline)"
        
        # Step 2: Test HTTP/HTTPS connectivity
        working_url = self._test_http_connectivity(hostname)
        if not working_url:
            return None, f"Host '{hostname}' is reachable but HTTP/HTTPS services are not responding"
        
        return working_url, None
    
    def _detect_technology_context(self, soup: BeautifulSoup, response) -> Dict[str, Any]:
        """
        Intelligent technology detection for context-aware vulnerability assessment
        Reduces false positives by understanding the application stack
        """
        context = {
            'is_wordpress': False,
            'is_drupal': False,
            'is_static': False,
            'is_spa': False,
            'cms_type': None,
            'has_database_evidence': False,
            'javascript_framework': None,
            'server_technology': response.headers.get('Server', '').lower(),
            'confidence_level': 'low'
        }
        
        html_content = response.text.lower()
        
        # WordPress Detection (high confidence indicators)
        wordpress_indicators = [
            'wp-content', 'wp-includes', 'wp-admin', 'wordpress',
            'wpcf7', 'elementor', 'wp-json', '/wp/', 'wp_nonce'
        ]
        wp_score = sum(1 for indicator in wordpress_indicators if indicator in html_content)
        if wp_score >= 2:
            context['is_wordpress'] = True
            context['cms_type'] = 'WordPress'
            context['confidence_level'] = 'high' if wp_score >= 4 else 'medium'
        
        # Drupal Detection
        drupal_indicators = ['drupal', 'sites/default', '/sites/all/', 'drupal.js']
        if any(indicator in html_content for indicator in drupal_indicators):
            context['is_drupal'] = True
            context['cms_type'] = 'Drupal'
            context['confidence_level'] = 'medium'
        
        # Static Site Detection
        static_indicators = ['jekyll', 'hugo', 'gatsby', 'netlify', 'github.io']
        if any(indicator in html_content for indicator in static_indicators):
            context['is_static'] = True
            context['cms_type'] = 'Static Site Generator'
            context['confidence_level'] = 'high'
        
        # SPA Detection
        spa_indicators = ['react', 'angular', 'vue.js', 'spa-', 'single-page']
        if any(indicator in html_content for indicator in spa_indicators):
            context['is_spa'] = True
            context['javascript_framework'] = 'Modern SPA'
        
        # Database Evidence Detection (more comprehensive)
        db_indicators = [
            'mysql', 'postgresql', 'mongodb', 'redis', 'database error',
            'sql syntax', 'connection failed', 'query failed', 'sqlite',
            'phpmyadmin', 'adminer', 'query string', 'db_', 'database_'
        ]
        
        # Look for actual database interaction signs
        forms = soup.find_all('form')
        has_search_forms = any(
            'search' in form.get('action', '').lower() or 
            any('search' in inp.get('name', '').lower() for inp in form.find_all(['input', 'select', 'textarea']))
            for form in forms
        )
        
        has_user_forms = any(
            any(field in inp.get('name', '').lower() for field in ['user', 'login', 'email', 'password'])
            for form in forms
            for inp in form.find_all(['input', 'select', 'textarea'])
        )
        
        # WordPress often has database interaction but with secure handling
        if context['is_wordpress']:
            # WordPress has database but usually secure - flag only if suspicious patterns
            context['has_database_evidence'] = (
                any(indicator in html_content for indicator in db_indicators) or
                has_search_forms  # WordPress search uses database
            )
        else:
            # Non-WordPress sites - more likely to have unsafe database handling
            context['has_database_evidence'] = (
                any(indicator in html_content for indicator in db_indicators) or
                has_search_forms or has_user_forms
            )
        
        return context
        
    def scan_url(self, url: str, modules: List[str] = None) -> List[Vulnerability]:
        """Main scanning function with smart URL detection"""
        if modules is None:
            modules = ['xss', 'csrf', 'injection', 'nosql_injection', 'broken_pages', 'headers', 'info_disclosure', 'authentication', 'access_control', 'file_upload', 'tech_stack', 'directory_traversal', 'seo']
            
        vulnerabilities = []
        
        # Smart URL detection and validation
        working_url, error = self._smart_url_detection(url)
        if error:
            vulnerabilities.append(
                Vulnerability(
                    type="Connection Error",
                    severity="info",
                    description=error,
                    location=url
                )
            )
            return vulnerabilities
        
        # Use the working URL for scanning
        url = working_url
        
        try:
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Detect technology context for intelligent vulnerability assessment
            context = self._detect_technology_context(soup, response)
            
            for module in modules:
                if module == 'xss':
                    vulnerabilities.extend(self._scan_xss(soup, url))
                elif module == 'csrf':
                    vulnerabilities.extend(self._scan_csrf(soup, url))
                elif module == 'injection':
                    vulnerabilities.extend(self._scan_injection_smart(soup, url, context))
                elif module == 'nosql_injection':
                    vulnerabilities.extend(self._scan_nosql_injection_smart(soup, url, context))
                elif module == 'broken_pages':
                    vulnerabilities.extend(self._scan_broken_pages(url))
                elif module == 'headers':
                    vulnerabilities.extend(self._scan_headers(response, url))
                elif module == 'info_disclosure':
                    vulnerabilities.extend(self._scan_info_disclosure(response, url))
                elif module == 'authentication':
                    vulnerabilities.extend(self._scan_authentication(soup, url))
                elif module == 'access_control':
                    vulnerabilities.extend(self._scan_access_control(soup, url))
                elif module == 'file_upload':
                    vulnerabilities.extend(self._scan_file_upload(soup, url))
                elif module == 'tech_stack':
                    vulnerabilities.extend(self._scan_tech_stack(response, soup, url))
                elif module == 'directory_traversal':
                    vulnerabilities.extend(self._scan_directory_traversal(url))
                elif module == 'seo':
                    vulnerabilities.extend(self._scan_seo(url, response, soup))
                    
        except Exception as e:
            vulnerabilities.append(
                Vulnerability(
                    type="Scan Error",
                    severity="info",
                    description=f"Error scanning {url}: {str(e)}",
                    location=url
                )
            )
            
        return vulnerabilities
    
    def _scan_xss(self, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """XSS vulnerability detection"""
        vulnerabilities = []
        
        # Check for potentially vulnerable inputs
        inputs = soup.find_all(['input', 'textarea'])
        for input_tag in inputs:
            input_name = input_tag.get('name', 'unnamed')
            if input_tag.get('type') not in ['hidden', 'submit', 'button']:
                vulnerabilities.append(
                    Vulnerability(
                        type="Potential XSS Input",
                        severity="medium",
                        description=f"Input '{input_name}' might be vulnerable to XSS without proper output encoding",
                        location=url,
                    )
                )
        
        # Check for unsafe JavaScript patterns
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and 'innerHTML' in script.string:
                vulnerabilities.append(
                    Vulnerability(
                        type="Potentially Unsafe JavaScript",
                        severity="low",
                        description="JavaScript inline com innerHTML assignment",
                        location=url,
                    )
                )
                
        return vulnerabilities
    
    def _scan_csrf(self, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """CSRF protection verification"""
        vulnerabilities = []
        
        forms = soup.find_all('form')
        for form in forms:
            method = form.get('method', 'get').lower()
            if method == 'post':
                # Check for CSRF tokens
                csrf_tokens = form.find_all('input', {
                    'name': re.compile(r'.*csrf.*|.*token.*|.*_token.*', re.I)
                })
                if not csrf_tokens:
                    vulnerabilities.append(
                        Vulnerability(
                            type="Missing CSRF Protection",
                            severity="high",
                            description="POST form without CSRF protection detected",
                            location=url,
                        )
                    )
                    
        return vulnerabilities
    
    def _scan_injection(self, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """SQL/Command injection detection"""
        vulnerabilities = []
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'select', 'textarea'])
            suspicious_params = []
            
            for input_tag in inputs:
                name = input_tag.get('name', '')
                if any(keyword in name.lower() for keyword in ['id', 'user', 'admin', 'sql', 'cmd', 'exec']):
                    suspicious_params.append(name)
            
            if suspicious_params:
                vulnerabilities.append(
                    Vulnerability(
                        type="SQL Injection Risk",
                        severity="high",
                        description=f"Form with potentially vulnerable parameters: {', '.join(suspicious_params)}",
                        location=url,
                    )
                )
                
        return vulnerabilities
    
    def _scan_nosql_injection(self, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """NoSQL injection detection"""
        vulnerabilities = []
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'select', 'textarea'])
            suspicious_params = []
            
            for input_tag in inputs:
                name = input_tag.get('name', '')
                input_type = input_tag.get('type', '')
                
                # NoSQL specific parameters
                nosql_patterns = ['mongo', 'document', 'collection', 'query', 'filter', 
                                'match', 'aggregate', 'pipeline', 'find', 'search', 
                                'json', 'bson', 'redis', 'key', 'hash']
                
                if any(keyword in name.lower() for keyword in nosql_patterns):
                    suspicious_params.append(name)
                elif input_type == 'hidden' and '$' in input_tag.get('value', ''):
                    suspicious_params.append(f"{name} (MongoDB operator detected)")
                elif 'json' in input_tag.get('class', []) or 'document' in input_tag.get('class', []):
                    suspicious_params.append(f"{name} (JSON/Document input)")
            
            if suspicious_params:
                vulnerabilities.append(
                    Vulnerability(
                        type="NoSQL Injection Risk",
                        severity="high",
                        description=f"Form with potentially vulnerable NoSQL parameters: {', '.join(suspicious_params)}. Note: This indicates possible NoSQL database usage.",
                        location=url,
                    )
                )
        
        # Check for exposed MongoDB/Redis endpoints or configurations
        scripts = soup.find_all('script')
        for script in scripts:
            script_text = script.get_text()
            if any(pattern in script_text.lower() for pattern in ['mongodb://', 'redis://', '$gt', '$lt', '$ne', '$in', '$or']):
                vulnerabilities.append(
                    Vulnerability(
                        type="NoSQL Configuration Exposure",
                        severity="medium",
                        description="NoSQL connection strings or operators found in client-side code",
                        location=url,
                    )
                )
                break
                
        return vulnerabilities
    
    def _scan_injection_smart(self, soup: BeautifulSoup, url: str, context: Dict[str, Any]) -> List[Vulnerability]:
        """Enhanced SQL/Command injection detection with context awareness"""
        vulnerabilities = []
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'select', 'textarea'])
            suspicious_params = []
            
            for input_tag in inputs:
                name = input_tag.get('name', '')
                input_type = input_tag.get('type', '')
                
                # Context-aware parameter analysis
                is_wordpress_param = any(wp_indicator in name.lower() for wp_indicator in [
                    'post_id', 'form_id', 'page_id', 'wp_', '_wp', 'wpcf7', 'elementor'
                ])
                
                # Real SQL injection indicators vs WordPress parameters
                real_sql_indicators = ['id', 'user_id', 'admin_id', 'search', 'query', 'sql', 'cmd', 'exec']
                has_real_sql_risk = any(keyword in name.lower() for keyword in real_sql_indicators)
                
                # Determine if this is a real threat based on context
                if has_real_sql_risk:
                    if context['is_wordpress'] and is_wordpress_param:
                        # WordPress parameter - check if there's actual database evidence
                        if context['has_database_evidence'] or name.lower() in ['id', 'user_id', 'search']:
                            # Only flag if there's strong evidence of database interaction
                            suspicious_params.append(name)
                    else:
                        # Non-WordPress or real SQL parameters
                        suspicious_params.append(name)
            
            if suspicious_params:
                # Adjust severity based on context
                severity = "medium" if context['is_wordpress'] else "high"
                
                # Add context-specific description
                if context['is_wordpress']:
                    description = f"WordPress form parameters may be vulnerable to SQL injection: {', '.join(suspicious_params)}. Note: WordPress uses MySQL database for content management."
                else:
                    description = f"Form with potentially vulnerable parameters: {', '.join(suspicious_params)}"
                
                vulnerabilities.append(
                    Vulnerability(
                        type="SQL Injection Risk",
                        severity=severity,
                        description=description,
                        location=url,
                    )
                )
                
        return vulnerabilities
    
    def _scan_nosql_injection_smart(self, soup: BeautifulSoup, url: str, context: Dict[str, Any]) -> List[Vulnerability]:
        """Enhanced NoSQL injection detection with context awareness"""
        vulnerabilities = []
        
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all(['input', 'select', 'textarea'])
            suspicious_params = []
            
            for input_tag in inputs:
                name = input_tag.get('name', '')
                input_type = input_tag.get('type', '')
                
                # WordPress-specific NoSQL false positives
                wordpress_nosql_false_positives = [
                    '_wpcf7_posted_data_hash', '_wpnonce', '_wp_http_referer'
                ]
                
                # Real NoSQL injection indicators
                real_nosql_patterns = ['mongo', 'document', 'collection', 'query', 'filter', 
                                     'match', 'aggregate', 'pipeline', 'find', 'search', 
                                     'json', 'bson', 'redis', 'key', 'hash']
                
                is_wordpress_nosql_param = name in wordpress_nosql_false_positives
                has_real_nosql_risk = any(keyword in name.lower() for keyword in real_nosql_patterns)
                
                # Context-aware detection
                if context['is_wordpress'] and is_wordpress_nosql_param:
                    # WordPress security parameter - not a real NoSQL injection risk
                    continue
                elif has_real_nosql_risk:
                    suspicious_params.append(name)
                elif input_type == 'hidden' and '$' in input_tag.get('value', ''):
                    # Check if it's actually MongoDB operators, not WordPress data
                    if not context['is_wordpress']:
                        suspicious_params.append(f"{name} (MongoDB operator detected)")
                elif 'json' in input_tag.get('class', []) or 'document' in input_tag.get('class', []):
                    suspicious_params.append(f"{name} (JSON/Document input)")
            
            if suspicious_params:
                # Adjust severity based on context and evidence
                severity = "medium" if context['is_wordpress'] else "high"
                
                # Add context-specific description
                if context['is_wordpress']:
                    description = f"WordPress form contains NoSQL-like parameters: {', '.join(suspicious_params)}. Note: WordPress typically uses MySQL, but plugins may use NoSQL databases."
                else:
                    description = f"Form with potentially vulnerable NoSQL parameters: {', '.join(suspicious_params)}"
                
                vulnerabilities.append(
                    Vulnerability(
                        type="NoSQL Injection Risk",
                        severity=severity,
                        description=description,
                        location=url,
                    )
                )
        
        # Check for exposed MongoDB/Redis endpoints or configurations
        scripts = soup.find_all('script')
        for script in scripts:
            script_text = script.get_text()
            if any(pattern in script_text.lower() for pattern in ['mongodb://', 'redis://', '$gt', '$lt', '$ne', '$in', '$or']):
                # Only flag if not WordPress (WordPress uses $ for jQuery, not MongoDB)
                if not context['is_wordpress'] or any(real_db in script_text.lower() for real_db in ['mongodb://', 'redis://']):
                    vulnerabilities.append(
                        Vulnerability(
                            type="NoSQL Configuration Exposure",
                            severity="medium",
                            description="NoSQL connection strings or operators found in client-side code",
                            location=url,
                            )
                    )
                    break
                
        return vulnerabilities
    
    def _scan_broken_pages(self, url: str) -> List[Vulnerability]:
        """404/offline pages and broken links detection"""
        vulnerabilities = []
        
        try:
            response = requests.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Find all internal links
            links = soup.find_all('a', href=True)
            buttons = soup.find_all(['button', 'input'], {'type': ['button', 'submit']})
            
            broken_links = []
            inactive_elements = []
            
            for link in links[:20]:  # Limit to first 20 links to avoid timeout
                href = link.get('href')
                if href and href.startswith(('http://', 'https://', '/')):
                    # Make it absolute URL if relative
                    if href.startswith('/'):
                        from urllib.parse import urljoin
                        href = urljoin(url, href)
                    
                    try:
                        # Use GET with stream=True instead of HEAD to avoid blocking
                        link_response = requests.get(href, timeout=5, allow_redirects=True, stream=True)
                        # Only read headers, don't download content
                        link_response.close()
                        if link_response.status_code >= 400:
                            broken_links.append(f"{href} ({link_response.status_code})")
                    except:
                        broken_links.append(f"{href} (unreachable)")
            
            # Check for buttons without proper onclick/action
            for button in buttons:
                onclick = button.get('onclick', '')
                form_parent = button.find_parent('form')
                
                if not onclick and not form_parent and button.get('type') != 'submit':
                    button_text = button.get_text(strip=True) or button.get('value', 'Unknown button')
                    inactive_elements.append(button_text)
            
            if broken_links:
                vulnerabilities.append(
                    Vulnerability(
                        type="Broken Links/Pages",
                        severity="medium",
                        description=f"Found {len(broken_links)} broken links that return 404/errors",
                        location=url,
                    )
                )
            
            if inactive_elements:
                vulnerabilities.append(
                    Vulnerability(
                        type="Inactive UI Elements",
                        severity="low",
                        description=f"Found {len(inactive_elements)} buttons/elements without proper functionality",
                        location=url,
                    )
                )
                
        except Exception as e:
            vulnerabilities.append(
                Vulnerability(
                    type="Page Analysis Error",
                    severity="low",
                    description=f"Could not fully analyze page structure: {str(e)}",
                    location=url,
                )
            )
                
        return vulnerabilities
    
    def _scan_headers(self, response: requests.Response, url: str) -> List[Vulnerability]:
        """Security headers analysis"""
        vulnerabilities = []
        headers = response.headers
        
        security_headers = {
            'X-Frame-Options': 'Missing X-Frame-Options - Clickjacking risk',
            'X-Content-Type-Options': 'Missing X-Content-Type-Options - MIME sniffing',
            'X-XSS-Protection': 'Missing X-XSS-Protection - XSS protection',
            'Content-Security-Policy': 'Missing Content-Security-Policy - Script injection risk',
            'Strict-Transport-Security': 'Missing HSTS Header - HTTPS downgrade attacks'
        }
        
        for header, description in security_headers.items():
            if header not in headers:
                severity = "high" if header in ['Content-Security-Policy'] else "medium"
                vulnerabilities.append(
                    Vulnerability(
                        type=f"Missing {header}",
                        severity=severity,
                        description=description,
                        location=url
                    )
                )
        
        # Check if HTTPS site has HSTS
        if url.startswith('https://') and 'Strict-Transport-Security' not in headers:
            vulnerabilities.append(
                Vulnerability(
                    type="Missing HSTS Header",
                    severity="medium",
                    description="HTTPS site without HTTP Strict Transport Security",
                    location=url
                )
            )
            
        return vulnerabilities
    
    def _scan_info_disclosure(self, response: requests.Response, url: str) -> List[Vulnerability]:
        """Information disclosure detection"""
        vulnerabilities = []
        content = response.text.lower()
        
        # Check for exposed information
        disclosure_patterns = {
            'function': 'Function definition',
            'error': 'Error message',
            'debug': 'Debug information',
            'stack trace': 'Stack trace',
            'mysql': 'Database error'
        }
        
        for pattern, description in disclosure_patterns.items():
            if pattern in content:
                vulnerabilities.append(
                    Vulnerability(
                        type="Source Code in Response",
                        severity="low",
                        description=f"Response contains {description}",
                        location=url
                    )
                )
                break  # Avoid duplicates
                
        return vulnerabilities
    
    def _scan_authentication(self, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """Authentication security analysis"""
        vulnerabilities = []
        
        # Look for login forms with weak patterns
        forms = soup.find_all('form')
        for form in forms:
            inputs = form.find_all('input')
            has_password = any(inp.get('type') == 'password' for inp in inputs)
            
            if has_password:
                # Check for missing password requirements
                password_input = next((inp for inp in inputs if inp.get('type') == 'password'), None)
                if password_input and not password_input.get('pattern'):
                    vulnerabilities.append(
                        Vulnerability(
                            type="Weak Password Policy",
                            severity="medium", 
                            description="Password field without pattern validation",
                            location=url
                        )
                    )
                    
        return vulnerabilities
    
    def _scan_access_control(self, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """Access control verification"""
        vulnerabilities = []
        
        # Check for directory listing indicators
        if 'index of' in soup.get_text().lower():
            vulnerabilities.append(
                Vulnerability(
                    type="Directory Listing",
                    severity="medium",
                    description="Directory listing detected",
                    location=url
                )
            )
            
        return vulnerabilities
    
    def _scan_file_upload(self, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """File upload security analysis"""
        vulnerabilities = []
        
        # Check for file upload forms
        file_inputs = soup.find_all('input', {'type': 'file'})
        for file_input in file_inputs:
            if not file_input.get('accept'):
                vulnerabilities.append(
                    Vulnerability(
                        type="Unrestricted File Upload",
                        severity="high",
                        description="File upload without type restrictions",
                        location=url
                    )
                )
        
        # Check for redirect patterns in JavaScript
        scripts = soup.find_all('script')
        for script in scripts:
            if script.string and any(word in script.string for word in ['location.href', 'window.location', 'redirect']):
                vulnerabilities.append(
                    Vulnerability(
                        type="Potential Redirect in JavaScript",
                        severity="low",
                        description="JavaScript contains redirect functionality that might be exploitable",
                        location=url
                    )
                )
                break
                
        return vulnerabilities
    
    def _scan_tech_stack(self, response, soup: BeautifulSoup, url: str) -> List[Vulnerability]:
        """Technology Stack Fingerprinting"""
        vulnerabilities = []
        tech_info = []
        
        # Server headers
        server = response.headers.get('Server', '')
        if server:
            tech_info.append(f"Server: {server}")
            # Check for outdated/vulnerable server versions
            if any(old_version in server.lower() for old_version in ['apache/2.2', 'nginx/1.0', 'iis/6.0']):
                vulnerabilities.append(
                    Vulnerability(
                        type="Outdated Server Version",
                        severity="medium",
                        description=f"Potentially outdated server version detected: {server}",
                        location=url,
                    )
                )
        
        # X-Powered-By header
        powered_by = response.headers.get('X-Powered-By', '')
        if powered_by:
            tech_info.append(f"Powered-By: {powered_by}")
            vulnerabilities.append(
                Vulnerability(
                    type="Information Disclosure in Headers",
                    severity="low",
                    description=f"X-Powered-By header reveals technology: {powered_by}",
                    location=url,
                )
            )
        
        # Framework detection in HTML
        html_content = soup.get_text().lower()
        frameworks = {
            'wordpress': ['wp-content', 'wp-includes', 'wp-admin'],
            'drupal': ['drupal', 'sites/default'],
            'joomla': ['joomla', 'administrator'],
            'django': ['django', 'csrfmiddlewaretoken'],
            'laravel': ['laravel_session', '_token'],
            'react': ['react', 'react-dom'],
            'angular': ['angular', 'ng-app'],
            'vue': ['vue.js', 'v-for', 'v-if']
        }
        
        for framework, indicators in frameworks.items():
            if any(indicator in html_content for indicator in indicators):
                tech_info.append(f"Framework: {framework.title()}")
        
        # META tags analysis
        meta_tags = soup.find_all('meta')
        for meta in meta_tags:
            generator = meta.get('name')
            if generator == 'generator':
                content = meta.get('content', '')
                if content:
                    tech_info.append(f"Generator: {content}")
                    vulnerabilities.append(
                        Vulnerability(
                            type="Technology Disclosure in Meta Tags",
                            severity="low",
                            description=f"Meta generator reveals technology: {content}",
                            location=url,
                        )
                    )
        
        # JavaScript libraries detection
        script_tags = soup.find_all('script', src=True)
        js_libraries = []
        for script in script_tags:
            src = script.get('src', '')
            if 'jquery' in src.lower():
                js_libraries.append('jQuery')
            elif 'bootstrap' in src.lower():
                js_libraries.append('Bootstrap')
            elif 'angular' in src.lower():
                js_libraries.append('Angular')
            elif 'react' in src.lower():
                js_libraries.append('React')
        
        if js_libraries:
            tech_info.append(f"JS Libraries: {', '.join(js_libraries)}")
        
        # Add technology stack as informational finding
        if tech_info:
            vulnerabilities.append(
                Vulnerability(
                    type="Technology Stack Detected",
                    severity="info",
                    description=f"Detected technologies: {'; '.join(tech_info)}",
                    location=url,
                )
            )
        
        return vulnerabilities
    
    def _scan_directory_traversal(self, url: str) -> List[Vulnerability]:
        """Directory Traversal Detection"""
        vulnerabilities = []
        
        # Common sensitive paths to test
        sensitive_paths = [
            '/etc/passwd',
            '/etc/hosts',
            '/etc/shadow',
            '/.env',
            '/.git/',
            '/.git/config',
            '/config.json',
            '/admin/',
            '/administrator/',
            '/wp-admin/',
            '/phpmyadmin/',
            '/backup/',
            '/logs/',
            '/test/',
            '/dev/',
            '/temp/',
            '/tmp/',
            '/uploads/',
            '/files/',
            '/private/',
            '/secret/'
        ]
        
        # Parse base URL
        parsed_url = urlparse(url)
        base_url = f"{parsed_url.scheme}://{parsed_url.netloc}"
        
        accessible_paths = []
        
        for path in sensitive_paths:
            try:
                test_url = base_url + path
                # Use GET with stream=True to avoid HEAD blocking issues
                response = self.session.get(test_url, timeout=5, allow_redirects=False, stream=True)
                response.close()  # Don't download content, just check status
                
                # Check for accessible paths (not 404, 403, etc.)
                if response.status_code in [200, 301, 302]:
                    accessible_paths.append(path)
                    
                    # Determine severity based on path sensitivity
                    severity = "high"
                    if path in ['/etc/passwd', '/etc/shadow', '/.env', '/.git/config']:
                        severity = "high"
                    elif path in ['/admin/', '/administrator/', '/wp-admin/', '/phpmyadmin/']:
                        severity = "medium"
                    else:
                        severity = "low"
                    
                    vulnerabilities.append(
                        Vulnerability(
                            type="Directory/File Accessible",
                            severity=severity,
                            description=f"Sensitive path accessible: {path} (HTTP {response.status_code})",
                            location=test_url,
                        )
                    )
                    
            except Exception:
                # Ignore connection errors for individual paths
                continue
        
        # Check for directory listing
        try:
            # Test common directories that might have listing enabled
            test_dirs = ['/uploads/', '/files/', '/images/', '/documents/', '/backup/']
            for test_dir in test_dirs:
                test_url = base_url + test_dir
                response = self.session.get(test_url, timeout=5)
                
                if (response.status_code == 200 and 
                    ('Index of' in response.text or 
                     '<title>Directory listing' in response.text or
                     'Parent Directory' in response.text)):
                    
                    vulnerabilities.append(
                        Vulnerability(
                            type="Directory Listing Enabled",
                            severity="medium",
                            description=f"Directory listing enabled at: {test_dir}",
                            location=test_url,
                        )
                    )
                    
        except Exception:
            pass
        
        return vulnerabilities
    
    def calculate_security_score(self, vulnerabilities: List[Vulnerability], url: str = "") -> int:
        """Calculate hybrid security score: ZowTi analysis + Best Practices"""
        # Check for connection errors first
        connection_errors = [v for v in vulnerabilities if v.type == "Connection Error"]
        if connection_errors:
            return -1  # Special code for connection errors
        
        # START WITH 0 AND BUILD UP WITH POSITIVE POINTS
        base_score = 0
        vulnerability_penalties = 0
        
        # POSITIVE SECURITY MEASURES (GUARANTEED POINTS)
        if url.startswith('https://'):
            base_score += 15  # HTTPS Protocol
        
        # Check for good security headers (award points for what's present)
        missing_headers = [v for v in vulnerabilities if v.type.startswith("Missing")]
        total_possible_headers = 5  # CSP, X-Frame, X-XSS, X-Content-Type, HSTS
        headers_present = total_possible_headers - len(missing_headers)
        base_score += headers_present * 3  # 3 points per present header
        
        # Meta viewport and responsive design (basic check)
        base_score += 2  # Assume present unless detected otherwise
        
        # No critical JavaScript errors (give points if no major JS issues)
        js_errors = [v for v in vulnerabilities if 'JavaScript' in v.type and v.severity == 'high']
        if not js_errors:
            base_score += 5
        
        # CSRF Protection check (give points if forms are protected)
        csrf_issues = [v for v in vulnerabilities if 'CSRF' in v.type]
        if not csrf_issues:
            base_score += 10
        
        # XSS Protection check
        xss_issues = [v for v in vulnerabilities if 'XSS' in v.type and v.severity in ['high', 'medium']]
        if not xss_issues:
            base_score += 8
        
        # SQL Injection Protection
        sql_issues = [v for v in vulnerabilities if 'SQL' in v.type or 'Injection' in v.type]
        if not sql_issues:
            base_score += 12
        
        # Access Control
        access_issues = [v for v in vulnerabilities if 'Directory' in v.type or 'Access' in v.type]
        if not access_issues:
            base_score += 5
        
        # Info Disclosure
        info_issues = [v for v in vulnerabilities if 'Source Code' in v.type or 'Disclosure' in v.type]
        if not info_issues:
            base_score += 3
        
        # File Upload Security
        upload_issues = [v for v in vulnerabilities if 'Upload' in v.type]
        if not upload_issues:
            base_score += 5
        
        # Authentication Security
        auth_issues = [v for v in vulnerabilities if 'Password' in v.type or 'Auth' in v.type]
        if not auth_issues:
            base_score += 5
        
        # NoSQL Injection Protection (NEW MODULE)
        nosql_issues = [v for v in vulnerabilities if 'NoSQL' in v.type]
        if not nosql_issues:
            base_score += 8
        
        # Broken Pages/Links Check (NEW MODULE)
        broken_issues = [v for v in vulnerabilities if 'Broken' in v.type or 'Inactive' in v.type]
        if not broken_issues:
            base_score += 4
        
        # PENALTY SYSTEM (SEPARATE FROM BASE POINTS)
        for vuln in vulnerabilities:
            if vuln.severity == "high":
                vulnerability_penalties += 8
            elif vuln.severity == "medium":
                vulnerability_penalties += 4
            elif vuln.severity == "low":
                vulnerability_penalties += 2
        
        # FINAL SCORE = BASE POINTS - PENALTIES (but base points are protected)
        final_score = base_score - vulnerability_penalties
        
        # PURE ZOWTI SECURITY SCORING
        # Removed Best Practices integration - now handled as separate module
        
        # ENSURE MINIMUM SCORE REFLECTS BASIC SECURITY MEASURES
        # If site has HTTPS, minimum score should be at least 10
        minimum_score = 15 if url.startswith('https://') else 5
        
        return max(minimum_score, min(100, final_score))
    
    def generate_report(self, url: str, vulnerabilities: List[Vulnerability]) -> Dict[str, Any]:
        """Generate formatted security report"""
        score = self.calculate_security_score(vulnerabilities, url)
        
        # Handle connection errors
        if score == -1:
            connection_errors = [v for v in vulnerabilities if v.type == "Connection Error"]
            return {
                "target": url,
                "security_score": "N/A",
                "risk_level": "CONNECTION_ERROR",
                "total_vulnerabilities": 0,
                "vulnerabilities": {
                    "critical_high": [],
                    "medium": [],
                    "low": []
                },
                "connection_error": connection_errors[0].description if connection_errors else "Unknown connection error",
                "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
            }
        
        # Categorize vulnerabilities
        critical_high = [v for v in vulnerabilities if v.severity == "high"]
        medium = [v for v in vulnerabilities if v.severity == "medium"] 
        low = [v for v in vulnerabilities if v.severity == "low"]
        
        # Filter out 'info' severity vulnerabilities from count
        counted_vulnerabilities = [v for v in vulnerabilities if v.severity in ["high", "medium", "low"]]
        
        risk_level = "LOW"
        if len(critical_high) > 0:
            risk_level = "CRITICAL"
        elif len(medium) > 2:
            risk_level = "HIGH"
        elif len(medium) > 0:
            risk_level = "MEDIUM"
            
        return {
            "target": url,
            "security_score": score,
            "risk_level": risk_level,
            "total_vulnerabilities": len(counted_vulnerabilities),
            "vulnerabilities": {
                "critical_high": [{"type": v.type, "description": v.description} for v in critical_high],
                "medium": [{"type": v.type, "description": v.description} for v in medium],
                "low": [{"type": v.type, "description": v.description} for v in low]
            },
            "scan_timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def get_risk_level(self, vulnerabilities: List[Vulnerability]) -> str:
        """Get risk level based on vulnerabilities"""
        if not vulnerabilities:
            return "LOW"
        
        severity_counts = self.get_vulnerabilities_by_severity(vulnerabilities)
        
        if severity_counts.get('critical', 0) > 0:
            return "CRITICAL"
        elif severity_counts.get('high', 0) >= 3:
            return "CRITICAL"
        elif severity_counts.get('high', 0) > 0:
            return "HIGH"
        elif severity_counts.get('medium', 0) >= 5:
            return "HIGH"
        elif severity_counts.get('medium', 0) > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def get_vulnerabilities_by_severity(self, vulnerabilities: List[Vulnerability]) -> Dict[str, int]:
        """Get vulnerability count by severity"""
        by_severity = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        
        for vuln in vulnerabilities:
            severity = vuln.severity.lower()
            if severity in by_severity:
                by_severity[severity] += 1
        
        return by_severity
    
    def _scan_best_practices(self, url: str) -> List[Vulnerability]:
        """
        Best Practices Analysis Module - Security Enhancement
        
        Senior Engineering: Integrate industry best practices validation
        Convert Best Practices issues to vulnerability format for unified reporting
        """
        vulnerabilities = []
        
        try:
            # Import the Best Practices function from app.py
            from app import get_pagespeed_best_practices_data
            
            # Get Best Practices data
            best_practices_data = get_pagespeed_best_practices_data(url)
            
            # Handle API errors
            if 'error' in best_practices_data:
                vulnerabilities.append(
                    Vulnerability(
                        type="Best Practices: API Error",
                        severity="info",
                        description=f"Unable to get Best Practices data: {best_practices_data['error']}",
                        location="Best Practices Analysis",
                    )
                )
                return vulnerabilities
            
            # Convert Best Practices issues to vulnerability format
            for issue in best_practices_data.get('issues', []):
                # Map Best Practices severity to vulnerability severity  
                severity_mapping = {
                    'high': 'medium',        # High BP issues are medium security priority
                    'medium': 'low',         # Medium BP issues are low security priority
                    'low': 'info'           # Low BP issues are informational
                }
                
                vulnerabilities.append(
                    Vulnerability(
                        type=f"Best Practices: {issue.get('type', 'Security Issue')}",
                        severity=severity_mapping.get(issue.get('severity', 'low'), 'info'),
                        description=issue.get('description', 'Security best practice issue detected'),
                        location="Security Best Practices Analysis",
                    )
                )
            
            # Add overall Best Practices score if low
            best_practices_score = best_practices_data.get('best_practices_score', 100)
            if best_practices_score < 80:
                vulnerabilities.append(
                    Vulnerability(
                        type="Best Practices: Low Security Score",
                        severity="low",
                        description=f"Security best practices score is {best_practices_score}/100 (below recommended 80+)",
                        location="Overall security posture",
                    )
                )
                
        except Exception as e:
            vulnerabilities.append(
                Vulnerability(
                    type="Best Practices Analysis Error",
                    severity="info",
                    description=f"Security best practices analysis failed: {str(e)}",
                    location="Security Module",
                )
            )
        
        return vulnerabilities
    
    def _scan_seo(self, url: str, response, soup: BeautifulSoup) -> List[Vulnerability]:
        """
        SEO Analysis Module - Google PageSpeed Integration
        
        Senior Engineering: Use Google PageSpeed API for consistent scoring
        Convert Google SEO issues to vulnerability format for unified reporting
        """
        vulnerabilities = []
        
        try:
            # Import the Google PageSpeed SEO function from app.py
            from app import get_pagespeed_seo_data
            
            # Get SEO data from Google PageSpeed API
            seo_data = get_pagespeed_seo_data(url)
            
            # Handle API errors
            if 'error' in seo_data:
                vulnerabilities.append(
                    Vulnerability(
                        type="SEO: API Error",
                        severity="info",
                        description=f"Unable to get Google PageSpeed SEO data: {seo_data['error']}",
                        location="Google PageSpeed API",
                    )
                )
                return vulnerabilities
            
            # Convert Google PageSpeed SEO issues to vulnerability format
            for issue in seo_data.get('issues', []):
                # Map Google PageSpeed severity to vulnerability severity
                severity_mapping = {
                    'high': 'medium',        # High SEO issues are medium security priority
                    'medium': 'low',         # Medium SEO issues are low security priority
                    'low': 'info'           # Low SEO issues are informational
                }
                
                vulnerabilities.append(
                    Vulnerability(
                        type=f"SEO: {issue.get('type', 'Optimization Issue')}",
                        severity=severity_mapping.get(issue.get('severity', 'low'), 'info'),
                        description=issue.get('description', 'SEO optimization issue detected'),
                        location="Google PageSpeed Analysis",
                    )
                )
            
            # Add SEO score as informational finding if score is low
            seo_score = seo_data.get('seo_score', 100)
            if seo_score < 70:
                vulnerabilities.append(
                    Vulnerability(
                        type="SEO: Low Optimization Score",
                        severity="low",
                        description=f"SEO score is {seo_score}/100 (below recommended 70+)",
                        location="Overall page",
                    )
                )
                
        except Exception as e:
            vulnerabilities.append(
                Vulnerability(
                    type="SEO Analysis Error",
                    severity="info",
                    description=f"SEO analysis failed: {str(e)}",
                    location="SEO Module",
                )
            )
        
        return vulnerabilities


# Color formatting for better presentation
class Colors:
    """ANSI color codes for terminal output"""
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    
    # Risk level colors
    CRITICAL = '\033[95m'  # Magenta
    HIGH = '\033[91m'     # Red
    MEDIUM = '\033[93m'   # Yellow
    LOW = '\033[92m'      # Green
    
    @staticmethod
    def disable():
        """Disable colors (for Windows or when needed)"""
        Colors.HEADER = ''
        Colors.OKBLUE = ''
        Colors.OKCYAN = ''
        Colors.OKGREEN = ''
        Colors.WARNING = ''
        Colors.FAIL = ''
        Colors.ENDC = ''
        Colors.BOLD = ''
        Colors.UNDERLINE = ''
        Colors.CRITICAL = ''
        Colors.HIGH = ''
        Colors.MEDIUM = ''
        Colors.LOW = ''

def print_banner():
    """Print professional banner"""
    banner = f"""{Colors.OKCYAN}{Colors.BOLD}
╔══════════════════════════════════════════════════════════════╗
║                        🛡️  ZowTiScan v2.0                    ║
║                    Professional Security Scanner              ║
║                      🔍 Scanning in progress...              ║
╚══════════════════════════════════════════════════════════════╝{Colors.ENDC}
"""
    print(banner)

def get_risk_emoji(risk_level):
    """Get emoji for risk level"""
    risk_emojis = {
        'CRITICAL': '🚨',
        'HIGH': '⚠️',
        'MEDIUM': '⚡',
        'LOW': '✅',
        'CONNECTION_ERROR': '❌'
    }
    return risk_emojis.get(risk_level, '❓')

def get_risk_color(risk_level):
    """Get color for risk level"""
    risk_colors = {
        'CRITICAL': Colors.CRITICAL,
        'HIGH': Colors.HIGH,
        'MEDIUM': Colors.MEDIUM,
        'LOW': Colors.LOW,
        'CONNECTION_ERROR': Colors.FAIL
    }
    return risk_colors.get(risk_level, '')

def format_score_display(score, risk_level):
    """Format security score with colors and styling"""
    emoji = get_risk_emoji(risk_level)
    color = get_risk_color(risk_level)
    
    if score == 'N/A':
        return f"{Colors.FAIL}❌ Connection Error{Colors.ENDC}"
    
    score_bar = "█" * (score // 10) + "░" * (10 - score // 10)
    return f"{color}{emoji} Security Score: {score}/100{Colors.ENDC} {Colors.BOLD}[{score_bar}]{Colors.ENDC} {color}({risk_level}){Colors.ENDC}"

def print_vulnerability_section(title, vulnerabilities, color, icon):
    """Print formatted vulnerability section"""
    if not vulnerabilities:
        return
        
    print(f"\n{color}{Colors.BOLD}{icon} {title.upper()} ISSUES:{Colors.ENDC}")
    print(f"{color}{'─' * 50}{Colors.ENDC}")
    
    for i, vuln in enumerate(vulnerabilities, 1):
        print(f"{color}  {i:2d}.{Colors.ENDC} {Colors.BOLD}{vuln['type']}{Colors.ENDC}")
        print(f"      {vuln['description']}")
        print()

def main():
    """CLI interface for ZowTiScan"""
    # Fix Windows console encoding completely
    import sys
    import os
    if sys.platform.startswith('win'):
        os.system('chcp 65001 >nul 2>&1')  # Set console to UTF-8
        import codecs
        sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'replace')
        sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'replace')
        # Disable colors on Windows for better compatibility
        Colors.disable()
    
    parser = argparse.ArgumentParser(description='ZowTiScan - Professional Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--modules', '-m', 
                       choices=['xss', 'csrf', 'injection', 'nosql_injection', 'broken_pages', 'headers', 'info_disclosure', 'authentication', 'access_control', 'file_upload', 'tech_stack', 'directory_traversal', 'all'],
                       nargs='+', default=['all'],
                       help='Security modules to run')
    parser.add_argument('--format', '-f', choices=['json', 'text'], default='text',
                       help='Output format')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')
    
    args = parser.parse_args()
    
    if args.no_color:
        Colors.disable()
    
    if 'all' in args.modules:
        modules = ['xss', 'csrf', 'injection', 'nosql_injection', 'broken_pages', 'headers', 'info_disclosure', 'authentication', 'access_control', 'file_upload', 'tech_stack', 'directory_traversal', 'seo']
    else:
        modules = args.modules
    
    # Print banner for text format
    if args.format == 'text':
        print_banner()
        print(f"{Colors.OKCYAN}🌐 Target:{Colors.ENDC} {Colors.BOLD}{args.url}{Colors.ENDC}")
        print(f"{Colors.OKCYAN}🔍 Modules:{Colors.ENDC} {len(modules)} security modules")
        print(f"{Colors.OKCYAN}⏱️  Starting analysis...{Colors.ENDC}")
        print()
    
    scanner = SecurityScanner()
    start_time = time.time()
    
    vulnerabilities = scanner.scan_url(args.url, modules)
    duration = time.time() - start_time
    
    if args.format == 'json':
        report = scanner.generate_report(args.url, vulnerabilities)
        report['scan_duration'] = round(duration, 2)
        print(json.dumps(report, indent=2))
    else:
        # Enhanced text format
        report = scanner.generate_report(args.url, vulnerabilities)
        
        # Handle connection errors
        if 'connection_error' in report:
            print(f"{Colors.FAIL}❌ CONNECTION ERROR:{Colors.ENDC}")
            print(f"   {report['connection_error']}")
            return
        
        print(f"{Colors.OKGREEN}{'═' * 70}{Colors.ENDC}")
        print(f"{Colors.BOLD}📊 SCAN RESULTS{Colors.ENDC}")
        print(f"{Colors.OKGREEN}{'═' * 70}{Colors.ENDC}")
        print()
        
        # Security score with visual bar
        print(format_score_display(report['security_score'], report['risk_level']))
        
        # Vulnerability summary
        total_vulns = report['total_vulnerabilities']
        vuln_emoji = "🔐" if total_vulns == 0 else "⚠️"
        print(f"{Colors.OKCYAN}{vuln_emoji} Vulnerabilities found:{Colors.ENDC} {Colors.BOLD}{total_vulns} issues{Colors.ENDC}")
        
        # Scan info
        print(f"{Colors.OKCYAN}📋 Scan duration:{Colors.ENDC} {Colors.BOLD}{duration:.2f} seconds{Colors.ENDC}")
        print(f"{Colors.OKCYAN}🔍 Modules analyzed:{Colors.ENDC} {Colors.BOLD}{len(modules)} security checks{Colors.ENDC}")
        
        # Module status indicator
        status_color = Colors.OKGREEN if total_vulns == 0 else Colors.WARNING
        status_icon = "✅" if total_vulns == 0 else "📊"
        print(f"{status_color}{status_icon} Analysis complete!{Colors.ENDC}")
        
        # Professional footer
        if args.format == 'text':
            print(f"\n{Colors.OKCYAN}📄 Professional report generated{Colors.ENDC}")
            if total_vulns > 0:
                print(f"{Colors.OKCYAN}📊 JSON data available with --format json{Colors.ENDC}")
            print(f"{Colors.OKCYAN}🚀 Powered by ZowTiScan Security Framework{Colors.ENDC}")
        
        # Vulnerability sections
        print_vulnerability_section(
            "🚨 Critical/High", 
            report['vulnerabilities']['critical_high'], 
            Colors.CRITICAL, 
            "🚨"
        )
        
        print_vulnerability_section(
            "⚠️ Medium", 
            report['vulnerabilities']['medium'], 
            Colors.MEDIUM, 
            "⚠️"
        )
        
        print_vulnerability_section(
            "⚡ Low", 
            report['vulnerabilities']['low'], 
            Colors.LOW, 
            "⚡"
        )
        
        # Final separator
        print(f"\n{Colors.OKGREEN}{'═' * 70}{Colors.ENDC}")


if __name__ == "__main__":
    main()