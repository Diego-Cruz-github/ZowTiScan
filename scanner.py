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
    """Professional security scanner with 8 detection modules"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZowTiScan/1.0 (Security Scanner)'
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
                response = self.session.head(test_url, timeout=10, allow_redirects=True)
                if response.status_code < 400:
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
        
    def scan_url(self, url: str, modules: List[str] = None) -> List[Vulnerability]:
        """Main scanning function with smart URL detection"""
        if modules is None:
            modules = ['xss', 'csrf', 'injection', 'nosql_injection', 'broken_pages', 'headers', 'info_disclosure', 'authentication', 'access_control', 'file_upload']
            
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
            
            for module in modules:
                if module == 'xss':
                    vulnerabilities.extend(self._scan_xss(soup, url))
                elif module == 'csrf':
                    vulnerabilities.extend(self._scan_csrf(soup, url))
                elif module == 'injection':
                    vulnerabilities.extend(self._scan_injection(soup, url))
                elif module == 'nosql_injection':
                    vulnerabilities.extend(self._scan_nosql_injection(soup, url))
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
                        evidence=str(input_tag)[:100]
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
                        evidence=script.string[:100]
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
                            evidence=str(form)[:200]
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
                        evidence=str(form)[:200]
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
                        description=f"Form with potentially vulnerable NoSQL parameters: {', '.join(suspicious_params)}",
                        location=url,
                        evidence=str(form)[:200]
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
                        evidence=script_text[:150]
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
                        link_response = requests.head(href, timeout=5, allow_redirects=True)
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
                        evidence="; ".join(broken_links[:5])  # Show first 5
                    )
                )
            
            if inactive_elements:
                vulnerabilities.append(
                    Vulnerability(
                        type="Inactive UI Elements",
                        severity="low",
                        description=f"Found {len(inactive_elements)} buttons/elements without proper functionality",
                        location=url,
                        evidence="; ".join(inactive_elements[:5])
                    )
                )
                
        except Exception as e:
            vulnerabilities.append(
                Vulnerability(
                    type="Page Analysis Error",
                    severity="low",
                    description=f"Could not fully analyze page structure: {str(e)}",
                    location=url,
                    evidence=""
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
    
    def calculate_security_score(self, vulnerabilities: List[Vulnerability], url: str = "") -> int:
        """Calculate security score based on vulnerabilities and positive security measures"""
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
    
    parser = argparse.ArgumentParser(description='ZowTiScan - Professional Security Scanner')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--modules', '-m', 
                       choices=['xss', 'csrf', 'injection', 'nosql_injection', 'broken_pages', 'headers', 'info_disclosure', 'authentication', 'access_control', 'file_upload', 'all'],
                       nargs='+', default=['all'],
                       help='Security modules to run')
    parser.add_argument('--format', '-f', choices=['json', 'text'], default='text',
                       help='Output format')
    
    args = parser.parse_args()
    
    if 'all' in args.modules:
        modules = ['xss', 'csrf', 'injection', 'nosql_injection', 'broken_pages', 'headers', 'info_disclosure', 'authentication', 'access_control', 'file_upload']
    else:
        modules = args.modules
    
    scanner = SecurityScanner()
    start_time = time.time()
    
    print(f"ZowTiScan - Scanning {args.url}")
    print("=" * 60)
    
    vulnerabilities = scanner.scan_url(args.url, modules)
    duration = time.time() - start_time
    
    if args.format == 'json':
        report = scanner.generate_report(args.url, vulnerabilities)
        report['scan_duration'] = round(duration, 2)
        print(json.dumps(report, indent=2))
    else:
        # Text format (like your example)
        report = scanner.generate_report(args.url, vulnerabilities)
        
        print(f"Security Score: {report['security_score']}/100 ({report['risk_level']})")
        print(f"Vulnerabilities found: {report['total_vulnerabilities']} issues")
        print(f"Scan duration: {duration:.2f} seconds")
        print()
        
        if report['vulnerabilities']['critical_high']:
            print("CRITICAL/HIGH:")
            for i, vuln in enumerate(report['vulnerabilities']['critical_high'], 1):
                print(f"{i}. {vuln['type']} - {vuln['description']}")
            print()
            
        if report['vulnerabilities']['medium']:
            print("MEDIUM:")
            for i, vuln in enumerate(report['vulnerabilities']['medium'], len(report['vulnerabilities']['critical_high']) + 1):
                print(f"{i}. {vuln['type']} - {vuln['description']}")
            print()
            
        if report['vulnerabilities']['low']:
            print("LOW:")
            for i, vuln in enumerate(report['vulnerabilities']['low'], len(report['vulnerabilities']['critical_high']) + len(report['vulnerabilities']['medium']) + 1):
                print(f"{i}. {vuln['type']} - {vuln['description']}")


if __name__ == "__main__":
    main()