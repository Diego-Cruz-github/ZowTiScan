#!/usr/bin/env python3
"""
Real unit tests for ZowTiScan SecurityScanner
Using pytest framework
"""

import pytest
import requests
import requests_mock
from scanner import SecurityScanner, Vulnerability


@pytest.fixture
def scanner():
    """Create scanner instance for testing"""
    return SecurityScanner()


@pytest.fixture
def sample_html():
    """Sample HTML with vulnerabilities for testing"""
    return """
    <!DOCTYPE html>
    <html>
    <head><title>Test Site</title></head>
    <body>
        <form method="post" action="/submit">
            <input type="text" name="username" />
            <input type="password" name="password" />
            <input type="hidden" name="post_id" value="123" />
            <input type="submit" value="Submit" />
        </form>
        
        <form method="post" action="/comment">
            <input type="text" name="comment" />
            <textarea name="message"></textarea>
            <input type="submit" value="Post" />
        </form>
        
        <script>
            function updateContent() {
                document.getElementById('content').innerHTML = userInput;
            }
        </script>
        
        <input type="file" name="upload" />
    </body>
    </html>
    """


class TestSecurityScanner:
    """Test cases for SecurityScanner class"""
    
    def test_scanner_initialization(self, scanner):
        """Test scanner initializes correctly"""
        assert scanner is not None
        assert hasattr(scanner, 'session')
        assert scanner.session.headers['User-Agent'] == 'ZowTiScan/1.0 (Security Scanner)'
    
    def test_xss_detection(self, scanner, sample_html):
        """Test XSS vulnerability detection"""
        with requests_mock.Mocker() as m:
            m.get('http://test.com', text=sample_html)
            
            vulnerabilities = scanner.scan_url('http://test.com', ['xss'])
            
            # Should find XSS vulnerabilities
            xss_vulns = [v for v in vulnerabilities if 'XSS' in v.type]
            assert len(xss_vulns) > 0
            
            # Should find unsafe JavaScript
            js_vulns = [v for v in vulnerabilities if 'JavaScript' in v.type]
            assert len(js_vulns) > 0
    
    def test_csrf_detection(self, scanner, sample_html):
        """Test CSRF protection detection"""
        with requests_mock.Mocker() as m:
            m.get('http://test.com', text=sample_html)
            
            vulnerabilities = scanner.scan_url('http://test.com', ['csrf'])
            
            # Should find missing CSRF protection
            csrf_vulns = [v for v in vulnerabilities if 'CSRF' in v.type]
            assert len(csrf_vulns) > 0
            
            # Should be high severity
            assert any(v.severity == 'high' for v in csrf_vulns)
    
    def test_injection_detection(self, scanner, sample_html):
        """Test SQL injection detection"""
        with requests_mock.Mocker() as m:
            m.get('http://test.com', text=sample_html)
            
            vulnerabilities = scanner.scan_url('http://test.com', ['injection'])
            
            # Should find injection risks
            injection_vulns = [v for v in vulnerabilities if 'injection' in v.type.lower() or 'SQL' in v.type]
            assert len(injection_vulns) > 0
    
    def test_headers_detection(self, scanner):
        """Test security headers detection"""
        with requests_mock.Mocker() as m:
            # Mock response without security headers
            m.get('http://test.com', text='<html></html>', headers={})
            
            vulnerabilities = scanner.scan_url('http://test.com', ['headers'])
            
            # Should find missing headers
            header_vulns = [v for v in vulnerabilities if 'Missing' in v.type]
            assert len(header_vulns) > 0
            
            # Should find critical headers
            csp_vulns = [v for v in vulnerabilities if 'Content-Security-Policy' in v.type]
            assert len(csp_vulns) > 0
            assert csp_vulns[0].severity == 'high'
    
    def test_headers_present(self, scanner):
        """Test when security headers are present"""
        with requests_mock.Mocker() as m:
            headers = {
                'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff', 
                'X-XSS-Protection': '1; mode=block',
                'Content-Security-Policy': "default-src 'self'",
                'Strict-Transport-Security': 'max-age=31536000'
            }
            m.get('https://secure.com', text='<html></html>', headers=headers)
            
            vulnerabilities = scanner.scan_url('https://secure.com', ['headers'])
            
            # Should find no missing headers
            missing_headers = [v for v in vulnerabilities if 'Missing' in v.type]
            assert len(missing_headers) == 0
    
    def test_file_upload_detection(self, scanner, sample_html):
        """Test file upload vulnerability detection"""
        with requests_mock.Mocker() as m:
            m.get('http://test.com', text=sample_html)
            
            vulnerabilities = scanner.scan_url('http://test.com', ['file_upload'])
            
            # Should find unrestricted file upload
            upload_vulns = [v for v in vulnerabilities if 'Upload' in v.type]
            assert len(upload_vulns) > 0
    
    def test_security_score_calculation(self, scanner):
        """Test security score calculation"""
        vulnerabilities = [
            Vulnerability('Test High', 'high', 'High severity test', 'test.com'),
            Vulnerability('Test Medium', 'medium', 'Medium severity test', 'test.com'),
            Vulnerability('Test Low', 'low', 'Low severity test', 'test.com')
        ]
        
        score = scanner.calculate_security_score(vulnerabilities)
        
        # Score should be 100 - 20 - 10 - 5 = 65
        assert score == 65
    
    def test_security_score_minimum(self, scanner):
        """Test security score doesn't go below 0"""
        # Many high severity vulnerabilities
        vulnerabilities = [
            Vulnerability(f'Test High {i}', 'high', 'High severity test', 'test.com')
            for i in range(10)
        ]
        
        score = scanner.calculate_security_score(vulnerabilities)
        assert score == 0  # Should not go below 0
    
    def test_report_generation(self, scanner):
        """Test report generation"""
        vulnerabilities = [
            Vulnerability('CSRF Missing', 'high', 'No CSRF protection', 'test.com'),
            Vulnerability('XSS Risk', 'medium', 'XSS vulnerability', 'test.com'),
            Vulnerability('Info Disclosure', 'low', 'Information leak', 'test.com')
        ]
        
        report = scanner.generate_report('http://test.com', vulnerabilities)
        
        assert report['target'] == 'http://test.com'
        assert report['security_score'] == 65  # 100 - 20 - 10 - 5
        assert report['risk_level'] == 'CRITICAL'  # Has high severity
        assert report['total_vulnerabilities'] == 3
        assert len(report['vulnerabilities']['critical_high']) == 1
        assert len(report['vulnerabilities']['medium']) == 1
        assert len(report['vulnerabilities']['low']) == 1
    
    def test_scan_error_handling(self, scanner):
        """Test error handling during scan"""
        with requests_mock.Mocker() as m:
            m.get('http://invalid.com', exc=requests.exceptions.ConnectionError)
            
            vulnerabilities = scanner.scan_url('http://invalid.com', ['xss'])
            
            # Should have error vulnerability
            error_vulns = [v for v in vulnerabilities if 'Error' in v.type]
            assert len(error_vulns) > 0
    
    def test_all_modules_scan(self, scanner, sample_html):
        """Test scanning with all modules"""
        with requests_mock.Mocker() as m:
            m.get('http://test.com', text=sample_html, headers={})
            
            modules = ['xss', 'csrf', 'injection', 'headers', 'info_disclosure', 'authentication', 'access_control', 'file_upload']
            vulnerabilities = scanner.scan_url('http://test.com', modules)
            
            # Should find vulnerabilities from multiple modules
            assert len(vulnerabilities) > 5
            
            # Should have different types of vulnerabilities
            types = {v.type for v in vulnerabilities}
            assert len(types) > 3


class TestVulnerability:
    """Test cases for Vulnerability dataclass"""
    
    def test_vulnerability_creation(self):
        """Test Vulnerability object creation"""
        vuln = Vulnerability(
            type="Test XSS",
            severity="high",
            description="Test description",
            location="http://test.com",
            evidence="<script>alert(1)</script>"
        )
        
        assert vuln.type == "Test XSS"
        assert vuln.severity == "high"
        assert vuln.description == "Test description"
        assert vuln.location == "http://test.com"
        assert vuln.evidence == "<script>alert(1)</script>"
    
    def test_vulnerability_default_evidence(self):
        """Test Vulnerability with default evidence"""
        vuln = Vulnerability(
            type="Test",
            severity="low",
            description="Test",
            location="test.com"
        )
        
        assert vuln.evidence == ""


if __name__ == "__main__":
    pytest.main([__file__, "-v"])