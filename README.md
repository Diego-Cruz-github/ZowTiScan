# 🔒 ZowTiScan - Professional Security Scanner

Clean, fast, and effective web security scanner with 14 detection modules.

## Features

- **14 Security Modules**: XSS, CSRF, SQL Injection, NoSQL Injection, Headers, Broken Pages/Links, Info Disclosure, Authentication, Access Control, File Upload
- **REST API**: Complete programmatic access via JSON endpoints
- **Professional Reports**: Detailed PDF, JSON and formatted text reports
- **Safe Mode**: No payloads injected, passive analysis only
- **Real TDD**: Comprehensive pytest test suite
- **Debug Support**: Development PIN available for troubleshooting

## 📸 Demonstração

![ZowTiScan Demo](Demonstração/Gravando-2025-09-29-115632.gif)

*Professional web security scanning in action - Real-time vulnerability detection with detailed reporting*

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Command Line
```bash
# Scan all modules
python scanner.py https://example.com

# Scan specific modules
python scanner.py https://example.com --modules xss csrf injection nosql_injection headers

# JSON output
python scanner.py https://example.com --format json
```

### As Library
```python
from scanner import SecurityScanner

scanner = SecurityScanner()
vulnerabilities = scanner.scan_url('https://example.com')
report = scanner.generate_report('https://example.com', vulnerabilities)
```

### REST API Integration
```bash
# Start the web server
python app.py

# API endpoint available at:
POST http://localhost:5000/api/scan
Content-Type: application/json

{"url": "https://example.com"}
```

```python
# Python API integration
import requests

response = requests.post('http://localhost:5000/api/scan', 
                        json={'url': 'https://example.com'})
result = response.json()
print(f"Security Score: {result['security_score']}/100")
```

## Example Output

```
ZowTiScan - Scanning https://example.com
============================================================
Security Score: 45/100 (HIGH RISK)
Vulnerabilities found: 8 issues
Scan duration: 1.13 seconds

CRITICAL/HIGH:
1. Missing CSRF Protection - POST form without CSRF protection detected
2. SQL Injection Risk - Form with potentially vulnerable parameters: user_id, post_id

MEDIUM:
3. Missing Content-Security-Policy - Script injection risk
4. Missing X-Frame-Options - Clickjacking risk
5. Missing HSTS Header - HTTPS downgrade attacks

LOW:
6. Potential XSS Input - Input 'comment' might be vulnerable to XSS
7. Source Code in Response - Response contains Function definition
8. Potentially Unsafe JavaScript - JavaScript inline com innerHTML assignment
```

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test
pytest tests/test_scanner.py::TestSecurityScanner::test_xss_detection -v
```

## Modules

| Module | Description | Detects |
|--------|-------------|---------|
| **XSS** | Cross-Site Scripting | Unsafe inputs, innerHTML usage |
| **CSRF** | Cross-Site Request Forgery | Missing CSRF tokens |
| **SQL Injection** | SQL Database Attacks | Suspicious SQL parameters |
| **NoSQL Injection** | NoSQL Database Attacks | MongoDB, Redis vulnerabilities |
| **Headers** | Security Headers | Missing CSP, HSTS, X-Frame-Options |
| **Broken Pages** | Link Validation | 404s, inactive elements |
| **Info Disclosure** | Information Leaks | Error messages, debug info |
| **Authentication** | Auth Security | Weak password policies |
| **Access Control** | Authorization | Directory listing |
| **File Upload** | Upload Security | Unrestricted uploads |

## Development & Support

### Debug Mode
When running in development mode (`python app.py`), debug PIN is displayed in console for troubleshooting. If you encounter issues, please include the debug information when reaching out for support.

### Report Generation
The scanner automatically generates multiple report formats:
- **PDF Reports**: Professional formatted security assessments
- **JSON Data**: Structured data for integrations
- **Text Reports**: Human-readable analysis with professional insights

## License

MIT License - Professional security scanner for educational and authorized testing only.

---

**Use only on websites you own or have explicit permission to test.**
