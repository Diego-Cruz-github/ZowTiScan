# 🔒 ZowTiScan - Professional Security Scanner

Clean, fast, and effective web security scanner with 14 detection modules.

## Features

- **14 Security Modules**: XSS, CSRF, SQL Injection, NoSQL Injection, Headers, Broken Pages/Links, Info Disclosure, Authentication, Access Control, File Upload
- **Fast Scanning**: Complete analysis in ~1 second
- **Safe Mode**: No payloads injected, passive analysis only
- **Professional Reports**: JSON and text output formats
- **Real TDD**: Comprehensive pytest test suite

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

## License

MIT License - Professional security scanner for educational and authorized testing only.

---

**Use only on websites you own or have explicit permission to test.**