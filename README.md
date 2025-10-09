# ZowTiCheck - Professional Security & Performance Scanner

Comprehensive security, performance, SEO and web patterns audit for websites and web applications.

[![Python](https://img.shields.io/badge/Python-3.8+-blue?logo=python&logoColor=white)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.x-green?logo=flask&logoColor=white)](https://flask.palletsprojects.com)
[![Security](https://img.shields.io/badge/Security-Scanner-red?logo=shield&logoColor=white)](https://github.com/Diego-Cruz-github/ZowTiScan)
[![API](https://img.shields.io/badge/API-REST-purple?logo=fastapi&logoColor=white)](https://github.com/Diego-Cruz-github/ZowTiScan)

## Core Features

**Multi-Domain Security Analysis**
- Advanced vulnerability detection across 12+ security modules
- XSS, CSRF, SQL/NoSQL injection identification
- HTTP security headers validation and authentication analysis
- Access control verification and information disclosure detection

**Performance & SEO Integration**
- Core Web Vitals analysis for desktop and mobile via Google PageSpeed API
- SEO optimization recommendations with meta tags and HTML structure analysis
- Web development patterns assessment
- Professional-grade reporting in PDF, JSON and text formats

**Enterprise Architecture**
- REST API with comprehensive JSON endpoints
- CLI interface and Python library integration
- Auto-detection of HTTP/HTTPS protocols
- Multi-format output for CI/CD pipeline integration

## Demonstration

![ZowTiCheck Demo](demo/demo.gif)

*Quadruple audit in action: security + performance + SEO + web patterns*

**Demo target**: testphp.vulnweb.com - Acunetix test site with intentional vulnerabilities (SQL Injection, XSS, HTTP configuration flaws) demonstrating scanner effectiveness

## Technical Stack

**Backend Architecture**
- Python 3.8+ with Flask framework
- Advanced HTTP client libraries (requests, BeautifulSoup4)
- Data validation with Pydantic models
- Google PageSpeed Insights API integration
- Professional PDF report generation

**Frontend Interface**
- Modern HTML5, CSS3, vanilla JavaScript
- Responsive design architecture
- Real-time audit progress indicators

**API Layer**
- RESTful API with comprehensive endpoints
- External service integrations (Google PageSpeed)
- Automatic protocol detection and validation

## Installation

```bash
# Clone repository
git clone https://github.com/Diego-Cruz-github/ZowTiScan.git
cd ZowTiScan

# Install dependencies
pip install -r requirements.txt

# Configure environment variables (optional)
cp .env.example .env
```

## Usage

### Command Line Interface
```bash
# Complete audit (security + performance + SEO + web patterns)
python scanner.py https://example.com --audit

# Security-only scan
python scanner.py https://example.com --security

# JSON output format
python scanner.py https://example.com --audit --format json
```

### Python Library
```python
from scanner import SecurityScanner

scanner = SecurityScanner()
result = scanner.audit_complete('https://example.com')
print(f"Security: {result['security_score']}/100")
print(f"Performance: {result['performance_score']}/100")
```

### REST API
```bash
# Start server
python app.py

# Complete audit
curl -X POST http://localhost:5000/api/audit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://example.com"}'
```

## Output Example

```
ZowTiCheck - Auditing https://example.com
============================================================
Security Score: 67/100 (MEDIUM RISK)
Performance Score: 89/100 (GOOD)
SEO Score: 82/100 (GOOD)
Web Patterns Score: 91/100 (EXCELLENT)

Vulnerabilities found: 5 issues
Quadruple audit: 3.8 seconds

CRITICAL:
Missing CSRF Protection - POST form vulnerability
MEDIUM: Missing meta description (SEO impact)
```

## Security Modules

**Advanced Vulnerability Detection**
- Web application security assessment with comprehensive OWASP coverage
- Session management and authentication security validation
- Advanced injection vulnerability detection (SQL, NoSQL, XSS, CSRF)
- HTTP security headers analysis and configuration assessment
- Information disclosure and data exposure identification
- Resource validation and access control verification

## Architecture Overview

**Modular Design**
- 12+ specialized security modules with independent execution
- Performance analysis engine with Google PageSpeed API integration
- SEO optimization scanner with technical recommendations
- Web development patterns assessment and best practices validation

**Professional Reporting**
- Executive summary reports with risk scoring and prioritization
- Technical detailed reports with remediation recommendations
- Multi-format output (PDF, JSON, plain text) for various stakeholders
- CI/CD pipeline integration with automated reporting

## Technical Differentiators

- **Quadruple Analysis**: Security + Performance + SEO + Web Patterns in single scan
- **Multi-Device Assessment**: Separate desktop and mobile performance analysis
- **Protocol Intelligence**: Automatic HTTP/HTTPS detection and testing
- **Enterprise Integration**: REST API architecture for automated security workflows
- **Rapid Execution**: Complete audit cycles in under 5 seconds
- **Scalable Architecture**: Designed for high-volume enterprise environments

## License

MIT License - Professional scanner for educational and authorized testing purposes.

## Legal Notice

**Use only on websites you own or have explicit permission to test.**

---

**Partnership & Development**

Developed in partnership with [ZowTi](https://zowti.com/) - Cybersecurity & Compliance Solutions  
[English](https://zowti.com/en/index.html) | [Español](https://zowti.com/es/index.html)

**Diego Fonte**  
Full Stack Developer | Cybersecurity & AI Focused  
[Portfolio PT](https://diegofontedev.com.br/) | [EN](https://diegofontedev.com.br/index-en.html) | [ES](https://diegofontedev.com.br/index-es.html)  
Contact: contato@diegofontedev.com.br
