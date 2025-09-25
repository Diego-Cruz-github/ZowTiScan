"""
ZowTiScan - Professional Security Scanner
FastAPI Backend with XSS Detection Engine
"""

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl
from typing import List, Dict, Any
import requests
from bs4 import BeautifulSoup
import re
import time
from urllib.parse import urljoin

app = FastAPI(
    title="ZowTiScan API",
    description="Professional Security Scanner - XSS Detection Engine",
    version="1.0.0"
)

# CORS para desenvolvimento
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos de dados
class ScanRequest(BaseModel):
    target: HttpUrl
    scan_type: str = "xss"
    depth: int = 1

class Vulnerability(BaseModel):
    type: str
    severity: str
    description: str
    location: str
    payload: str
    evidence: str

class ScanResult(BaseModel):
    target: str
    scan_type: str
    vulnerabilities: List[Vulnerability]
    security_score: int
    scan_duration: float
    timestamp: str

# XSS Payloads básicos (versão pública limitada)
XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "javascript:alert('XSS')",
    "<img src=x onerror=alert('XSS')>",
    "';alert('XSS');//",
    "<svg onload=alert('XSS')>",
]

class XSSScanner:
    """Scanner XSS SAFE MODE - Análise não-invasiva"""
    
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'ZowTiScan/1.0 Security Scanner (Safe Mode)'
        })
    
    def scan_url(self, url: str) -> List[Vulnerability]:
        """Análise SEGURA de vulnerabilidades XSS - sem injetar código"""
        vulnerabilities = []
        
        try:
            # Analisa código fonte sem executar payloads
            response = self.session.get(url, timeout=10)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Verifica headers de segurança
            security_vulns = self._check_security_headers(response.headers, url)
            vulnerabilities.extend(security_vulns)
            
            # Analisa formulários sem testar
            forms = soup.find_all('form')
            for form in forms:
                form_vulns = self._analyze_form_security(url, form)
                vulnerabilities.extend(form_vulns)
            
            # Analisa código JavaScript inline
            script_vulns = self._analyze_inline_scripts(soup, url)
            vulnerabilities.extend(script_vulns)
            
        except Exception as e:
            # Em produção, logging adequado
            pass
        
        return vulnerabilities
    
    def _check_security_headers(self, headers: dict, url: str) -> List[Vulnerability]:
        """SAFE: Verifica headers de segurança sem testar payloads"""
        vulnerabilities = []
        
        # Headers de segurança importantes
        security_headers = {
            'Content-Security-Policy': 'High',
            'X-Frame-Options': 'Medium', 
            'X-Content-Type-Options': 'Medium',
            'X-XSS-Protection': 'Medium',
            'Strict-Transport-Security': 'Medium'
        }
        
        for header, severity in security_headers.items():
            if header not in headers:
                vulnerabilities.append(Vulnerability(
                    type="Missing Security Header",
                    severity=severity,
                    description=f"Header de segurança '{header}' ausente",
                    location=url,
                    payload="N/A - Análise passiva",
                    evidence=f"Header '{header}' não encontrado na resposta"
                ))
        
        return vulnerabilities
    
    def _analyze_form_security(self, base_url: str, form) -> List[Vulnerability]:
        """SAFE: Analisa formulários sem enviar dados"""
        vulnerabilities = []
        
        try:
            action = form.get('action', '')
            method = form.get('method', 'get').lower()
            form_url = urljoin(base_url, action)
            
            # Verifica se formulário tem proteção CSRF
            csrf_token = form.find(['input'], {'name': re.compile(r'csrf|token|_token', re.I)})
            if not csrf_token:
                vulnerabilities.append(Vulnerability(
                    type="Missing CSRF Protection",
                    severity="Medium",
                    description="Formulário sem proteção CSRF aparente",
                    location=form_url,
                    payload="N/A - Análise estática",
                    evidence="Token CSRF não encontrado no formulário"
                ))
            
            # Verifica inputs sem validação aparente
            for input_tag in form.find_all(['input', 'textarea']):
                input_type = input_tag.get('type', 'text')
                if input_type in ['text', 'search'] and not input_tag.get('pattern'):
                    vulnerabilities.append(Vulnerability(
                        type="Input Without Validation",
                        severity="Low",
                        description=f"Input '{input_tag.get('name', 'unnamed')}' sem validação aparente",
                        location=form_url,
                        payload="N/A - Análise estática",
                        evidence="Input sem atributos de validação (pattern, maxlength, etc.)"
                    ))
                    break  # Só reporta um por formulário para não spam
        
        except:
            pass
        
        return vulnerabilities
    
    def _analyze_inline_scripts(self, soup, url: str) -> List[Vulnerability]:
        """SAFE: Analisa JavaScript inline para padrões inseguros"""
        vulnerabilities = []
        
        try:
            scripts = soup.find_all('script')
            
            # Padrões perigosos em JavaScript
            dangerous_patterns = {
                r'document\.write\s*\(': 'document.write usage',
                r'innerHTML\s*=': 'innerHTML assignment',
                r'eval\s*\(': 'eval() usage',
                r'setTimeout\s*\(\s*["\'][^"\']*["\']': 'setTimeout with string'
            }
            
            for script in scripts:
                if script.string:
                    for pattern, description in dangerous_patterns.items():
                        if re.search(pattern, script.string, re.I):
                            vulnerabilities.append(Vulnerability(
                                type="Potentially Unsafe JavaScript",
                                severity="Low",
                                description=f"JavaScript inline com {description}",
                                location=url,
                                payload="N/A - Análise estática",
                                evidence=f"Padrão encontrado: {description}"
                            ))
                            break  # Um por script
        
        except:
            pass
        
        return vulnerabilities

# Instância global do scanner
xss_scanner = XSSScanner()

@app.get("/")
async def root():
    return {"message": "ZowTiScan API - Professional Security Scanner"}

@app.get("/health")
async def health_check():
    return {"status": "healthy", "scanner": "ready"}

@app.post("/api/scan", response_model=ScanResult)
async def perform_scan(request: ScanRequest):
    """Executa scan de segurança no target especificado"""
    
    start_time = time.time()
    target_url = str(request.target)
    
    try:
        vulnerabilities = []
        
        if request.scan_type.lower() == "xss":
            vulnerabilities = xss_scanner.scan_url(target_url)
        else:
            raise HTTPException(
                status_code=400, 
                detail="Tipo de scan não suportado. Use: 'xss'"
            )
        
        # Calcula score de segurança (básico)
        security_score = max(0, 100 - (len(vulnerabilities) * 15))
        
        scan_duration = time.time() - start_time
        
        return ScanResult(
            target=target_url,
            scan_type=request.scan_type,
            vulnerabilities=vulnerabilities,
            security_score=security_score,
            scan_duration=round(scan_duration, 2),
            timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
        )
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Erro no scan: {str(e)}")

@app.get("/api/payloads")
async def get_sample_payloads():
    """Retorna exemplos de payloads XSS para fins educativos"""
    return {
        "xss_examples": XSS_PAYLOADS[:3],  # Apenas alguns para demo
        "note": "Use apenas para testes em sistemas próprios"
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)