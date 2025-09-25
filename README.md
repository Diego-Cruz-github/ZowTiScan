# 🔒 ZowTiScan

**Scanner Profissional de Segurança | Detecção multicamadas: web, código e infraestrutura**

[![Security Scanner](https://img.shields.io/badge/Security-Scanner-red.svg)](https://zowti.com)
[![Python](https://img.shields.io/badge/Python-FastAPI-blue.svg)](https://fastapi.tiangolo.com/)
[![Next.js](https://img.shields.io/badge/Frontend-Next.js-black.svg)](https://nextjs.org/)

---

## 🛡️ Sobre o ZowTiScan

ZowTiScan é uma plataforma profissional de análise de segurança desenvolvida pela **Zowti Cybersecurity**. Nossa solução oferece detecção multicamadas de vulnerabilidades em aplicações web, análise de código-fonte e avaliação de infraestrutura.

### 🔒 **SAFE MODE - Análise Não-Invasiva**

**ZowTiScan opera exclusivamente em MODO SEGURO:**
- ✅ **Zero payload injection** - não injeta código malicioso
- ✅ **Análise passiva** - apenas lê código-fonte e headers
- ✅ **Não-destrutivo** - não modifica dados do target
- ✅ **Eticamente responsável** - demonstra vulnerabilidades sem explorar

**Por que Safe Mode?**
- **Proteção legal** - evita violação de sistemas
- **Responsabilidade ética** - não causa danos a terceiros  
- **Análise profissional** - identifica riscos sem testá-los
- **Demonstração técnica** - comprova conhecimento sem invasão

### ✨ Funcionalidades Principais

- **🌐 Web Security Analysis (Safe Mode)**
  - Verificação de Security Headers (CSP, HSTS, X-Frame-Options)
  - Análise de formulários sem proteção CSRF
  - Detecção de JavaScript patterns inseguros
  - Auditoria SSL/TLS (headers apenas)

- **📋 Static Code Analysis** 
  - Análise de credenciais expostas (sem acesso ao código)
  - Verificação de dependências conhecidas
  - Padrões de configuração insegura

- **🔍 Infrastructure Assessment (Passive)**
  - Análise de headers de resposta
  - Detecção de tecnologias expostas
  - Verificação de configurações públicas

## 🚀 Como Usar

### Pré-requisitos
- Python 3.8+
- Node.js 16+
- PostgreSQL 12+

### Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/Diego-Cruz-github/ZowTiScan.git
cd ZowTiScan

# Configure o backend
cd backend
pip install -r requirements.txt
python main.py

# Configure o frontend
cd ../frontend
npm install
npm run dev
```

### Uso Básico

```bash
# Scan básico de um website
curl -X POST http://localhost:8000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "https://example.com", "type": "web"}'
```

## 📊 Exemplo de Relatório

```json
{
  "target": "https://example.com",
  "scan_date": "2024-01-15T10:30:00Z",
  "vulnerabilities": [
    {
      "type": "Missing Security Header",
      "severity": "Medium",
      "header": "Content-Security-Policy"
    }
  ],
  "security_score": 75
}
```

## 🏗️ Arquitetura

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Next.js UI    │───▶│  FastAPI Core   │───▶│  PostgreSQL     │
│   (Frontend)    │    │   (Backend)     │    │   (Database)    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

## 🔐 Segurança e Responsabilidade

- **Safe Mode Only** - análises não-invasivas exclusivamente
- **Zero payload injection** - não executa código nos targets
- **Respeito ao robots.txt** e rate limits
- **Análise passiva** de segurança apenas
- **Conformidade LGPD** e práticas éticas
- **Uso responsável** - apenas sistemas próprios ou autorizados

## 📞 Suporte Profissional

Para suporte empresarial, consultoria em segurança ou implementações customizadas:

**Zowti Cybersecurity**
- 🌐 Website: [zowti.com](https://zowti.com)
- 📱 WhatsApp: +55 (31) 98606-3092
- 📧 Email: contato@zowti.com

## 📄 Licença

Este projeto está sob licença MIT - veja o arquivo [LICENSE](LICENSE) para detalhes.

---

**⚠️ Disclaimer:** Use esta ferramenta apenas em sistemas que você possui ou tem autorização explícita para testar. O uso inadequado pode violar leis de segurança cibernética.

**Desenvolvido com ❤️ pela equipe Zowti Cybersecurity**