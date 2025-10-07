# 🔒 ZowTiCheck - Professional Security & Performance Scanner

Auditoria completa de segurança, performance, SEO e web patterns para sites e aplicações web.

## 🚀 Principais Recursos

- **12+ Módulos de Segurança**: XSS, CSRF, SQL/NoSQL Injection, Headers, Authentication, Access Control
- **Performance Analysis**: Core Web Vitals desktop/mobile via Google PageSpeed API
- **SEO Optimization**: Meta tags, estrutura HTML e otimizações
- **Web Patterns**: Análise de padrões de desenvolvimento web
- **REST API**: Integração completa via endpoints JSON
- **Relatórios Profissionais**: PDF executivo, técnico e JSON
- **Auto-detect HTTP/HTTPS**: Detecção automática de protocolo
- **CLI + Library**: Uso via linha de comando ou como biblioteca Python

## 📸 Demonstração

![ZowTiCheck Demo](ss/Gravando-2025-10-07-140124.gif)

*Auditoria quádrupla em ação: segurança + performance + SEO + web patterns*

**URL de demonstração**: testphp.vulnweb.com - Site de testes da Acunetix com vulnerabilidades intencionais (SQL Injection, XSS, falhas de configuração HTTP) para demonstrar a eficácia do scanner

## 💻 Stack Tecnológica

**Backend:**
- Python 3.8+ com Flask
- requests, BeautifulSoup4, pydantic
- Google PageSpeed Insights API
- reportlab para relatórios PDF

**Frontend:**
- HTML5, CSS3, JavaScript vanilla
- Interface responsiva e moderna

**APIs:**
- REST API completa
- Google PageSpeed Insights integration
- Auto-detect HTTP/HTTPS

## 🛠️ Instalação

```bash
# Clone o repositório
git clone https://github.com/seu-usuario/ZowTiCheck.git
cd ZowTiCheck

# Instale as dependências
pip install -r requirements.txt

# Configure as variáveis de ambiente (opcional)
cp .env.example .env
```

## 📖 Uso

### Linha de Comando
```bash
# Auditoria completa (segurança + performance + SEO + web patterns)
python scanner.py https://exemplo.com --audit

# Apenas segurança
python scanner.py https://exemplo.com --security

# Formato JSON
python scanner.py https://exemplo.com --audit --format json
```

### Como Biblioteca Python
```python
from scanner import SecurityScanner

scanner = SecurityScanner()
result = scanner.audit_complete('https://exemplo.com')
print(f"Security: {result['security_score']}/100")
print(f"Performance: {result['performance_score']}/100")
```

### API REST
```bash
# Iniciar servidor
python app.py

# Auditoria completa
curl -X POST http://localhost:5000/api/audit \
  -H "Content-Type: application/json" \
  -d '{"url": "https://exemplo.com"}'
```

## 📊 Exemplo de Saída

```
ZowTiCheck - Auditing https://exemplo.com
============================================================
✅ Security Score: 67/100 (MEDIUM RISK)
⚡ Performance Score: 89/100 (GOOD)
🔍 SEO Score: 82/100 (GOOD)
🌐 Web Patterns Score: 91/100 (EXCELLENT)

⚠️ Vulnerabilities found: 5 issues
📋 Quadruple audit: 3.8 seconds

CRITICAL:
🔍 Missing CSRF Protection - POST form vulnerability
⚡ MEDIUM: Missing meta description (SEO impact)
```

## 🔧 Funcionalidades Principais

### Módulos de Segurança (12+)
- **Web Application Security**: Detecção de vulnerabilidades comuns
- **Session Security**: Validação de segurança de sessões  
- **Injection Vulnerabilities**: Sistema de detecção avançado
- **HTTP Security**: Análise de configurações de segurança
- **Information Security**: Detecção de exposição de dados
- **Resource Validation**: Verificação de recursos e links
- **Access Control**: Validação de controles de acesso
- **File Security**: Verificação de segurança em uploads

### Performance + SEO + Web Patterns
- **Core Web Vitals**: Desktop e mobile via Google PageSpeed
- **SEO Analysis**: Meta tags e estrutura HTML
- **Page Speed Insights**: Integração completa com Google API
- **Web Patterns**: Padrões de desenvolvimento web modernos

### Enterprise Integration
- **API REST**: Endpoints para auditoria automática
- **CI/CD Integration**: Integração com pipelines de desenvolvimento
- **Executive Reports**: Relatórios profissionais automatizados
- **Multi-format Output**: PDF, JSON, texto

## 🌟 Diferenciais

- ✅ **Auditoria 4 em 1**: Segurança + Performance + SEO + Web Patterns
- ✅ **Desktop + Mobile**: Análise separada para diferentes dispositivos
- ✅ **Auto-detect**: Detecção automática de HTTP/HTTPS
- ✅ **Professional Grade**: Relatórios executivos e técnicos
- ✅ **Fast Results**: Auditoria completa em segundos
- ✅ **Enterprise Ready**: API REST para integração empresarial

## 📈 Roadmap

- [ ] Autenticação JWT
- [ ] Dashboard web interativo  
- [ ] Integração com mais APIs de performance
- [ ] Módulos de segurança adicionais
- [ ] Suporte para testes automatizados
- [ ] Integração com CI/CD avançada

## 🤝 Contribuição

Este é um projeto em desenvolvimento ativo. Para contribuições:

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📜 Licença

MIT License - Scanner profissional para uso educacional e testes autorizados.

## ⚠️ Aviso Legal

**Use apenas em sites que você possui ou tem permissão explícita para testar.**

---

**Desenvolvido por**: [Diego Fonte](https://diegofontedev.com.br) - Desenvolvedor Full Stack, Consultor em IA e Cibersegurança  
**Parceria**: [ZowTi](https://www.zowti.com)