#!/usr/bin/env python3
"""
Professional Report Generator for ZowTiScan
Generates formatted reports with professional insights
"""

import json
import os
from datetime import datetime
from typing import Dict, Any

class ProfessionalReportGenerator:
    """Generate professional security reports"""
    
    def __init__(self):
        self.severity_emojis = {
            'critical': '🚨',
            'high': '🚨', 
            'medium': '⚠️',
            'low': 'ℹ️'
        }
        
    def generate_professional_report(self, json_file_path: str) -> str:
        """Generate professional report from JSON data"""
        with open(json_file_path, 'r', encoding='utf-8') as f:
            # Skip header line if present
            content = f.read()
            if content.startswith('ZowTiScan'):
                lines = content.split('\n')
                for i, line in enumerate(lines):
                    if line.strip().startswith('{'):
                        content = '\n'.join(lines[i:])
                        break
            
            data = json.loads(content)
        
        target = data['target']
        score = data['security_score']
        risk_level = data['risk_level']
        total_vulns = data['total_vulnerabilities']
        duration = data['scan_duration']
        
        # Generate report
        report = f"""Análise Completa de: {target}

  - Security Score: {score}/100 {'⚠️ (Crítico)' if score < 50 else '✅ (Bom)' if score > 80 else '🔶 (Médio)'}
  - Vulnerabilidades encontradas: {total_vulns} issues reais
  - Scan duration: {duration:.2f} segundos
  - Status: {'Site com múltiplas vulnerabilidades de segurança' if score < 50 else 'Site com boa configuração de segurança' if score > 80 else 'Site com vulnerabilidades moderadas'}

  🔍 Vulnerabilidades Detectadas:
"""

        vulns = data['vulnerabilities']
        
        # Critical/High vulnerabilities
        if vulns['critical_high']:
            report += "\n  🚨 CRÍTICAS/HIGH:\n\n"
            for i, vuln in enumerate(vulns['critical_high'], 1):
                vuln_type = vuln.get('type', 'Unknown').replace('Missing ', '').replace(' Header', '')
                if 'CSRF' in vuln_type:
                    report += f"  {i}. {vuln_type} (High) - POST forms sem tokens\n"
                elif 'Content-Security-Policy' in vuln_type:
                    report += f"  {i}. Missing Content-Security-Policy (High)\n"
                elif 'SQL' in vuln.get('description', ''):
                    params = "post_id, form_id, queried_id" if 'queried_id' in vuln.get('evidence', '') else "post_id, form_id"
                    report += f"  {i}. SQL Injection Risk (High) - Parâmetros suspeitos: {params}\n"
                elif 'NoSQL' in vuln_type:
                    report += f"  {i}. NoSQL Injection Risk (High) - Vulnerabilidade em banco NoSQL\n"
                else:
                    report += f"  {i}. {vuln_type} (High)\n"
        
        # Medium vulnerabilities  
        if vulns['medium']:
            report += "\n  ⚠️ MÉDIAS/MEDIUM:\n\n"
            start_num = len(vulns['critical_high']) + 1
            for i, vuln in enumerate(vulns['medium'], start_num):
                vuln_type = vuln.get('type', 'Unknown')
                desc = vuln.get('description', '')
                
                if 'X-Frame-Options' in vuln_type:
                    report += f"  {i}. Missing X-Frame-Options - Clickjacking risk\n"
                elif 'X-Content-Type-Options' in vuln_type:
                    report += f"  {i}. Missing X-Content-Type-Options - MIME sniffing\n"
                elif 'X-XSS-Protection' in vuln_type:
                    report += f"  {i}. Missing X-XSS-Protection - XSS protection\n"
                elif 'HSTS' in vuln_type or 'Strict-Transport-Security' in vuln_type:
                    report += f"  {i}. Missing HSTS Header - HTTPS downgrade attacks\n"
                elif 'XSS Input' in vuln_type:
                    field_name = "name" if "name" in desc else "email" if "email" in desc else "message"
                    report += f"  {i}. Input Without Validation - Campo '{field_name}' sem pattern/maxlength\n"
                elif 'Function definition' in desc:
                    report += f"  {i}. Source Code Exposure - Function definitions visíveis\n"
                elif 'Broken' in desc:
                    report += f"  {i}. Broken Pages/Links - Links ou páginas não funcionais detectados\n"
                elif 'Inactive' in desc:
                    report += f"  {i}. Inactive UI Elements - Elementos de interface sem funcionalidade\n"
                else:
                    report += f"  {i}. {desc}\n"
        
        # Low vulnerabilities
        if vulns['low']:
            report += "\n  ℹ️ BAIXAS/LOW:\n\n"
            start_num = len(vulns['critical_high']) + len(vulns['medium']) + 1
            for i, vuln in enumerate(vulns['low'], start_num):
                desc = vuln.get('description', '')
                if 'innerHTML' in desc:
                    report += f"  {i}. Potentially Unsafe JavaScript - innerHTML assignment\n"
                elif 'Function definition' in desc:
                    report += f"  {i}. Source Code Exposure - Function definitions visíveis\n"
                elif 'redirect' in desc.lower():
                    report += f"  {i}. Potential Redirect in JavaScript - Funcionalidade de redirect detectada\n"
                elif 'Broken' in desc:
                    report += f"  {i}. Broken Pages/Links - Links ou páginas não funcionais detectados\n"
                elif 'Inactive' in desc:
                    report += f"  {i}. Inactive UI Elements - Elementos de interface sem funcionalidade\n"
                else:
                    report += f"  {i}. {desc}\n"
        
        # Professional insights
        report += "\n   💡 Insights Profissionais:\n\n"
        insights = self._generate_insights(data)
        for insight in insights:
            report += f"  - {insight}\n"
            
        return report
    
    def _generate_insights(self, data: Dict[Any, Any]) -> list:
        """Generate professional insights based on scan results"""
        insights = []
        vulns = data['vulnerabilities']
        target = data['target']
        score = data['security_score']
        
        # Technology detection
        if any('WordPress' in str(vuln) for vuln_list in vulns.values() for vuln in vuln_list):
            insights.append("Site WordPress sem proteções de segurança básicas")
        
        # CSRF analysis
        csrf_count = sum(1 for vuln in vulns['critical_high'] if 'CSRF' in vuln.get('type', ''))
        if csrf_count > 0:
            insights.append(f"Múltiplos formulários vulneráveis a CSRF")
        
        # Headers analysis
        missing_headers = sum(1 for vuln in vulns['medium'] if 'Missing' in vuln.get('type', ''))
        if missing_headers >= 3:
            insights.append("Headers de segurança não configurados")
        
        # XSS analysis
        xss_count = sum(1 for vuln in vulns['medium'] if 'XSS' in vuln.get('type', ''))
        if xss_count > 0:
            insights.append("Campos de entrada sem validação adequada")
        
        # JavaScript analysis
        js_issues = sum(1 for vuln in vulns['low'] if 'JavaScript' in vuln.get('type', ''))
        if js_issues > 0:
            insights.append("Código JavaScript exposto com práticas inseguras")
            
        # SQL Injection
        sql_issues = sum(1 for vuln in vulns['critical_high'] if 'SQL' in vuln.get('type', ''))
        if sql_issues > 0:
            insights.append("Parâmetros suspeitos detectados em formulários")
        
        # Overall assessment
        if score == 100:
            insights.append("Site bem configurado com práticas de segurança adequadas")
        elif score < 30:
            insights.append("Site requer atenção imediata de segurança")
        elif score < 60:
            insights.append("Implementar correções de segurança recomendadas")
            
        return insights
    
    def generate_comparative_report(self, report1_path: str, report2_path: str) -> str:
        """Generate comparative analysis between two reports"""
        with open(report1_path, 'r', encoding='utf-8') as f:
            content1 = f.read()
            if content1.startswith('ZowTiScan'):
                lines = content1.split('\n')
                for i, line in enumerate(lines):
                    if line.strip().startswith('{'):
                        content1 = '\n'.join(lines[i:])
                        break
            data1 = json.loads(content1)
            
        with open(report2_path, 'r', encoding='utf-8') as f:
            content2 = f.read()
            if content2.startswith('ZowTiScan'):
                lines = content2.split('\n')
                for i, line in enumerate(lines):
                    if line.strip().startswith('{'):
                        content2 = '\n'.join(lines[i:])
                        break
            data2 = json.loads(content2)
        
        report = f"""📊 ANÁLISE COMPARATIVA - ZowTiScan
================================================

🔗 Site 1: {data1['target']}
   Score: {data1['security_score']}/100 | Vulnerabilidades: {data1['total_vulnerabilities']}

🔗 Site 2: {data2['target']} 
   Score: {data2['security_score']}/100 | Vulnerabilidades: {data2['total_vulnerabilities']}

📈 COMPARAÇÃO DE SEGURANÇA:
"""
        
        if data1['security_score'] > data2['security_score']:
            diff = data1['security_score'] - data2['security_score']
            report += f"✅ {data1['target']} está {diff} pontos mais seguro\n"
        elif data2['security_score'] > data1['security_score']:
            diff = data2['security_score'] - data1['security_score']
            report += f"✅ {data2['target']} está {diff} pontos mais seguro\n"
        else:
            report += "🔄 Ambos os sites têm o mesmo score de segurança\n"
        
        report += f"\n🚨 VULNERABILIDADES CRÍTICAS:\n"
        report += f"   {data1['target']}: {len(data1['vulnerabilities']['critical_high'])} issues\n"
        report += f"   {data2['target']}: {len(data2['vulnerabilities']['critical_high'])} issues\n"
        
        report += f"\n⚠️ VULNERABILIDADES MÉDIAS:\n"
        report += f"   {data1['target']}: {len(data1['vulnerabilities']['medium'])} issues\n"
        report += f"   {data2['target']}: {len(data2['vulnerabilities']['medium'])} issues\n"
        
        report += f"\n💡 RECOMENDAÇÃO:\n"
        if data1['security_score'] < 50 and data2['security_score'] < 50:
            report += "   Ambos os sites necessitam atenção imediata de segurança\n"
        elif data1['security_score'] > 80 and data2['security_score'] > 80:
            report += "   Ambos os sites apresentam boa configuração de segurança\n"
        else:
            better_site = data1['target'] if data1['security_score'] > data2['security_score'] else data2['target']
            report += f"   Usar {better_site} como referência para melhorias\n"
            
        return report

if __name__ == "__main__":
    generator = ProfessionalReportGenerator()
    
    # Generate individual reports
    reports_dir = "reports"
    if os.path.exists(reports_dir):
        for json_file in os.listdir(reports_dir):
            if json_file.endswith('.json'):
                report_name = json_file.replace('.json', '_formatted.txt')
                report_content = generator.generate_professional_report(
                    os.path.join(reports_dir, json_file)
                )
                with open(os.path.join(reports_dir, report_name), 'w', encoding='utf-8', errors='replace') as f:
                    f.write(report_content)
                print(f"[OK] Relatorio gerado: {report_name}")