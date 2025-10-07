/**
 * ZowTiCheck Professional Frontend
 * Real-time Security + Performance + SEO Audit Interface
 * Integrates with Flask Backend APIs
 */

class ZowTiCheckUI {
    constructor() {
        this.baseURL = 'http://localhost:5000';
        this.isScanning = false;
        this.currentScanType = 'full';
        this.currentResults = null;
        
        // Initialize UI components
        this.initializeElements();
        this.initializeEventListeners();
        this.initializeAnimations();
        
        console.log('🛡️ ZowTiCheck UI initialized - Ready for security audits');
    }

    initializeElements() {
        // Input elements
        this.urlInput = document.getElementById('urlInput');
        this.detectBtn = document.getElementById('detectBtn');
        this.scanBtn = document.getElementById('scanBtn');
        this.exportBtn = document.getElementById('exportBtn');
        this.pdfSummaryBtn = document.getElementById('pdfSummaryBtn');
        this.pdfDetailedBtn = document.getElementById('pdfDetailedBtn');
        
        // Display elements
        this.protocolDisplay = document.getElementById('protocolDisplay');
        this.resultsContent = document.getElementById('resultsContent');
        this.loadingOverlay = document.getElementById('loadingOverlay');
        this.loadingStatus = document.getElementById('loadingStatus');
        this.progressBar = document.getElementById('progressBar');
        
        // Buttons
        this.scanTypeButtons = document.querySelectorAll('.scan-type-btn');
    }

    initializeEventListeners() {
        // URL input and detection
        this.urlInput.addEventListener('input', () => this.validateURL());
        this.detectBtn.addEventListener('click', () => this.detectProtocol());
        
        // Scan type selection
        this.scanTypeButtons.forEach(btn => {
            btn.addEventListener('click', () => this.selectScanType(btn.dataset.mode));
        });
        
        // Main scan button
        this.scanBtn.addEventListener('click', () => this.startScan());
        
        
        // Export functionality
        this.exportBtn.addEventListener('click', () => this.exportResults());
        
        // Enter key support
        this.urlInput.addEventListener('keypress', (e) => {
            if (e.key === 'Enter' && !this.isScanning) {
                this.startScan();
            }
        });
    }

    initializeAnimations() {
        // Add cyber glow effect to active elements
        const glowElements = document.querySelectorAll('.scan-btn, .feature-badge');
        glowElements.forEach(el => {
            el.addEventListener('mouseenter', () => {
                el.classList.add('pulse-glow');
            });
            el.addEventListener('mouseleave', () => {
                el.classList.remove('pulse-glow');
            });
        });
    }

    validateURL() {
        const url = this.urlInput.value.trim();
        const isValid = url.length > 0 && (url.includes('.') || url.includes('localhost'));
        
        this.scanBtn.disabled = !isValid || this.isScanning;
        
        if (url.length > 0 && !isValid) {
            this.protocolDisplay.textContent = '⚠️ Enter a valid domain or URL';
            this.protocolDisplay.className = 'protocol-display error';
        } else {
            this.protocolDisplay.textContent = '';
            this.protocolDisplay.className = 'protocol-display';
        }
    }

    async detectProtocol() {
        const url = this.urlInput.value.trim();
        if (!url) return;

        this.detectBtn.disabled = true;
        this.protocolDisplay.textContent = '🔍 Detecting optimal protocol...';
        this.protocolDisplay.className = 'protocol-display';

        try {
            const response = await fetch(`${this.baseURL}/api/smart-detect`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ domain: url })
            });

            const data = await response.json();
            
            if (data.success) {
                this.protocolDisplay.textContent = `✅ Protocol: ${data.protocol.toUpperCase()} | Final URL: ${data.finalUrl}`;
                this.protocolDisplay.className = 'protocol-display success';
                this.urlInput.value = data.finalUrl;
            } else {
                this.protocolDisplay.textContent = `❌ ${data.error}`;
                this.protocolDisplay.className = 'protocol-display error';
            }
        } catch (error) {
            this.protocolDisplay.textContent = `❌ Detection failed: ${error.message}`;
            this.protocolDisplay.className = 'protocol-display error';
        } finally {
            this.detectBtn.disabled = false;
        }
    }

    async autoDetectSilent(url) {
        // Auto-detect protocol silently without UI updates
        try {
            const response = await fetch(`${this.baseURL}/api/smart-detect`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ domain: url })
            });

            const data = await response.json();
            
            if (data.success) {
                return data.finalUrl;
            } else {
                // If auto-detect fails, return original URL
                return url;
            }
        } catch (error) {
            // If auto-detect fails, return original URL
            return url;
        }
    }

    selectScanType(mode) {
        this.currentScanType = mode;
        
        // Update UI state
        this.scanTypeButtons.forEach(btn => {
            btn.classList.remove('active');
        });
        
        const activeBtn = document.querySelector(`[data-mode=\"${mode}\"]`);
        if (activeBtn) {
            activeBtn.classList.add('active');
        }
        
        // Update scan button text
        const modeTexts = {
            security: '🛡️ Start Security Scan',
            performance: '🚀 Start Performance Analysis', 
            seo: '🎯 Start SEO Analysis',
            'web-patterns': '🔧 Start Web Patterns Analysis',
            full: '⭐ Start Complete Audit'
        };
        
        const scanTextElement = this.scanBtn.querySelector('.scan-text');
        if (scanTextElement) {
            scanTextElement.textContent = modeTexts[mode] || 'Start Scan';
        }
        
        console.log(`🎯 Scan type selected: ${mode}`);
    }

    async startScan() {
        const url = this.urlInput.value.trim();
        if (!url || this.isScanning) return;

        this.isScanning = true;
        this.showLoadingOverlay();
        this.updateScanButton(true);
        
        try {
            // AUTOMATIC PROTOCOL DETECTION - Always execute before any scan
            this.updateLoadingStatus('🔍 Auto-detecting optimal protocol...', 5);
            const detectedUrl = await this.autoDetectSilent(url);
            
            // Update URL input with detected URL silently
            this.urlInput.value = detectedUrl;
            
            // Update protocol display
            const protocol = detectedUrl.startsWith('https://') ? 'HTTPS' : 'HTTP';
            this.protocolDisplay.textContent = `✅ Auto-detected: ${protocol} | ${detectedUrl}`;
            this.protocolDisplay.className = 'protocol-display success';
            
            let results;
            
            // Route to appropriate API based on scan type
            switch (this.currentScanType) {
                case 'security':
                    results = await this.performSecurityScan(detectedUrl);
                    break;
                case 'performance':
                    results = await this.performPerformanceScan(detectedUrl);
                    break;
                case 'seo':
                    results = await this.performSEOScan(detectedUrl);
                    break;
                case 'web-patterns':
                    results = await this.performWebPatternsScan(detectedUrl);
                    break;
                case 'full':
                    results = await this.performFullAudit(detectedUrl);
                    break;
            }
            
            this.currentResults = results;
            this.displayResults(results);
            this.exportBtn.disabled = false;
            this.pdfSummaryBtn.disabled = false;
            this.pdfDetailedBtn.disabled = false;
            
        } catch (error) {
            console.error('Scan error:', error);
            this.displayError(error.message || 'Unknown error occurred during scan');
        } finally {
            this.isScanning = false;
            this.hideLoadingOverlay();
            this.updateScanButton(false);
        }
    }

    async performSecurityScan(url) {
        this.updateLoadingStatus('Initializing security modules...', 10);
        
        const response = await fetch(`${this.baseURL}/api/scan`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`Security scan failed: ${response.status}`);
        }

        this.updateLoadingStatus('Analyzing vulnerabilities...', 60);
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.message || 'Security scan failed');
        }

        this.updateLoadingStatus('Generating security report...', 90);
        return {
            type: 'security',
            data: data
        };
    }

    async performPerformanceScan(url) {
        this.updateLoadingStatus('Connecting to PageSpeed API...', 20);
        
        const response = await fetch(`${this.baseURL}/api/performance`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`Performance scan failed: ${response.status}`);
        }

        this.updateLoadingStatus('Analyzing Core Web Vitals...', 70);
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Performance scan failed');
        }

        this.updateLoadingStatus('Generating performance report...', 95);
        return {
            type: 'performance',
            data: data
        };
    }

    async performSEOScan(url) {
        this.updateLoadingStatus('Connecting to PageSpeed SEO API...', 20);
        
        // Use dedicated SEO API for dual mobile + desktop analysis
        const response = await fetch(`${this.baseURL}/api/seo`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`SEO scan failed: ${response.status}`);
        }

        this.updateLoadingStatus('Analyzing mobile + desktop SEO factors...', 70);
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'SEO scan failed');
        }

        this.updateLoadingStatus('Generating dual SEO report...', 95);
        return {
            type: 'seo',
            data: data
        };
    }

    async performWebPatternsScan(url) {
        this.updateLoadingStatus('Connecting to PageSpeed Best Practices API...', 20);
        
        // Use dedicated Web Patterns API for best practices analysis
        const response = await fetch(`${this.baseURL}/api/web-patterns`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`Web Patterns scan failed: ${response.status}`);
        }

        this.updateLoadingStatus('Analyzing web development best practices...', 70);
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Web Patterns scan failed');
        }

        this.updateLoadingStatus('Generating web patterns report...', 95);
        return {
            type: 'web-patterns',
            data: data
        };
    }

    async performFullAudit(url) {
        this.updateLoadingStatus('Starting comprehensive audit...', 5);
        
        const response = await fetch(`${this.baseURL}/api/audit`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ url: url })
        });

        if (!response.ok) {
            throw new Error(`Full audit failed: ${response.status}`);
        }

        this.updateLoadingStatus('Processing security + performance + SEO...', 40);
        await this.simulateProgress();
        
        const data = await response.json();
        
        if (!data.success) {
            throw new Error(data.error || 'Full audit failed');
        }

        this.updateLoadingStatus('Finalizing triple audit report...', 95);
        return {
            type: 'full',
            data: data
        };
    }

    async simulateProgress() {
        const steps = [
            { message: 'Scanning for vulnerabilities...', progress: 50 },
            { message: 'Analyzing performance metrics...', progress: 65 },
            { message: 'Evaluating SEO factors...', progress: 80 },
            { message: 'Compiling comprehensive report...', progress: 90 }
        ];

        for (const step of steps) {
            await new Promise(resolve => setTimeout(resolve, 800));
            this.updateLoadingStatus(step.message, step.progress);
        }
    }

    displayResults(results) {
        const { type, data } = results;
        
        let html = '';
        
        switch (type) {
            case 'security':
                html = this.renderSecurityResults(data);
                break;
            case 'performance':
                html = this.renderPerformanceResults(data);
                break;
            case 'seo':
                html = this.renderSEOResults(data);
                break;
            case 'web-patterns':
                html = this.renderWebPatternsResults(data);
                break;
            case 'full':
                html = this.renderFullAuditResults(data);
                break;
        }
        
        this.resultsContent.innerHTML = html;
        
        // Animate results appearance
        setTimeout(() => {
            this.resultsContent.querySelectorAll('.summary-card, .vulnerability-item').forEach((el, index) => {
                setTimeout(() => {
                    el.style.animation = 'slideInUp 0.5s ease forwards';
                }, index * 100);
            });
        }, 100);
    }

    renderSecurityResults(data) {
        const report = data.security_report || data.data || data;
        
        return `
            <div class=\"results-display\">
                <div class=\"results-header\">
                    <h3><i class=\"fas fa-shield-alt\"></i> Security Analysis Results</h3>
                    <div class=\"scan-meta\">
                        <span class=\"scan-time\">⚡ ${report.scan_duration || 0}s</span>
                        <span class=\"modules-count\">🔧 ${(report.modules_scanned || []).length} modules</span>
                        <div class=\"pdf-buttons-inline\">
                            <button class=\"action-btn pdf-btn\" onclick=\"window.zowtiCheck.generateModulePDF('security')\">
                                <i class=\"fas fa-chart-pie\"></i> Executive PDF
                            </button>
                            <button class=\"action-btn pdf-btn\" onclick=\"window.zowtiCheck.generateModulePDF('security', 'detailed')\">
                                <i class=\"fas fa-file-alt\"></i> Technical PDF
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class=\"results-summary\">
                    <div class=\"summary-card\">
                        <div class=\"summary-score ${this.getScoreClass(report.security_score || 0)}\">${report.security_score || 0}/100</div>
                        <div class=\"summary-label\">Security Score</div>
                    </div>
                    <div class=\"summary-card\">
                        <div class=\"summary-score\">${report.total_vulnerabilities || 0}</div>
                        <div class=\"summary-label\">Vulnerabilities</div>
                    </div>
                    <div class=\"summary-card\">
                        <div class=\"summary-score ${this.getRiskClass(report.risk_level || 'LOW')}\">${report.risk_level || 'UNKNOWN'}</div>
                        <div class=\"summary-label\">Risk Level</div>
                    </div>
                </div>
                
                ${this.renderVulnerabilities(report.vulnerabilities)}
            </div>
        `;
    }

    renderPerformanceResults(data) {
        const perf = data.performance || data.data || data;
        
        // Check if this is dual data (mobile + desktop)
        if (perf.mobile && perf.desktop) {
            return this.renderDualPerformanceResults(perf);
        }
        
        // Fallback to single device rendering
        return `
            <div class="results-display">
                <div class="results-header">
                    <h3><i class="fas fa-tachometer-alt"></i> Performance Analysis Results</h3>
                    <div class="pdf-buttons-inline">
                        <button class="action-btn pdf-btn" onclick="window.zowtiCheck.generateModulePDF('performance')">
                            <i class="fas fa-chart-pie"></i> Executive PDF
                        </button>
                        <button class="action-btn pdf-btn" onclick="window.zowtiCheck.generateModulePDF('performance', 'detailed')">
                            <i class="fas fa-file-alt"></i> Technical PDF
                        </button>
                    </div>
                </div>
                
                <div class="results-summary">
                    <div class="summary-card">
                        <div class="summary-score ${this.getScoreClass(perf.score || 0)}">${perf.score || 0}/100</div>
                        <div class="summary-label">Performance Score</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score">${(perf.core_vitals && perf.core_vitals.lcp) || 'N/A'}</div>
                        <div class="summary-label">LCP</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score">${(perf.core_vitals && perf.core_vitals.cls) || 'N/A'}</div>
                        <div class="summary-label">CLS</div>
                    </div>
                </div>
                
                <div class="performance-details">
                    <h4>Core Web Vitals</h4>
                    <div class="metrics-grid">
                        ${perf.metrics ? Object.entries(perf.metrics).map(([key, value]) => `
                            <div class="metric-item">
                                <span class="metric-name">${key.replace(/-/g, ' ').toUpperCase()}</span>
                                <span class="metric-value">${value}</span>
                            </div>
                        `).join('') : '<p>No metrics available</p>'}
                    </div>
                </div>
            </div>
        `;
    }

    renderDualPerformanceResults(data) {
        const mobile = data.mobile || {};
        const desktop = data.desktop || {};
        const summary = data.summary || {};
        
        return `
            <div class="results-display">
                <div class="results-header">
                    <h3><i class="fas fa-tachometer-alt"></i> Performance Analysis Results</h3>
                    <div class="scan-meta">
                        <span class="scan-time">⚡ ${data.total_time || 'N/A'}</span>
                        <span class="scan-devices">📱💻 Mobile + Desktop</span>
                        <div class="pdf-buttons-inline">
                            <button class="action-btn pdf-btn" onclick="window.zowtiCheck.generateModulePDF('performance')">
                                <i class="fas fa-chart-pie"></i> Executive PDF
                            </button>
                            <button class="action-btn pdf-btn" onclick="window.zowtiCheck.generateModulePDF('performance', 'detailed')">
                                <i class="fas fa-file-alt"></i> Technical PDF
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="dual-performance-summary">
                    <div class="device-comparison">
                        <div class="device-card mobile">
                            <div class="device-header">
                                <i class="fas fa-mobile-alt"></i>
                                <span class="device-name">Mobile</span>
                            </div>
                            <div class="device-score ${this.getScoreClass(mobile.score || 0)}">
                                ${mobile.score || 0}/100
                            </div>
                            <div class="device-status">${this.getPerformanceStatus(mobile.score || 0)}</div>
                        </div>
                        
                        <div class="score-difference">
                            <div class="diff-value">${summary.score_difference || 0}</div>
                            <div class="diff-label">Point Difference</div>
                        </div>
                        
                        <div class="device-card desktop">
                            <div class="device-header">
                                <i class="fas fa-desktop"></i>
                                <span class="device-name">Desktop</span>
                            </div>
                            <div class="device-score ${this.getScoreClass(desktop.score || 0)}">
                                ${desktop.score || 0}/100
                            </div>
                            <div class="device-status">${this.getPerformanceStatus(desktop.score || 0)}</div>
                        </div>
                    </div>
                </div>
                
                <div class="dual-vitals-comparison">
                    <h4>Core Web Vitals Comparison</h4>
                    <div class="vitals-grid">
                        <div class="vital-comparison">
                            <div class="vital-name">Largest Contentful Paint (LCP)</div>
                            <div class="vital-values">
                                <span class="mobile-value">📱 ${(mobile.core_vitals && mobile.core_vitals.lcp) || 'N/A'}</span>
                                <span class="desktop-value">💻 ${(desktop.core_vitals && desktop.core_vitals.lcp) || 'N/A'}</span>
                            </div>
                        </div>
                        <div class="vital-comparison">
                            <div class="vital-name">Cumulative Layout Shift (CLS)</div>
                            <div class="vital-values">
                                <span class="mobile-value">📱 ${(mobile.core_vitals && mobile.core_vitals.cls) || 'N/A'}</span>
                                <span class="desktop-value">💻 ${(desktop.core_vitals && desktop.core_vitals.cls) || 'N/A'}</span>
                            </div>
                        </div>
                        <div class="vital-comparison">
                            <div class="vital-name">First Contentful Paint (FCP)</div>
                            <div class="vital-values">
                                <span class="mobile-value">📱 ${(mobile.metrics && mobile.metrics['first-contentful-paint']) || 'N/A'}</span>
                                <span class="desktop-value">💻 ${(desktop.metrics && desktop.metrics['first-contentful-paint']) || 'N/A'}</span>
                            </div>
                        </div>
                        <div class="vital-comparison">
                            <div class="vital-name">Speed Index</div>
                            <div class="vital-values">
                                <span class="mobile-value">📱 ${(mobile.metrics && mobile.metrics['speed-index']) || 'N/A'}</span>
                                <span class="desktop-value">💻 ${(desktop.metrics && desktop.metrics['speed-index']) || 'N/A'}</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        `;
    }

    getPerformanceStatus(score) {
        if (score >= 90) return 'GOOD';
        if (score >= 50) return 'NEEDS IMPROVEMENT';
        return 'POOR';
    }

    renderSEOResults(data) {
        const seo = data.seo || data.data || data;
        
        // Check if this is dual SEO data (mobile + desktop)
        if (seo.mobile && seo.desktop) {
            return this.renderDualSEOResults(seo);
        }
        
        // Fallback to single device rendering (legacy compatibility)
        const report = data.security_report || data.data || data;
        const allVulns = Array.isArray(report.vulnerabilities) ? report.vulnerabilities : [];
        const seoVulns = allVulns.filter(v => v.type && v.type.includes('SEO'));
        
        return `
            <div class=\"results-display\">
                <div class=\"results-header\">
                    <h3><i class=\"fas fa-search\"></i> SEO Analysis Results</h3>
                    <div class=\"scan-meta\">
                        <span class=\"scan-time\">⚡ ${report.scan_duration || '0'}s</span>
                        <span class=\"seo-issues\">🔍 ${seoVulns.length} SEO issues</span>
                        <div class=\"pdf-buttons-inline\">
                            <button class=\"action-btn pdf-btn\" onclick=\"window.zowtiCheck.generateModulePDF('seo')\">
                                <i class=\"fas fa-chart-pie\"></i> Executive PDF
                            </button>
                            <button class=\"action-btn pdf-btn\" onclick=\"window.zowtiCheck.generateModulePDF('seo', 'detailed')\">
                                <i class=\"fas fa-file-alt\"></i> Technical PDF
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class=\"results-summary\">
                    <div class=\"summary-card\">
                        <div class=\"summary-score ${this.getScoreClass(report.security_score || 0)}\">${report.security_score || 0}/100</div>
                        <div class=\"summary-label\">SEO Score</div>
                    </div>
                    <div class=\"summary-card\">
                        <div class=\"summary-score\">${seoVulns.length}</div>
                        <div class=\"summary-label\">SEO Issues</div>
                    </div>
                    <div class=\"summary-card\">
                        <div class=\"summary-score ${this.getRiskClass(report.risk_level || 'LOW')}\">${report.risk_level || 'UNKNOWN'}</div>
                        <div class=\"summary-label\">SEO Health</div>
                    </div>
                </div>
                
                <div class=\"seo-analysis\">
                    <h4><i class=\"fas fa-search-plus\"></i> SEO Optimization Opportunities</h4>
                    ${this.renderVulnerabilities(seoVulns)}
                </div>
            </div>
        `;
    }

    renderDualSEOResults(data) {
        const mobile = data.mobile || {};
        const desktop = data.desktop || {};
        const summary = data.summary || {};
        
        return `
            <div class="results-display">
                <div class="results-header">
                    <h3><i class="fas fa-search"></i> SEO Analysis Results</h3>
                    <div class="scan-meta">
                        <span class="scan-time">⚡ ${data.total_time || 'N/A'}</span>
                        <span class="scan-devices">📱💻 Mobile + Desktop</span>
                    </div>
                </div>
                
                <div class="dual-performance-summary">
                    <div class="device-comparison">
                        <div class="device-card mobile">
                            <div class="device-header">
                                <i class="fas fa-mobile-alt"></i>
                                <span class="device-name">Mobile SEO</span>
                            </div>
                            <div class="device-score ${this.getScoreClass(mobile.seo_score || 0)}">
                                ${mobile.seo_score || 0}/100
                            </div>
                            <div class="device-status">${this.getSEOStatus(mobile.seo_score || 0)}</div>
                        </div>
                        
                        <div class="score-difference">
                            <div class="diff-value">${summary.score_difference || 0}</div>
                            <div class="diff-label">Point Difference</div>
                        </div>
                        
                        <div class="device-card desktop">
                            <div class="device-header">
                                <i class="fas fa-desktop"></i>
                                <span class="device-name">Desktop SEO</span>
                            </div>
                            <div class="device-score ${this.getScoreClass(desktop.seo_score || 0)}">
                                ${desktop.seo_score || 0}/100
                            </div>
                            <div class="device-status">${this.getSEOStatus(desktop.seo_score || 0)}</div>
                        </div>
                    </div>
                </div>
                
                <div class="dual-vitals-comparison">
                    <h4>SEO Issues Comparison</h4>
                    <div class="vitals-grid">
                        <div class="vital-comparison">
                            <div class="vital-name">Total Issues Found</div>
                            <div class="vital-values">
                                <span class="mobile-value">📱 ${mobile.total_issues || 0} issues</span>
                                <span class="desktop-value">💻 ${desktop.total_issues || 0} issues</span>
                            </div>
                        </div>
                        <div class="vital-comparison">
                            <div class="vital-name">SEO Health Status</div>
                            <div class="vital-values">
                                <span class="mobile-value">📱 ${mobile.risk_level || 'N/A'}</span>
                                <span class="desktop-value">💻 ${desktop.risk_level || 'N/A'}</span>
                            </div>
                        </div>
                        <div class="vital-comparison">
                            <div class="vital-name">Analysis Source</div>
                            <div class="vital-values">
                                <span class="mobile-value">📱 ${mobile.source || 'Google PageSpeed'}</span>
                                <span class="desktop-value">💻 ${desktop.source || 'Google PageSpeed'}</span>
                            </div>
                        </div>
                    </div>
                </div>
                
                ${this.renderSEOIssuesComparison(mobile, desktop)}
            </div>
        `;
    }

    getSEOStatus(score) {
        if (score >= 90) return 'EXCELLENT';
        if (score >= 80) return 'GOOD';
        if (score >= 60) return 'NEEDS IMPROVEMENT';
        return 'POOR';
    }

    renderSEOIssuesComparison(mobile, desktop) {
        const mobileIssues = mobile.issues || [];
        const desktopIssues = desktop.issues || [];
        
        if (mobileIssues.length === 0 && desktopIssues.length === 0) {
            return `
                <div class="no-vulnerabilities">
                    <i class="fas fa-check-circle"></i>
                    <p>No SEO issues detected on either device. Excellent SEO optimization!</p>
                </div>
            `;
        }
        
        return `
            <div class="seo-issues-comparison">
                <h4><i class="fas fa-search-plus"></i> SEO Issues by Device</h4>
                
                <div class="device-issues-grid">
                    <div class="device-issues mobile-issues">
                        <h5>📱 Mobile Issues (${mobileIssues.length})</h5>
                        ${mobileIssues.length > 0 ? 
                            mobileIssues.map(issue => `
                                <div class="issue-item ${issue.severity || 'info'}">
                                    <span class="issue-title">${issue.type || 'SEO Issue'}</span>
                                    <span class="issue-severity ${issue.severity || 'info'}">${issue.severity || 'info'}</span>
                                </div>
                            `).join('') :
                            '<p class="no-issues">No mobile-specific SEO issues found</p>'
                        }
                    </div>
                    
                    <div class="device-issues desktop-issues">
                        <h5>💻 Desktop Issues (${desktopIssues.length})</h5>
                        ${desktopIssues.length > 0 ? 
                            desktopIssues.map(issue => `
                                <div class="issue-item ${issue.severity || 'info'}">
                                    <span class="issue-title">${issue.type || 'SEO Issue'}</span>
                                    <span class="issue-severity ${issue.severity || 'info'}">${issue.severity || 'info'}</span>
                                </div>
                            `).join('') :
                            '<p class="no-issues">No desktop-specific SEO issues found</p>'
                        }
                    </div>
                </div>
            </div>
        `;
    }

    renderWebPatternsResults(data) {
        const patterns = data.web_patterns || data.data || data;
        
        return `
            <div class="results-display">
                <div class="results-header">
                    <h3><i class="fas fa-code"></i> Web Development Patterns Results</h3>
                    <div class="scan-meta">
                        <span class="scan-time">⚡ Analysis completed</span>
                        <span class="patterns-source">📊 Google PageSpeed Best Practices</span>
                        <div class="pdf-buttons-inline">
                            <button class="action-btn pdf-btn" onclick="window.zowtiCheck.generateModulePDF('web_patterns')">
                                <i class="fas fa-chart-pie"></i> Executive PDF
                            </button>
                            <button class="action-btn pdf-btn" onclick="window.zowtiCheck.generateModulePDF('web_patterns', 'detailed')">
                                <i class="fas fa-file-alt"></i> Technical PDF
                            </button>
                        </div>
                    </div>
                </div>
                
                <div class="results-summary">
                    <div class="summary-card">
                        <div class="summary-score ${this.getScoreClass(patterns.best_practices_score || 0)}">
                            ${patterns.best_practices_score || 0}/100
                        </div>
                        <div class="summary-label">Best Practices Score</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score">${patterns.total_issues || 0}</div>
                        <div class="summary-label">Issues Found</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score ${this.getWebPatternsClass(patterns.best_practices_score || 0)}">
                            ${this.getWebPatternsStatus(patterns.best_practices_score || 0)}
                        </div>
                        <div class="summary-label">Code Quality</div>
                    </div>
                </div>
                
                <div class="web-patterns-analysis">
                    <h4><i class="fas fa-tools"></i> Development Best Practices</h4>
                    ${this.renderWebPatternsIssues(patterns.issues || [])}
                </div>
                
                <div class="patterns-info">
                    <p><strong>Analysis Source:</strong> ${patterns.source || 'Google PageSpeed Insights Best Practices'}</p>
                    <p><strong>Categories Analyzed:</strong> HTTPS usage, HTTP/2 implementation, vulnerable libraries, console errors, image optimization, font preloading, and character encoding.</p>
                </div>
            </div>
        `;
    }

    getWebPatternsStatus(score) {
        if (score >= 90) return 'GOOD';
        if (score >= 80) return 'SATISFACTORY';
        if (score >= 60) return 'NEEDS WORK';
        return 'POOR';
    }

    getWebPatternsClass(score) {
        if (score >= 80) return 'success';
        if (score >= 60) return 'warning';
        return 'error';
    }

    renderWebPatternsIssues(issues) {
        if (!issues || issues.length === 0) {
            return `
                <div class="no-vulnerabilities">
                    <i class="fas fa-check-circle"></i>
                    <p>All best practices are being followed! Excellent web development patterns.</p>
                </div>
            `;
        }
        
        return `
            <div class="patterns-issues-list">
                ${issues.map(issue => `
                    <div class="issue-item ${issue.severity || 'info'}">
                        <div class="issue-header">
                            <span class="issue-title">${issue.type || 'Best Practice Issue'}</span>
                            <span class="issue-severity ${issue.severity || 'info'}">${issue.severity || 'info'}</span>
                        </div>
                        <div class="issue-description">${issue.description || 'No description available'}</div>
                    </div>
                `).join('')}
            </div>
        `;
    }

    renderFullAuditResults(data) {
        const security = data.security || {};
        const performance = data.performance || {};
        const seo = data.seo || {};
        const webPatterns = data.web_patterns || {};
        
        // Handle scores for all modules
        const securityScore = security.connection_error ? 'ERROR' : (security.security_score || 0);
        const performanceScore = performance.error ? 'ERROR' : this.getAveragePerformanceScore(performance);
        const seoScore = seo.error ? 'ERROR' : this.getAverageSEOScore(seo);
        const patternsScore = webPatterns.error ? 'ERROR' : (webPatterns.best_practices_score || 0);
        
        // Extract vulnerabilities - count from total_vulnerabilities for accuracy
        const securityIssues = security.total_vulnerabilities || 0;
        
        // Extract vulnerabilities array for detailed display
        let vulnerabilities = [];
        if (security.vulnerabilities) {
            if (Array.isArray(security.vulnerabilities)) {
                vulnerabilities = security.vulnerabilities;
            } else if (typeof security.vulnerabilities === 'object') {
                const vulnObj = security.vulnerabilities;
                vulnerabilities = [
                    ...(vulnObj.critical_high || []),
                    ...(vulnObj.high || []),
                    ...(vulnObj.medium || []),
                    ...(vulnObj.low || [])
                ];
            }
        }
        
        const totalIssues = vulnerabilities.length + (seo.summary?.total_issues || 0) + (webPatterns.total_issues || 0);
        
        return `
            <div class="results-display">
                <div class="results-header">
                    <h3><i class="fas fa-star"></i> Complete 4-Module Audit Results</h3>
                    <div class="scan-meta">
                        <span class="scan-time">⚡ ${data.audit_duration || 0}s</span>
                        <span class="timestamp">📅 ${data.timestamp || 'Unknown'}</span>
                    </div>
                </div>
                
                <div class="results-summary">
                    <div class="summary-card">
                        <div class="summary-score ${securityScore === 'ERROR' ? 'error' : this.getScoreClass(securityScore)}">${securityScore}${securityScore !== 'ERROR' ? '/100' : ''}</div>
                        <div class="summary-label">Security</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score">📱${performance.mobile?.score || 0} 💻${performance.desktop?.score || 0}</div>
                        <div class="summary-label">Performance</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score">📱${seo.mobile?.seo_score || 0} 💻${seo.desktop?.seo_score || 0}</div>
                        <div class="summary-label">SEO</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score ${patternsScore === 'ERROR' ? 'error' : this.getScoreClass(patternsScore)}">${patternsScore}${patternsScore !== 'ERROR' ? '/100' : ''}</div>
                        <div class="summary-label">Web Patterns</div>
                    </div>
                    <div class="summary-card">
                        <div class="summary-score">${securityIssues}+${(seo.summary?.total_issues || 0) + (webPatterns.total_issues || 0)}</div>
                        <div class="summary-label">Security + Others</div>
                    </div>
                </div>
                
                <div class="audit-summary-section">
                    <h4><i class="fas fa-chart-line"></i> Executive Summary</h4>
                    <div class="summary-grid">
                        <div class="module-summary security-summary">
                            <div class="module-header">
                                <i class="fas fa-shield-alt"></i>
                                <span>Security Analysis</span>
                            </div>
                            ${security.connection_error ? 
                                `<div class="module-status error">Connection Error</div>` :
                                `
                                <div class="module-score ${this.getScoreClass(securityScore)}">${securityScore}/100</div>
                                <div class="module-details">
                                    <span class="detail-item">${vulnerabilities.length} vulnerabilities</span>
                                    <span class="detail-item risk-${(security.risk_level || 'low').toLowerCase()}">${security.risk_level || 'Unknown'} Risk</span>
                                </div>
                                `
                            }
                        </div>
                        
                        <div class="module-summary performance-summary">
                            <div class="module-header">
                                <i class="fas fa-tachometer-alt"></i>
                                <span>Performance Analysis</span>
                            </div>
                            ${performance.error ? 
                                `<div class="module-status error">Analysis Error</div>` :
                                `
                                <div class="module-score ${this.getScoreClass(performanceScore)}">${performanceScore}/100</div>
                                <div class="module-details">
                                    <span class="detail-item">📱 ${performance.mobile?.score || 0}/100</span>
                                    <span class="detail-item">💻 ${performance.desktop?.score || 0}/100</span>
                                </div>
                                `
                            }
                        </div>
                        
                        <div class="module-summary seo-summary">
                            <div class="module-header">
                                <i class="fas fa-search"></i>
                                <span>SEO Analysis</span>
                            </div>
                            ${seo.error ? 
                                `<div class="module-status error">Analysis Error</div>` :
                                `
                                <div class="module-score ${this.getScoreClass(seoScore)}">${seoScore}/100</div>
                                <div class="module-details">
                                    <span class="detail-item">📱 ${seo.mobile?.seo_score || 0}/100</span>
                                    <span class="detail-item">💻 ${seo.desktop?.seo_score || 0}/100</span>
                                </div>
                                `
                            }
                        </div>
                        
                        <div class="module-summary patterns-summary">
                            <div class="module-header">
                                <i class="fas fa-code"></i>
                                <span>Web Development Patterns</span>
                            </div>
                            ${webPatterns.error ? 
                                `<div class="module-status error">Analysis Error</div>` :
                                `
                                <div class="module-score ${this.getScoreClass(patternsScore)}">${patternsScore}/100</div>
                                <div class="module-details">
                                    <span class="detail-item">${webPatterns.total_issues || 0} issues found</span>
                                    <span class="detail-item quality-${this.getWebPatternsStatus(patternsScore).toLowerCase().replace(' ', '-')}">${this.getWebPatternsStatus(patternsScore)}</span>
                                </div>
                                `
                            }
                        </div>
                    </div>
                    
                    <div class="audit-footer">
                        <p><strong>📊 Analysis Complete:</strong> Comprehensive security, performance, SEO, and web development patterns audit completed successfully.</p>
                        <p><strong>💡 Recommendation:</strong> For a deep-dive analysis, download the <strong>Technical PDF</strong> or export the <strong>JSON</strong> report.</p>
                    </div>
                </div>
            </div>
        `;
    }

    getAveragePerformanceScore(performance) {
        if (performance.mobile?.score && performance.desktop?.score) {
            return Math.round((performance.mobile.score + performance.desktop.score) / 2);
        }
        return performance.score || 0;
    }

    getAverageSEOScore(seo) {
        if (seo.mobile?.seo_score && seo.desktop?.seo_score) {
            return Math.round((seo.mobile.seo_score + seo.desktop.seo_score) / 2);
        }
        return seo.seo_score || 0;
    }

    renderVulnerabilities(vulnerabilities) {
        // Ensure vulnerabilities is always an array
        const vulnArray = Array.isArray(vulnerabilities) ? vulnerabilities : [];
        
        if (!vulnArray || vulnArray.length === 0) {
            return `
                <div class=\"no-vulnerabilities\">
                    <i class=\"fas fa-check-circle\"></i>
                    <p>No vulnerabilities detected. Excellent security posture!</p>
                </div>
            `;
        }

        return `
            <div class=\"vulnerability-list\">
                <h4>Security Issues Detected</h4>
                ${vulnArray.map(vuln => `
                    <div class=\"vulnerability-item ${vuln.severity || 'info'}\">
                        <div class=\"vuln-header\">
                            <span class=\"vuln-title\">${vuln.type || 'Unknown Issue'}</span>
                            <span class=\"vuln-severity ${vuln.severity || 'info'}\">${vuln.severity || 'info'}</span>
                        </div>
                        <div class=\"vuln-description\">${vuln.description || 'No description available'}</div>
                        ${vuln.location ? `<div class=\"vuln-location\"><strong>Location:</strong> ${vuln.location}</div>` : ''}
                        ${vuln.evidence ? `<div class=\"vuln-evidence\"><strong>Evidence:</strong> <code>${vuln.evidence}</code></div>` : ''}
                    </div>
                `).join('')}
            </div>
        `;
    }


    displayError(message) {
        this.resultsContent.innerHTML = `
            <div class=\"error-display\">
                <div class=\"error-icon\">
                    <i class=\"fas fa-exclamation-triangle\"></i>
                </div>
                <h3>Scan Failed</h3>
                <p>${message}</p>
                <button class=\"retry-btn\" onclick=\"location.reload()\">
                    <i class=\"fas fa-redo\"></i>
                    Try Again
                </button>
            </div>
        `;
    }

    exportResults() {
        if (!this.currentResults) return;
        
        const dataStr = JSON.stringify(this.currentResults, null, 2);
        const dataBlob = new Blob([dataStr], { type: 'application/json' });
        
        const link = document.createElement('a');
        link.href = URL.createObjectURL(dataBlob);
        link.download = `zowticheck-report-${Date.now()}.json`;
        link.click();
        
        console.log('📊 Results exported successfully');
    }

    generatePDFSummary() {
        if (!this.currentResults) {
            alert('No audit results available. Please run a Full Audit first.');
            return;
        }
        
        // Create summary data for client presentation
        const summaryData = {
            type: 'executive_summary',
            target: this.currentResults.target,
            timestamp: this.currentResults.timestamp,
            security_score: this.currentResults.security?.security_score || 0,
            performance_mobile: this.currentResults.performance?.mobile?.score || 0,
            performance_desktop: this.currentResults.performance?.desktop?.score || 0,
            seo_mobile: this.currentResults.seo?.mobile?.seo_score || 0,
            seo_desktop: this.currentResults.seo?.desktop?.seo_score || 0,
            web_patterns_score: this.currentResults.web_patterns?.best_practices_score || 0,
            total_security_issues: this.currentResults.security?.total_vulnerabilities || 0,
            total_seo_issues: this.currentResults.seo?.summary?.total_issues || 0,
            total_web_issues: this.currentResults.web_patterns?.total_issues || 0
        };
        
        this.downloadPDF(summaryData, 'summary');
    }

    generatePDFDetailed() {
        if (!this.currentResults) {
            alert('No audit results available. Please run a Full Audit first.');
            return;
        }
        
        // Use complete audit data for technical report
        const detailedData = {
            type: 'technical_report',
            ...this.currentResults
        };
        
        this.downloadPDF(detailedData, 'detailed');
    }

    generateModulePDF(moduleType, reportType = 'summary') {
        if (!this.currentResults) {
            alert('No audit results available. Please run a scan first.');
            return;
        }

        const moduleData = {
            type: reportType === 'summary' ? 'executive_summary' : 'technical_report',
            module: moduleType,
            target: this.currentResults.target || 'Unknown',
            timestamp: new Date().toISOString(),
            ...this.currentResults
        };

        console.log(`🔄 Generating ${reportType} PDF for ${moduleType} module...`);
        this.downloadPDF(moduleData, reportType);
    }

    async downloadPDF(data, type) {
        try {
            const response = await fetch(`${this.baseURL}/api/generate-pdf`, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    data: data,
                    report_type: type
                })
            });

            if (!response.ok) {
                throw new Error(`PDF generation failed: ${response.status}`);
            }

            const blob = await response.blob();
            const link = document.createElement('a');
            link.href = URL.createObjectURL(blob);
            
            const filename = type === 'summary' 
                ? `zowticheck-executive-summary-${Date.now()}.pdf`
                : `zowticheck-technical-report-${Date.now()}.pdf`;
            
            link.download = filename;
            link.click();
            
            console.log(`📄 PDF ${type} report generated successfully`);
        } catch (error) {
            console.error('PDF generation error:', error);
            alert(`Failed to generate PDF report: ${error.message}`);
        }
    }

    showLoadingOverlay() {
        this.loadingOverlay.classList.remove('hidden');
        this.updateLoadingStatus('Initializing scan...', 0);
    }

    hideLoadingOverlay() {
        this.loadingOverlay.classList.add('hidden');
    }

    updateLoadingStatus(message, progress) {
        this.loadingStatus.textContent = message;
        this.progressBar.style.width = `${progress}%`;
    }

    updateScanButton(loading) {
        if (loading) {
            this.scanBtn.classList.add('loading');
            this.scanBtn.disabled = true;
        } else {
            this.scanBtn.classList.remove('loading');
            this.scanBtn.disabled = false;
        }
    }

    getScoreClass(score) {
        if (score >= 80) return 'success';
        if (score >= 60) return 'warning';
        return 'error';
    }

    getRiskClass(risk) {
        const riskMap = {
            'LOW': 'success',
            'MEDIUM': 'warning', 
            'HIGH': 'error',
            'CRITICAL': 'error'
        };
        return riskMap[risk] || 'info';
    }
}

// Enhanced CSS for dynamic content
const dynamicStyles = `
    <style>
    .results-display {
        background: var(--gradient-panel);
        border: 1px solid var(--border-primary);
        border-radius: 16px;
        padding: 2rem;
        margin-top: 1rem;
    }
    
    .results-header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        margin-bottom: 2rem;
        padding-bottom: 1rem;
        border-bottom: 1px solid var(--border-primary);
    }
    
    .results-header h3 {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        color: var(--text-primary);
        margin: 0;
    }
    
    .scan-meta {
        display: flex;
        gap: 1rem;
        font-size: 0.9rem;
        color: var(--text-secondary);
        font-family: 'JetBrains Mono', monospace;
    }
    
    .results-summary {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
        gap: 1.5rem;
        margin-bottom: 2rem;
    }
    
    .summary-card {
        background: var(--bg-input);
        border: 1px solid var(--border-primary);
        border-radius: 12px;
        padding: 1.5rem;
        text-align: center;
        transition: transform 0.3s ease;
    }
    
    .summary-card:hover {
        transform: translateY(-2px);
    }
    
    .summary-score {
        font-size: 2rem;
        font-weight: 700;
        font-family: 'JetBrains Mono', monospace;
        margin-bottom: 0.5rem;
    }
    
    .summary-score.success { color: var(--cyber-green); }
    .summary-score.warning { color: var(--cyber-yellow); }
    .summary-score.error { color: var(--cyber-red); }
    
    .summary-label {
        color: var(--text-secondary);
        font-size: 0.9rem;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    .vulnerability-list h4 {
        color: var(--text-primary);
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    
    .no-vulnerabilities {
        text-align: center;
        padding: 3rem;
        color: var(--cyber-green);
    }
    
    .no-vulnerabilities i {
        font-size: 3rem;
        margin-bottom: 1rem;
    }
    
    .error-display {
        text-align: center;
        padding: 3rem;
    }
    
    .error-icon {
        font-size: 3rem;
        color: var(--cyber-red);
        margin-bottom: 1rem;
    }
    
    .retry-btn {
        padding: 1rem 2rem;
        background: var(--gradient-button);
        border: none;
        border-radius: 8px;
        color: var(--bg-primary);
        font-weight: 600;
        cursor: pointer;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin: 1rem auto;
        transition: transform 0.3s ease;
    }
    
    .retry-btn:hover {
        transform: translateY(-2px);
    }
    
    .audit-sections {
        display: flex;
        flex-direction: column;
        gap: 2rem;
    }
    
    .audit-section h4 {
        color: var(--text-primary);
        margin-bottom: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
        padding-bottom: 0.5rem;
        border-bottom: 1px solid var(--border-primary);
    }
    
    .performance-summary p {
        margin-bottom: 0.5rem;
        color: var(--text-secondary);
    }
    
    .metrics-grid {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 1rem;
        margin-top: 1rem;
    }
    
    .metric-item {
        background: var(--bg-input);
        padding: 1rem;
        border-radius: 8px;
        border: 1px solid var(--border-primary);
    }
    
    .metric-name {
        display: block;
        font-size: 0.8rem;
        color: var(--text-secondary);
        text-transform: uppercase;
        margin-bottom: 0.5rem;
    }
    
    .metric-value {
        font-size: 1.1rem;
        font-weight: 600;
        color: var(--cyber-green);
        font-family: 'JetBrains Mono', monospace;
    }
    
    .vuln-location, .vuln-evidence {
        margin-top: 0.5rem;
        font-size: 0.85rem;
        color: var(--text-muted);
    }
    
    .vuln-evidence code {
        background: var(--bg-tertiary);
        padding: 0.25rem 0.5rem;
        border-radius: 4px;
        font-family: 'JetBrains Mono', monospace;
    }
    
    @keyframes slideInUp {
        from {
            opacity: 0;
            transform: translateY(20px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    </style>
`;

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    // Inject dynamic styles
    document.head.insertAdjacentHTML('beforeend', dynamicStyles);
    
    // Initialize the main application
    window.zowtiCheck = new ZowTiCheckUI();
    
    // Add some cybersecurity flair
    console.log('%c🛡️ ZowTiCheck Security Suite Loaded', 'color: #00ff88; font-size: 16px; font-weight: bold;');
    console.log('%c⚡ Ready for professional security audits', 'color: #00d4ff; font-size: 12px;');
});