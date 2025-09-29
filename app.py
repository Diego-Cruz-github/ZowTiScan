#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ZowTiScan Flask Backend
Integra o scanner Python com o frontend via API REST
"""

# Basic encoding declaration
import sys
import os

from flask import Flask, request, jsonify, send_from_directory
from flask_cors import CORS
import json
import time
from scanner import SecurityScanner

app = Flask(__name__)
CORS(app)  # Permite requests do frontend

@app.route('/')
def index():
    """Serve the frontend"""
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve static files"""
    return send_from_directory('frontend', filename)

@app.route('/api/scan', methods=['POST'])
def scan_endpoint():
    """API endpoint for scanning URLs"""
    try:
        data = request.get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({
                'error': 'URL is required'
            }), 400
        
        # Initialize scanner
        scanner = SecurityScanner()
        
        # Perform scan
        start_time = time.time()
        vulnerabilities = scanner.scan_url(url)
        duration = time.time() - start_time
        
        # Generate report
        report = scanner.generate_report(url, vulnerabilities)
        report['scan_duration'] = round(duration, 2)
        
        return jsonify(report)
        
    except Exception as e:
        return jsonify({
            'error': f'Internal server error: {str(e)}'
        }), 500

@app.route('/api/smart-detect', methods=['POST'])
def smart_detect_endpoint():
    """API endpoint for smart URL detection"""
    try:
        data = request.get_json()
        domain = data.get('domain', '').strip()
        
        if not domain:
            return jsonify({
                'error': 'Domain is required'
            }), 400
        
        # Initialize scanner
        scanner = SecurityScanner()
        
        # Perform smart detection
        working_url, error = scanner._smart_url_detection(domain)
        
        if error:
            return jsonify({
                'success': False,
                'error': error
            })
        
        # Extract protocol
        protocol = 'https' if working_url.startswith('https://') else 'http'
        
        return jsonify({
            'success': True,
            'protocol': protocol,
            'finalUrl': working_url,
            'error': None
        })
        
    except Exception as e:
        return jsonify({
            'success': False,
            'error': f'Detection failed: {str(e)}'
        })

if __name__ == '__main__':
    print("ZowTiScan Backend Starting...")
    print("Frontend: http://localhost:5000")
    print("API: http://localhost:5000/api/scan")
    print("Safe Mode: Passive Analysis Only")
    app.run(debug=True, host='0.0.0.0', port=5000)