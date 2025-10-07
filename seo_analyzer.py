#!/usr/bin/env python3
"""
ZowTiCheck SEO Analyzer Module
Senior Engineering: Modular, extensible, and maintainable SEO analysis
"""

import re
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urljoin
from bs4 import BeautifulSoup
from dataclasses import dataclass
from models import SEOMetricsModel

@dataclass
class SEOIssue:
    """SEO issue data structure"""
    type: str
    severity: str  # critical, high, medium, low
    description: str
    location: str
    recommendation: str
    impact: str

class SEOAnalyzer:
    """
    Professional SEO Analyzer
    
    Architecture: Single Responsibility Principle
    - Focused only on SEO analysis
    - Returns structured data for reporting layer
    - Configurable analysis depth
    """
    
    def __init__(self, config=None):
        self.config = config
        self.issues = []
        
        # SEO Best Practices Constants
        self.OPTIMAL_TITLE_LENGTH = (30, 60)
        self.OPTIMAL_META_DESC_LENGTH = (150, 160)
        self.OPTIMAL_URL_LENGTH = 75
        self.MAX_H1_COUNT = 1
        self.MIN_INTERNAL_LINKS = 3
        
        # Critical SEO factors for scoring
        self.SEO_WEIGHTS = {
            'title_tag': 20,
            'meta_description': 15,
            'h1_structure': 15,
            'alt_text': 10,
            'internal_linking': 10,
            'url_structure': 10,
            'content_quality': 10,
            'technical_seo': 10
        }
    
    def analyze_page(self, url: str, response, soup: BeautifulSoup) -> SEOMetricsModel:
        """
        Main SEO analysis entry point
        
        Senior Architecture: Clear separation of concerns
        """
        self.issues = []  # Reset for each analysis
        
        # Core SEO Elements
        title_analysis = self._analyze_title_tag(soup)
        meta_analysis = self._analyze_meta_description(soup)
        heading_analysis = self._analyze_heading_structure(soup)
        image_analysis = self._analyze_images(soup)
        link_analysis = self._analyze_links(soup, url)
        url_analysis = self._analyze_url_structure(url)
        content_analysis = self._analyze_content_quality(soup)
        technical_analysis = self._analyze_technical_seo(soup, response)
        
        # Calculate comprehensive SEO score
        seo_score = self._calculate_seo_score(
            title_analysis, meta_analysis, heading_analysis,
            image_analysis, link_analysis, url_analysis,
            content_analysis, technical_analysis
        )
        
        # Build SEO metrics model
        return SEOMetricsModel(
            score=seo_score,
            title_length=title_analysis.get('length', 0),
            meta_description_length=meta_analysis.get('length', 0),
            h1_count=heading_analysis.get('h1_count', 0),
            h2_count=heading_analysis.get('h2_count', 0),
            alt_text_missing=image_analysis.get('missing_alt', 0),
            internal_links=link_analysis.get('internal_count', 0),
            external_links=link_analysis.get('external_count', 0)
        )
    
    def _analyze_title_tag(self, soup: BeautifulSoup) -> Dict:
        """Analyze title tag optimization"""
        title_tag = soup.find('title')
        
        if not title_tag or not title_tag.string:
            self.issues.append(SEOIssue(
                type="Missing Title Tag",
                severity="critical",
                description="Page is missing a title tag",
                location="<head>",
                recommendation="Add a descriptive title tag between 30-60 characters",
                impact="Severe impact on search rankings and click-through rates"
            ))
            return {'length': 0, 'score': 0}
        
        title_text = title_tag.string.strip()
        title_length = len(title_text)
        
        # Title length analysis
        if title_length < self.OPTIMAL_TITLE_LENGTH[0]:
            self.issues.append(SEOIssue(
                type="Title Too Short",
                severity="medium",
                description=f"Title tag is only {title_length} characters",
                location="<title>",
                recommendation=f"Expand title to {self.OPTIMAL_TITLE_LENGTH[0]}-{self.OPTIMAL_TITLE_LENGTH[1]} characters",
                impact="Missed opportunity for keyword optimization"
            ))
        elif title_length > self.OPTIMAL_TITLE_LENGTH[1]:
            self.issues.append(SEOIssue(
                type="Title Too Long",
                severity="medium",
                description=f"Title tag is {title_length} characters (may be truncated)",
                location="<title>",
                recommendation=f"Reduce title to under {self.OPTIMAL_TITLE_LENGTH[1]} characters",
                impact="Title may be cut off in search results"
            ))
        
        # Title quality checks
        if not any(char.isupper() for char in title_text):
            self.issues.append(SEOIssue(
                type="Title Case Issue",
                severity="low",
                description="Title tag has no capital letters",
                location="<title>",
                recommendation="Use proper title case for better readability",
                impact="Minor impact on click-through rates"
            ))
        
        # Calculate title score
        score = 100
        if title_length < self.OPTIMAL_TITLE_LENGTH[0] or title_length > self.OPTIMAL_TITLE_LENGTH[1]:
            score -= 30
        
        return {'length': title_length, 'score': score, 'text': title_text}
    
    def _analyze_meta_description(self, soup: BeautifulSoup) -> Dict:
        """Analyze meta description optimization"""
        meta_desc = soup.find('meta', attrs={'name': 'description'})
        
        if not meta_desc or not meta_desc.get('content'):
            self.issues.append(SEOIssue(
                type="Missing Meta Description",
                severity="high",
                description="Page is missing a meta description",
                location="<head>",
                recommendation=f"Add a compelling meta description of {self.OPTIMAL_META_DESC_LENGTH[0]}-{self.OPTIMAL_META_DESC_LENGTH[1]} characters",
                impact="Significant impact on click-through rates from search results"
            ))
            return {'length': 0, 'score': 0}
        
        desc_text = meta_desc.get('content', '').strip()
        desc_length = len(desc_text)
        
        # Meta description length analysis
        if desc_length < self.OPTIMAL_META_DESC_LENGTH[0]:
            self.issues.append(SEOIssue(
                type="Meta Description Too Short",
                severity="medium",
                description=f"Meta description is only {desc_length} characters",
                location="<meta name='description'>",
                recommendation=f"Expand description to {self.OPTIMAL_META_DESC_LENGTH[0]}-{self.OPTIMAL_META_DESC_LENGTH[1]} characters",
                impact="Missed opportunity for compelling search result snippet"
            ))
        elif desc_length > self.OPTIMAL_META_DESC_LENGTH[1]:
            self.issues.append(SEOIssue(
                type="Meta Description Too Long",
                severity="medium",
                description=f"Meta description is {desc_length} characters (may be truncated)",
                location="<meta name='description'>",
                recommendation=f"Reduce description to under {self.OPTIMAL_META_DESC_LENGTH[1]} characters",
                impact="Description may be cut off in search results"
            ))
        
        # Calculate meta description score
        score = 100
        if desc_length < self.OPTIMAL_META_DESC_LENGTH[0] or desc_length > self.OPTIMAL_META_DESC_LENGTH[1]:
            score -= 25
        
        return {'length': desc_length, 'score': score, 'text': desc_text}
    
    def _analyze_heading_structure(self, soup: BeautifulSoup) -> Dict:
        """Analyze heading structure and hierarchy"""
        h1_tags = soup.find_all('h1')
        h2_tags = soup.find_all('h2')
        h3_tags = soup.find_all('h3')
        h4_tags = soup.find_all('h4')
        h5_tags = soup.find_all('h5')
        h6_tags = soup.find_all('h6')
        
        h1_count = len(h1_tags)
        h2_count = len(h2_tags)
        
        # H1 analysis
        if h1_count == 0:
            self.issues.append(SEOIssue(
                type="Missing H1 Tag",
                severity="high",
                description="Page is missing an H1 heading",
                location="<body>",
                recommendation="Add exactly one H1 tag with primary keyword",
                impact="Search engines need clear page topic indication"
            ))
        elif h1_count > 1:
            self.issues.append(SEOIssue(
                type="Multiple H1 Tags",
                severity="medium",
                description=f"Page has {h1_count} H1 tags (should have exactly 1)",
                location="<body>",
                recommendation="Use only one H1 tag per page, convert others to H2-H6",
                impact="Dilutes page topic focus for search engines"
            ))
        
        # H2 analysis
        if h2_count == 0 and len(soup.get_text().split()) > 300:
            self.issues.append(SEOIssue(
                type="Missing H2 Structure",
                severity="low",
                description="Long content without H2 headings for structure",
                location="<body>",
                recommendation="Add H2 headings to break up content sections",
                impact="Poor content readability and structure"
            ))
        
        # Heading hierarchy check
        if h3_tags and not h2_tags:
            self.issues.append(SEOIssue(
                type="Broken Heading Hierarchy",
                severity="low",
                description="H3 tags found without H2 tags",
                location="<body>",
                recommendation="Maintain proper heading hierarchy (H1→H2→H3→etc.)",
                impact="Poor content structure for accessibility and SEO"
            ))
        
        # Calculate heading score
        score = 100
        if h1_count != 1:
            score -= 30
        if h2_count == 0 and len(soup.get_text().split()) > 300:
            score -= 15
        
        return {
            'h1_count': h1_count,
            'h2_count': h2_count,
            'h3_count': len(h3_tags),
            'h4_count': len(h4_tags),
            'h5_count': len(h5_tags),
            'h6_count': len(h6_tags),
            'score': score
        }
    
    def _analyze_images(self, soup: BeautifulSoup) -> Dict:
        """Analyze image optimization"""
        images = soup.find_all('img')
        total_images = len(images)
        missing_alt = 0
        missing_src = 0
        
        for img in images:
            # Alt text analysis
            if not img.get('alt'):
                missing_alt += 1
            
            # Src analysis
            if not img.get('src'):
                missing_src += 1
        
        # Generate issues for missing alt text
        if missing_alt > 0:
            severity = "high" if missing_alt > total_images * 0.5 else "medium"
            self.issues.append(SEOIssue(
                type="Missing Alt Text",
                severity=severity,
                description=f"{missing_alt} out of {total_images} images missing alt text",
                location="<img> tags",
                recommendation="Add descriptive alt text to all images",
                impact="Poor accessibility and missed SEO opportunities"
            ))
        
        # Calculate image score
        score = 100
        if total_images > 0:
            alt_ratio = (total_images - missing_alt) / total_images
            score = int(alt_ratio * 100)
        
        return {
            'total_images': total_images,
            'missing_alt': missing_alt,
            'missing_src': missing_src,
            'score': score
        }
    
    def _analyze_links(self, soup: BeautifulSoup, current_url: str) -> Dict:
        """Analyze internal and external linking"""
        links = soup.find_all('a', href=True)
        internal_links = 0
        external_links = 0
        broken_links = 0
        
        current_domain = urlparse(current_url).netloc
        
        for link in links:
            href = link.get('href', '').strip()
            
            if not href or href.startswith('#'):
                continue
            
            # Determine if internal or external
            if href.startswith('http'):
                link_domain = urlparse(href).netloc
                if link_domain == current_domain:
                    internal_links += 1
                else:
                    external_links += 1
            elif href.startswith('/') or not href.startswith('http'):
                internal_links += 1
        
        # Internal linking analysis
        if internal_links < self.MIN_INTERNAL_LINKS:
            self.issues.append(SEOIssue(
                type="Insufficient Internal Links",
                severity="medium",
                description=f"Only {internal_links} internal links found (recommended: {self.MIN_INTERNAL_LINKS}+)",
                location="<a> tags",
                recommendation="Add more internal links to related content",
                impact="Missed opportunities for site structure and PageRank distribution"
            ))
        
        # Calculate linking score
        score = 100
        if internal_links < self.MIN_INTERNAL_LINKS:
            score -= 20
        
        return {
            'internal_count': internal_links,
            'external_count': external_links,
            'broken_count': broken_links,
            'score': score
        }
    
    def _analyze_url_structure(self, url: str) -> Dict:
        """Analyze URL structure optimization"""
        parsed_url = urlparse(url)
        path = parsed_url.path
        url_length = len(url)
        
        score = 100
        
        # URL length analysis
        if url_length > self.OPTIMAL_URL_LENGTH:
            self.issues.append(SEOIssue(
                type="Long URL",
                severity="low",
                description=f"URL is {url_length} characters (recommended: under {self.OPTIMAL_URL_LENGTH})",
                location="URL structure",
                recommendation="Use shorter, more descriptive URLs",
                impact="Long URLs are harder to share and remember"
            ))
            score -= 10
        
        # URL structure analysis
        if '_' in path:
            self.issues.append(SEOIssue(
                type="Underscores in URL",
                severity="low",
                description="URL contains underscores",
                location="URL structure",
                recommendation="Use hyphens (-) instead of underscores (_) in URLs",
                impact="Minor SEO impact - hyphens are preferred word separators"
            ))
            score -= 5
        
        return {'length': url_length, 'score': score}
    
    def _analyze_content_quality(self, soup: BeautifulSoup) -> Dict:
        """Analyze content quality and length"""
        # Extract text content
        text_content = soup.get_text()
        words = text_content.split()
        word_count = len(words)
        
        score = 100
        
        # Content length analysis
        if word_count < 300:
            self.issues.append(SEOIssue(
                type="Thin Content",
                severity="medium",
                description=f"Page has only {word_count} words",
                location="Page content",
                recommendation="Add more comprehensive content (recommended: 300+ words)",
                impact="Thin content may rank poorly in search results"
            ))
            score -= 25
        
        return {'word_count': word_count, 'score': score}
    
    def _analyze_technical_seo(self, soup: BeautifulSoup, response) -> Dict:
        """Analyze technical SEO factors"""
        score = 100
        
        # Meta viewport analysis
        viewport = soup.find('meta', attrs={'name': 'viewport'})
        if not viewport:
            self.issues.append(SEOIssue(
                type="Missing Viewport Meta Tag",
                severity="medium",
                description="Page is missing viewport meta tag",
                location="<head>",
                recommendation="Add <meta name='viewport' content='width=device-width, initial-scale=1'>",
                impact="Poor mobile experience affects mobile search rankings"
            ))
            score -= 15
        
        # Charset analysis
        charset = soup.find('meta', attrs={'charset': True})
        if not charset:
            self.issues.append(SEOIssue(
                type="Missing Charset Declaration",
                severity="low",
                description="Page is missing charset declaration",
                location="<head>",
                recommendation="Add <meta charset='UTF-8'> in <head>",
                impact="May cause character encoding issues"
            ))
            score -= 5
        
        return {'score': score}
    
    def _calculate_seo_score(self, *analyses) -> int:
        """
        Calculate weighted SEO score
        
        Senior Engineering: Transparent scoring algorithm
        """
        total_score = 0
        total_weight = 0
        
        weights = [
            self.SEO_WEIGHTS['title_tag'],
            self.SEO_WEIGHTS['meta_description'],
            self.SEO_WEIGHTS['h1_structure'],
            self.SEO_WEIGHTS['alt_text'],
            self.SEO_WEIGHTS['internal_linking'],
            self.SEO_WEIGHTS['url_structure'],
            self.SEO_WEIGHTS['content_quality'],
            self.SEO_WEIGHTS['technical_seo']
        ]
        
        for analysis, weight in zip(analyses, weights):
            if analysis and 'score' in analysis:
                total_score += analysis['score'] * weight
                total_weight += weight
        
        if total_weight == 0:
            return 0
        
        final_score = int(total_score / total_weight)
        return max(0, min(100, final_score))
    
    def get_seo_issues(self) -> List[SEOIssue]:
        """Get all identified SEO issues"""
        return self.issues
    
    def get_recommendations(self) -> List[str]:
        """Get prioritized SEO recommendations"""
        recommendations = []
        
        # Group by severity
        critical_issues = [issue for issue in self.issues if issue.severity == "critical"]
        high_issues = [issue for issue in self.issues if issue.severity == "high"]
        medium_issues = [issue for issue in self.issues if issue.severity == "medium"]
        
        # Prioritized recommendations
        for issue in critical_issues[:3]:  # Top 3 critical
            recommendations.append(f"🚨 CRITICAL: {issue.recommendation}")
        
        for issue in high_issues[:3]:  # Top 3 high
            recommendations.append(f"⚠️ HIGH: {issue.recommendation}")
        
        for issue in medium_issues[:2]:  # Top 2 medium
            recommendations.append(f"⚡ MEDIUM: {issue.recommendation}")
        
        return recommendations