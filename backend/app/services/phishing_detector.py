"""
Phishing Detection Service
Orchestrates email analysis, IOC extraction, and threat creation
"""

import time
from typing import Dict, Any
from datetime import datetime
import logging

from app.ai.factory import get_ai_provider
from app.services.ioc_extractor import IOCExtractor
from app.core.config import settings

logger = logging.getLogger(__name__)


class PhishingDetector:
    """Main phishing detection orchestrator"""
    
    def __init__(self):
        self.ai_provider = get_ai_provider()
        self.ioc_extractor = IOCExtractor()
        self.logger = logging.getLogger(__name__)
    
    async def analyze_email(self, email_content: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive email analysis
        
        Args:
            email_content: Parsed email data
        
        Returns:
            Complete analysis results including AI analysis and IOCs
        """
        start_time = time.time()
        
        try:
            # Step 1: Extract IOCs
            self.logger.info(f"Analyzing email: {email_content.get('subject', 'No Subject')}")
            iocs = self.ioc_extractor.extract_all(email_content)
            
            # Step 2: AI Analysis
            ai_analysis = await self.ai_provider.analyze_email(email_content)
            
            # Step 3: AI IOC Extraction (to supplement regex extraction)
            ai_iocs = await self.ai_provider.extract_iocs(email_content)
            
            # Merge IOCs
            merged_iocs = self._merge_iocs(iocs, ai_iocs)
            
            # Step 4: URL Analysis
            url_analysis = self._analyze_urls(merged_iocs.get('urls', []))
            
            # Step 5: Calculate final risk score
            final_analysis = self._calculate_final_risk(
                ai_analysis,
                merged_iocs,
                url_analysis
            )
            
            # Add metadata
            duration = time.time() - start_time
            final_analysis.update({
                'iocs': merged_iocs,
                'url_analysis': url_analysis,
                'analysis_duration': duration,
                'analyzed_at': datetime.utcnow().isoformat(),
                'ai_provider': settings.AI_PROVIDER
            })
            
            self.logger.info(
                f"Analysis complete: {final_analysis['risk_level']} "
                f"(confidence: {final_analysis['confidence']:.2f}) "
                f"in {duration:.2f}s"
            )
            
            return final_analysis
            
        except Exception as e:
            self.logger.error(f"Analysis failed: {e}", exc_info=True)
            return self._error_response(str(e))
    
    def _merge_iocs(
        self,
        regex_iocs: Dict[str, list],
        ai_iocs: Dict[str, list]
    ) -> Dict[str, list]:
        """Merge IOCs from regex and AI extraction"""
        merged = {}
        
        for key in ['domains', 'urls', 'ip_addresses', 'email_addresses', 'file_hashes']:
            regex_items = set(regex_iocs.get(key, []))
            ai_items = set(ai_iocs.get(key, []))
            merged[key] = list(regex_items.union(ai_items))
        
        return merged
    
    def _analyze_urls(self, urls: list) -> list:
        """Analyze all URLs for suspiciousness"""
        analyses = []
        
        for url in urls[:20]:  # Limit to first 20 URLs
            analysis = self.ioc_extractor.analyze_url_suspiciousness(url)
            analyses.append(analysis)
        
        return analyses
    
    def _calculate_final_risk(
        self,
        ai_analysis: Dict[str, Any],
        iocs: Dict[str, list],
        url_analysis: list
    ) -> Dict[str, Any]:
        """Calculate final risk assessment"""
        
        # Start with AI confidence
        base_confidence = ai_analysis.get('confidence', 0.0)
        
        # Adjust based on IOC count
        ioc_count = sum(len(v) for v in iocs.values())
        if ioc_count > 10:
            base_confidence = min(base_confidence + 0.1, 1.0)
        
        # Adjust based on suspicious URLs
        suspicious_url_count = sum(
            1 for ua in url_analysis if ua.get('is_suspicious', False)
        )
        if suspicious_url_count > 0:
            base_confidence = min(base_confidence + (suspicious_url_count * 0.05), 1.0)
        
        # Determine final risk level
        if base_confidence >= settings.HIGH_RISK_THRESHOLD:
            risk_level = "critical"
        elif base_confidence >= settings.PHISHING_CONFIDENCE_THRESHOLD:
            risk_level = "high"
        elif base_confidence >= 0.5:
            risk_level = "medium"
        else:
            risk_level = "low"
        
        # Override AI decision if confidence is high enough
        is_phishing = (
            ai_analysis.get('is_phishing', False) or
            base_confidence >= settings.PHISHING_CONFIDENCE_THRESHOLD
        )
        
        return {
            'is_phishing': is_phishing,
            'confidence': base_confidence,
            'risk_level': risk_level,
            'indicators': ai_analysis.get('indicators', []),
            'explanation': ai_analysis.get('explanation', ''),
            'ioc_count': ioc_count,
            'suspicious_url_count': suspicious_url_count
        }
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Return error response"""
        return {
            'is_phishing': False,
            'confidence': 0.0,
            'risk_level': 'unknown',
            'indicators': ['Analysis failed'],
            'explanation': f'Error during analysis: {error_message}',
            'iocs': {
                'domains': [],
                'urls': [],
                'ip_addresses': [],
                'email_addresses': [],
                'file_hashes': []
            },
            'url_analysis': [],
            'error': True
        }


# Convenience function
async def analyze_email_for_phishing(email_content: Dict[str, Any]) -> Dict[str, Any]:
    """Analyze email for phishing"""
    detector = PhishingDetector()
    return await detector.analyze_email(email_content)
