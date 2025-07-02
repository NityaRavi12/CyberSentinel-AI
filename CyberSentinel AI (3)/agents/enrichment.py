"""
Enrichment Agent for CyberSentinel AI - ATITA
Gathers additional context and threat intelligence
"""

import asyncio
import aiohttp
import re
from typing import Dict, Any, List, Optional
from agents.base_agent import BaseAgent
from core.database import db_manager
from core.models import ThreatStatus, EnrichmentData
from core.config import settings
from core.logging import get_logger

logger = get_logger("enrichment_agent")


class EnrichmentAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="enrichment", timeout=45)
        self.virustotal_api_key = settings.virustotal_api_key
        self.alienvault_api_key = settings.alienvault_api_key
        self.threatfox_api_key = settings.threatfox_api_key

    async def _initialize(self):
        """Initialize HTTP session for API calls"""
        self.session = aiohttp.ClientSession()
        logger.info("Enrichment agent initialized with API session")

    async def _shutdown(self):
        """Close HTTP session"""
        if hasattr(self, 'session'):
            await self.session.close()

    async def _process_task(self, task_data):
        """Process threat enrichment with external intelligence sources"""
        self.logger.info("Enrichment agent processing task", task=task_data)
        
        threat_data = task_data.get("threat_data", {})
        threat_id = threat_data.get("id")
        
        if not threat_id:
            return {"status": "error", "message": "No threat ID provided"}

        try:
            # Extract IOCs from threat data
            iocs = self._extract_iocs(threat_data)
            
            # Enrich with external sources
            enrichment_results = await self._enrich_iocs(iocs)
            
            # Create enrichment data
            enrichment_data = EnrichmentData(
                threat_id=threat_id,
                ioc_data=enrichment_results.get("ioc_data", []),
                related_threats=enrichment_results.get("related_threats", [])
            )
            
            # Update threat in database
            await db_manager.update_threat(threat_id, {
                "status": ThreatStatus.ENRICHED.value,
                "threat_metadata": {
                    **threat_data.get("threat_metadata", {}),
                    "enrichment": enrichment_results
                }
            })
            
            return {
                "status": "enriched",
                "threat_id": threat_id,
                "enrichment_data": enrichment_results
            }
            
        except Exception as e:
            self.logger.error(f"Error enriching threat {threat_id}: {e}")
            return {"status": "error", "message": str(e)}

    def _extract_iocs(self, threat_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from threat data"""
        iocs = {
            "ips": [],
            "domains": [],
            "urls": [],
            "hashes": [],
            "emails": []
        }
        
        # Extract from title and description
        text = f"{threat_data.get('title', '')} {threat_data.get('description', '')}"
        
        # IP addresses
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs["ips"] = re.findall(ip_pattern, text)
        
        # Domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs["domains"] = re.findall(domain_pattern, text)
        
        # URLs
        url_pattern = r'https?://[^\s]+'
        iocs["urls"] = re.findall(url_pattern, text)
        
        # MD5/SHA hashes
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        iocs["hashes"] = re.findall(hash_pattern, text)
        
        # Email addresses
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["emails"] = re.findall(email_pattern, text)
        
        return iocs

    async def _enrich_iocs(self, iocs: Dict[str, List[str]]) -> Dict[str, Any]:
        """Enrich IOCs with external threat intelligence"""
        enrichment_results = {
            "ioc_data": [],
            "related_threats": [],
            "virustotal_data": {},
            "alienvault_data": {},
            "threatfox_data": {}
        }
        
        # Enrich IPs
        for ip in iocs["ips"][:5]:  # Limit to first 5 IPs
            ip_data = await self._enrich_ip(ip)
            if ip_data:
                enrichment_results["ioc_data"].append(ip_data)
        
        # Enrich domains
        for domain in iocs["domains"][:5]:  # Limit to first 5 domains
            domain_data = await self._enrich_domain(domain)
            if domain_data:
                enrichment_results["ioc_data"].append(domain_data)
        
        # Enrich hashes
        for hash_value in iocs["hashes"][:5]:  # Limit to first 5 hashes
            hash_data = await self._enrich_hash(hash_value)
            if hash_data:
                enrichment_results["ioc_data"].append(hash_data)
        
        return enrichment_results

    async def _enrich_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Enrich IP address with threat intelligence"""
        try:
            # VirusTotal IP reputation
            if self.virustotal_api_key:
                vt_data = await self._query_virustotal_ip(ip)
                if vt_data:
                    return {
                        "type": "ip",
                        "value": ip,
                        "virustotal": vt_data,
                        "malicious_score": vt_data.get("malicious_votes", 0) / max(vt_data.get("total_votes", 1), 1)
                    }
            
            # AlienVault OTX
            if self.alienvault_api_key:
                otx_data = await self._query_alienvault_ip(ip)
                if otx_data:
                    return {
                        "type": "ip",
                        "value": ip,
                        "alienvault": otx_data,
                        "malicious_score": len(otx_data.get("pulse_info", {}).get("pulses", []))
                    }
            
            return {
                "type": "ip",
                "value": ip,
                "status": "no_intel_available"
            }
            
        except Exception as e:
            logger.error(f"Error enriching IP {ip}: {e}")
            return None

    async def _enrich_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Enrich domain with threat intelligence"""
        try:
            # WHOIS lookup (simplified)
            whois_data = await self._query_whois(domain)
            
            # VirusTotal domain reputation
            vt_data = None
            if self.virustotal_api_key:
                vt_data = await self._query_virustotal_domain(domain)
            
            return {
                "type": "domain",
                "value": domain,
                "whois": whois_data,
                "virustotal": vt_data,
                "malicious_score": vt_data.get("malicious_votes", 0) / max(vt_data.get("total_votes", 1), 1) if vt_data else 0
            }
            
        except Exception as e:
            logger.error(f"Error enriching domain {domain}: {e}")
            return None

    async def _enrich_hash(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Enrich file hash with threat intelligence"""
        try:
            # VirusTotal file analysis
            if self.virustotal_api_key:
                vt_data = await self._query_virustotal_file(hash_value)
                if vt_data:
                    return {
                        "type": "hash",
                        "value": hash_value,
                        "virustotal": vt_data,
                        "malicious_score": vt_data.get("positives", 0) / max(vt_data.get("total", 1), 1)
                    }
            
            return {
                "type": "hash",
                "value": hash_value,
                "status": "no_intel_available"
            }
            
        except Exception as e:
            logger.error(f"Error enriching hash {hash_value}: {e}")
            return None

    async def _query_virustotal_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for IP reputation"""
        if not self.virustotal_api_key:
            return None
            
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {"apikey": self.virustotal_api_key, "ip": ip}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "malicious_votes": data.get("positives", 0),
                        "total_votes": data.get("total", 0),
                        "country": data.get("country", ""),
                        "as_owner": data.get("as_owner", "")
                    }
        except Exception as e:
            logger.error(f"VirusTotal IP query error: {e}")
        return None

    async def _query_virustotal_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for domain reputation"""
        if not self.virustotal_api_key:
            return None
            
        try:
            url = f"https://www.virustotal.com/vtapi/v2/domain/report"
            params = {"apikey": self.virustotal_api_key, "domain": domain}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "malicious_votes": data.get("positives", 0),
                        "total_votes": data.get("total", 0),
                        "categories": data.get("categories", {})
                    }
        except Exception as e:
            logger.error(f"VirusTotal domain query error: {e}")
        return None

    async def _query_virustotal_file(self, hash_value: str) -> Optional[Dict[str, Any]]:
        """Query VirusTotal for file analysis"""
        if not self.virustotal_api_key:
            return None
            
        try:
            url = f"https://www.virustotal.com/vtapi/v2/file/report"
            params = {"apikey": self.virustotal_api_key, "resource": hash_value}
            
            async with self.session.get(url, params=params) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "positives": data.get("positives", 0),
                        "total": data.get("total", 0),
                        "file_type": data.get("type", ""),
                        "file_size": data.get("size", 0)
                    }
        except Exception as e:
            logger.error(f"VirusTotal file query error: {e}")
        return None

    async def _query_alienvault_ip(self, ip: str) -> Optional[Dict[str, Any]]:
        """Query AlienVault OTX for IP intelligence"""
        if not self.alienvault_api_key:
            return None
            
        try:
            url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
            headers = {"X-OTX-API-KEY": self.alienvault_api_key}
            
            async with self.session.get(url, headers=headers) as response:
                if response.status == 200:
                    data = await response.json()
                    return {
                        "pulse_info": data.get("pulse_info", {}),
                        "country_name": data.get("country_name", ""),
                        "city": data.get("city", "")
                    }
        except Exception as e:
            logger.error(f"AlienVault IP query error: {e}")
        return None

    async def _query_whois(self, domain: str) -> Optional[Dict[str, Any]]:
        """Query WHOIS information for domain"""
        try:
            # Simplified WHOIS lookup (in production, use a proper WHOIS library)
            return {
                "domain": domain,
                "status": "lookup_not_implemented",
                "note": "WHOIS lookup requires additional library (python-whois)"
            }
        except Exception as e:
            logger.error(f"WHOIS query error: {e}")
        return None 