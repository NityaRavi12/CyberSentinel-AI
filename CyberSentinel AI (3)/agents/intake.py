"""
Intake Agent for CyberSentinel AI - ATITA
Collects incoming threat data from multiple sources
"""

import asyncio
import re
import hashlib
from typing import Dict, Any, List, Optional
from datetime import datetime
from agents.base_agent import BaseAgent
from core.database import db_manager
from core.models import ThreatStatus, ThreatType, ThreatSeverity, SourceType
from core.config import settings
from core.logging import get_logger

logger = get_logger("intake_agent")


class IntakeAgent(BaseAgent):
    def __init__(self):
        super().__init__(name="intake", timeout=30)
        self.email_patterns = self._load_email_patterns()
        self.file_extensions = settings.allowed_file_types

    async def _initialize(self):
        """Initialize intake agent"""
        logger.info("Intake agent initialized with email and file processing capabilities")

    async def _shutdown(self):
        """Cleanup resources"""
        pass

    def _load_email_patterns(self) -> Dict[str, List[str]]:
        """Load patterns for email threat detection"""
        return {
            "phishing_indicators": [
                r"urgent.*action.*required",
                r"account.*suspended",
                r"verify.*account",
                r"click.*here.*login",
                r"password.*expired",
                r"security.*alert",
                r"unusual.*activity",
                r"confirm.*identity"
            ],
            "malware_indicators": [
                r"invoice.*attachment",
                r"document.*scan",
                r"payment.*receipt",
                r"important.*file",
                r"scan.*results",
                r"security.*update"
            ],
            "suspicious_senders": [
                r"noreply@.*",
                r"security@.*",
                r"admin@.*",
                r"support@.*",
                r"service@.*"
            ]
        }

    async def _process_task(self, task_data):
        """Process threat intake from various sources"""
        self.logger.info("Intake agent processing task", task=task_data)
        
        source_type = task_data.get("source_type", "api")
        threat_data = task_data.get("threat_data", {})
        threat_id = threat_data.get("id")
        
        if not threat_id:
            return {"status": "error", "message": "No threat ID provided"}

        try:
            # Process based on source type
            if source_type == "email":
                processed_data = await self._process_email_intake(threat_data)
            elif source_type == "file_upload":
                processed_data = await self._process_file_intake(threat_data)
            elif source_type == "siem":
                processed_data = await self._process_siem_intake(threat_data)
            elif source_type == "api":
                processed_data = await self._process_api_intake(threat_data)
            else:
                processed_data = await self._process_generic_intake(threat_data)
            
            # Update threat in database
            await db_manager.update_threat(threat_id, {
                "status": ThreatStatus.RECEIVED.value,
                "threat_metadata": {
                    **threat_data.get("threat_metadata", {}),
                    "intake_processing": processed_data
                }
            })
            
            return {
                "status": "intake_received",
                "threat_id": threat_id,
                "source_type": source_type,
                "processed_data": processed_data
            }
            
        except Exception as e:
            self.logger.error(f"Error processing intake for threat {threat_id}: {e}")
            return {"status": "error", "message": str(e)}

    async def _process_email_intake(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process email-based threat intake"""
        email_content = threat_data.get("email_content", "")
        email_metadata = threat_data.get("email_metadata", {})
        
        # Extract email components
        subject = email_metadata.get("subject", "")
        sender = email_metadata.get("from", "")
        recipients = email_metadata.get("to", [])
        attachments = email_metadata.get("attachments", [])
        
        # Analyze email for threats
        threat_indicators = self._analyze_email_threats(subject, email_content, sender, attachments)
        
        # Extract IOCs from email
        iocs = self._extract_iocs_from_email(email_content, subject)
        
        # Determine threat type and severity
        threat_type, severity, confidence = self._classify_email_threat(threat_indicators, iocs)
        
        # Update threat data
        threat_data.update({
            "threat_type": threat_type,
            "severity": severity,
            "confidence": confidence,
            "source": SourceType.EMAIL,
            "source_details": {
                "sender": sender,
                "recipients": recipients,
                "subject": subject,
                "attachments": attachments,
                "iocs": iocs
            }
        })
        
        return {
            "processing_type": "email",
            "threat_indicators": threat_indicators,
            "iocs_extracted": iocs,
            "classification": {
                "threat_type": threat_type,
                "severity": severity,
                "confidence": confidence
            }
        }

    async def _process_file_intake(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process file upload threat intake"""
        file_data = threat_data.get("file_data", {})
        file_content = file_data.get("content", "")
        file_metadata = file_data.get("metadata", {})
        
        filename = file_metadata.get("filename", "")
        file_size = file_metadata.get("size", 0)
        file_type = file_metadata.get("type", "")
        
        # Analyze file for threats
        threat_indicators = self._analyze_file_threats(filename, file_content, file_metadata)
        
        # Extract IOCs from file
        iocs = self._extract_iocs_from_file(file_content, filename)
        
        # Calculate file hash
        file_hash = self._calculate_file_hash(file_content)
        
        # Determine threat type and severity
        threat_type, severity, confidence = self._classify_file_threat(threat_indicators, iocs, file_metadata)
        
        # Update threat data
        threat_data.update({
            "threat_type": threat_type,
            "severity": severity,
            "confidence": confidence,
            "source": SourceType.FILE_UPLOAD,
            "source_details": {
                "filename": filename,
                "file_size": file_size,
                "file_type": file_type,
                "file_hash": file_hash,
                "iocs": iocs
            }
        })
        
        return {
            "processing_type": "file_upload",
            "threat_indicators": threat_indicators,
            "iocs_extracted": iocs,
            "file_analysis": {
                "hash": file_hash,
                "size": file_size,
                "type": file_type
            },
            "classification": {
                "threat_type": threat_type,
                "severity": severity,
                "confidence": confidence
            }
        }

    async def _process_siem_intake(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process SIEM-based threat intake"""
        siem_data = threat_data.get("siem_data", {})
        
        # Extract SIEM event details
        event_type = siem_data.get("event_type", "")
        event_source = siem_data.get("source", "")
        event_severity = siem_data.get("severity", "medium")
        event_description = siem_data.get("description", "")
        
        # Analyze SIEM event for threats
        threat_indicators = self._analyze_siem_threats(siem_data)
        
        # Extract IOCs from SIEM data
        iocs = self._extract_iocs_from_siem(siem_data)
        
        # Determine threat type and severity
        threat_type, severity, confidence = self._classify_siem_threat(threat_indicators, siem_data)
        
        # Update threat data
        threat_data.update({
            "threat_type": threat_type,
            "severity": severity,
            "confidence": confidence,
            "source": SourceType.SIEM,
            "source_details": {
                "event_type": event_type,
                "event_source": event_source,
                "event_severity": event_severity,
                "iocs": iocs
            }
        })
        
        return {
            "processing_type": "siem",
            "threat_indicators": threat_indicators,
            "iocs_extracted": iocs,
            "classification": {
                "threat_type": threat_type,
                "severity": severity,
                "confidence": confidence
            }
        }

    async def _process_api_intake(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process API-based threat intake"""
        # API intake is already structured, just validate and enhance
        threat_type = threat_data.get("threat_type", ThreatType.UNKNOWN)
        severity = threat_data.get("severity", ThreatSeverity.MEDIUM)
        confidence = threat_data.get("confidence", 0.5)
        
        # Extract IOCs from API data
        iocs = self._extract_iocs_from_api(threat_data)
        
        return {
            "processing_type": "api",
            "iocs_extracted": iocs,
            "classification": {
                "threat_type": threat_type,
                "severity": severity,
                "confidence": confidence
            }
        }

    async def _process_generic_intake(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process generic threat intake"""
        # Generic processing for unknown sources
        return {
            "processing_type": "generic",
            "classification": {
                "threat_type": ThreatType.UNKNOWN,
                "severity": ThreatSeverity.MEDIUM,
                "confidence": 0.3
            }
        }

    def _analyze_email_threats(self, subject: str, content: str, sender: str, attachments: List[str]) -> Dict[str, Any]:
        """Analyze email for threat indicators"""
        indicators = {
            "phishing_score": 0.0,
            "malware_score": 0.0,
            "suspicious_sender": False,
            "suspicious_attachments": False,
            "urgency_indicators": 0,
            "suspicious_links": 0
        }
        
        # Check for phishing indicators
        text = f"{subject} {content}".lower()
        for pattern in self.email_patterns["phishing_indicators"]:
            if re.search(pattern, text):
                indicators["phishing_score"] += 0.2
        
        # Check for malware indicators
        for pattern in self.email_patterns["malware_indicators"]:
            if re.search(pattern, text):
                indicators["malware_score"] += 0.15
        
        # Check for suspicious sender
        for pattern in self.email_patterns["suspicious_senders"]:
            if re.search(pattern, sender.lower()):
                indicators["suspicious_sender"] = True
                indicators["phishing_score"] += 0.3
        
        # Check for suspicious attachments
        suspicious_extensions = [".exe", ".bat", ".cmd", ".scr", ".pif"]
        for attachment in attachments:
            if any(ext in attachment.lower() for ext in suspicious_extensions):
                indicators["suspicious_attachments"] = True
                indicators["malware_score"] += 0.4
        
        # Check for urgency indicators
        urgency_words = ["urgent", "immediate", "critical", "emergency", "asap"]
        indicators["urgency_indicators"] = sum(1 for word in urgency_words if word in text)
        
        # Check for suspicious links
        url_pattern = r'https?://[^\s]+'
        urls = re.findall(url_pattern, content)
        indicators["suspicious_links"] = len(urls)
        
        return indicators

    def _analyze_file_threats(self, filename: str, content: str, metadata: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze file for threat indicators"""
        indicators = {
            "malware_score": 0.0,
            "suspicious_filename": False,
            "suspicious_content": False,
            "file_size_suspicious": False
        }
        
        # Check for suspicious filename
        suspicious_patterns = ["invoice", "receipt", "document", "scan", "payment"]
        if any(pattern in filename.lower() for pattern in suspicious_patterns):
            indicators["suspicious_filename"] = True
            indicators["malware_score"] += 0.2
        
        # Check for suspicious content
        if "powershell" in content.lower() or "cmd" in content.lower():
            indicators["suspicious_content"] = True
            indicators["malware_score"] += 0.4
        
        # Check file size
        file_size = metadata.get("size", 0)
        if file_size > 10 * 1024 * 1024:  # 10MB
            indicators["file_size_suspicious"] = True
            indicators["malware_score"] += 0.1
        
        return indicators

    def _analyze_siem_threats(self, siem_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze SIEM data for threat indicators"""
        indicators = {
            "threat_score": 0.0,
            "anomaly_detected": False,
            "multiple_events": False
        }
        
        event_type = siem_data.get("event_type", "").lower()
        event_severity = siem_data.get("severity", "medium")
        
        # Check for known threat patterns
        threat_patterns = ["malware", "intrusion", "breach", "attack", "exploit"]
        if any(pattern in event_type for pattern in threat_patterns):
            indicators["threat_score"] += 0.6
        
        # Check severity
        if event_severity in ["high", "critical"]:
            indicators["threat_score"] += 0.3
        
        # Check for anomalies
        if siem_data.get("anomaly_score", 0) > 0.7:
            indicators["anomaly_detected"] = True
            indicators["threat_score"] += 0.2
        
        return indicators

    def _extract_iocs_from_email(self, content: str, subject: str) -> Dict[str, List[str]]:
        """Extract IOCs from email content"""
        iocs = {"ips": [], "domains": [], "urls": [], "emails": []}
        
        text = f"{subject} {content}"
        
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs["ips"] = re.findall(ip_pattern, text)
        
        # Extract domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs["domains"] = re.findall(domain_pattern, text)
        
        # Extract URLs
        url_pattern = r'https?://[^\s]+'
        iocs["urls"] = re.findall(url_pattern, text)
        
        # Extract emails
        email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
        iocs["emails"] = re.findall(email_pattern, text)
        
        return iocs

    def _extract_iocs_from_file(self, content: str, filename: str) -> Dict[str, List[str]]:
        """Extract IOCs from file content"""
        iocs = {"ips": [], "domains": [], "urls": [], "hashes": []}
        
        # Extract IPs
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        iocs["ips"] = re.findall(ip_pattern, content)
        
        # Extract domains
        domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
        iocs["domains"] = re.findall(domain_pattern, content)
        
        # Extract URLs
        url_pattern = r'https?://[^\s]+'
        iocs["urls"] = re.findall(url_pattern, content)
        
        # Extract hashes
        hash_pattern = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
        iocs["hashes"] = re.findall(hash_pattern, content)
        
        return iocs

    def _extract_iocs_from_siem(self, siem_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from SIEM data"""
        iocs = {"ips": [], "domains": [], "urls": [], "hashes": []}
        
        # Extract from SIEM event data
        event_data = siem_data.get("event_data", {})
        
        # Extract IPs
        for field in ["source_ip", "destination_ip", "src_ip", "dst_ip"]:
            if field in event_data:
                ip = event_data[field]
                if re.match(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', ip):
                    iocs["ips"].append(ip)
        
        # Extract domains
        for field in ["domain", "hostname", "url"]:
            if field in event_data:
                domain = event_data[field]
                if re.match(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b', domain):
                    iocs["domains"].append(domain)
        
        return iocs

    def _extract_iocs_from_api(self, threat_data: Dict[str, Any]) -> Dict[str, List[str]]:
        """Extract IOCs from API threat data"""
        iocs = {"ips": [], "domains": [], "urls": [], "hashes": []}
        
        # Extract from source details
        source_details = threat_data.get("source_details", {})
        
        # Extract IPs
        if "ip" in source_details:
            iocs["ips"].append(source_details["ip"])
        
        # Extract domains
        if "domain" in source_details:
            iocs["domains"].append(source_details["domain"])
        
        # Extract URLs
        if "url" in source_details:
            iocs["urls"].append(source_details["url"])
        
        return iocs

    def _classify_email_threat(self, indicators: Dict[str, Any], iocs: Dict[str, List[str]]) -> tuple:
        """Classify email threat type and severity"""
        phishing_score = indicators["phishing_score"]
        malware_score = indicators["malware_score"]
        
        if malware_score > 0.5:
            return ThreatType.MALWARE, ThreatSeverity.HIGH, min(malware_score, 0.9)
        elif phishing_score > 0.5:
            return ThreatType.PHISHING, ThreatSeverity.MEDIUM, min(phishing_score, 0.8)
        else:
            return ThreatType.UNKNOWN, ThreatSeverity.LOW, 0.3

    def _classify_file_threat(self, indicators: Dict[str, Any], iocs: Dict[str, List[str]], metadata: Dict[str, Any]) -> tuple:
        """Classify file threat type and severity"""
        malware_score = indicators["malware_score"]
        
        if malware_score > 0.6:
            return ThreatType.MALWARE, ThreatSeverity.HIGH, min(malware_score, 0.9)
        elif malware_score > 0.3:
            return ThreatType.MALWARE, ThreatSeverity.MEDIUM, malware_score
        else:
            return ThreatType.UNKNOWN, ThreatSeverity.LOW, 0.2

    def _classify_siem_threat(self, indicators: Dict[str, Any], siem_data: Dict[str, Any]) -> tuple:
        """Classify SIEM threat type and severity"""
        threat_score = indicators["threat_score"]
        event_type = siem_data.get("event_type", "").lower()
        
        if "malware" in event_type:
            return ThreatType.MALWARE, ThreatSeverity.HIGH, min(threat_score, 0.9)
        elif "ddos" in event_type:
            return ThreatType.DDoS, ThreatSeverity.HIGH, min(threat_score, 0.8)
        elif "breach" in event_type:
            return ThreatType.DATA_BREACH, ThreatSeverity.CRITICAL, min(threat_score, 0.95)
        else:
            return ThreatType.UNKNOWN, ThreatSeverity.MEDIUM, threat_score

    def _calculate_file_hash(self, content: str) -> str:
        """Calculate SHA256 hash of file content"""
        return hashlib.sha256(content.encode()).hexdigest() 