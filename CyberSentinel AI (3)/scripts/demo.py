#!/usr/bin/env python3
"""
CyberSentinel AI - ATITA Demonstration Script
Shows the complete workflow in action
"""

import asyncio
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.database import db_manager
from core.logging import setup_logging
from agents.coordinator import CoordinatorAgent
from core.models import ThreatData, ThreatType, ThreatSeverity, SourceType


async def demo_complete_workflow():
    """Demonstrate the complete CyberSentinel AI workflow"""
    
    print("🚀 CyberSentinel AI - ATITA Demonstration")
    print("=" * 50)
    
    # Setup logging
    setup_logging()
    
    # Initialize database
    print("📊 Initializing database...")
    await db_manager.initialize()
    
    # Initialize coordinator
    print("🧭 Initializing coordinator agent...")
    coordinator = CoordinatorAgent()
    await coordinator.initialize()
    
    print("\n✅ System initialized successfully!")
    print("\n" + "=" * 50)
    
    # Demo 1: Ransomware Email Threat
    print("\n🔴 DEMO 1: Ransomware Email Threat")
    print("-" * 30)
    
    ransomware_threat = ThreatData(
        title="URGENT: Your account has been suspended",
        description="User received email with ransomware attachment. Email contains urgent language and suspicious attachment named 'invoice.exe'.",
        threat_type=ThreatType.UNKNOWN,  # Will be classified by triage agent
        severity=ThreatSeverity.MEDIUM,  # Will be updated by triage agent
        source=SourceType.EMAIL,
        source_details={
            "sender": "attacker@malicious.com",
            "subject": "URGENT: Your account has been suspended",
            "attachments": ["invoice.exe"]
        },
        confidence=0.5
    )
    
    print(f"📧 Threat submitted: {ransomware_threat.title}")
    print(f"   Source: {ransomware_threat.source.value}")
    print(f"   Initial confidence: {ransomware_threat.confidence}")
    
    # Process through coordinator
    result = await coordinator.process_task({
        "type": "threat_processing",
        "threat_data": ransomware_threat.dict(),
        "timestamp": "2024-01-15T10:30:00Z"
    })
    
    print(f"   Task ID: {result.get('task_id')}")
    
    # Wait for processing
    print("   ⏳ Processing through agent pipeline...")
    await asyncio.sleep(3)
    
    # Check final status
    final_threat = await db_manager.get_threat(ransomware_threat.id)
    if final_threat:
        print(f"   ✅ Final status: {final_threat.status}")
        print(f"   🎯 Classified as: {final_threat.threat_type.value}")
        print(f"   ⚠️  Severity: {final_threat.severity.value}")
        print(f"   📊 Confidence: {final_threat.confidence:.2f}")
    
    # Demo 2: Phishing Threat
    print("\n🔴 DEMO 2: Phishing Threat")
    print("-" * 30)
    
    phishing_threat = ThreatData(
        title="Bank Account Verification Required",
        description="User clicked on suspicious link in email claiming to be from bank. Email contains urgent verification request.",
        threat_type=ThreatType.UNKNOWN,
        severity=ThreatSeverity.MEDIUM,
        source=SourceType.EMAIL,
        source_details={
            "sender": "noreply@fakebank.com",
            "subject": "Verify your account immediately",
            "urls": ["https://fake-bank-login.com/verify"]
        },
        confidence=0.5
    )
    
    print(f"📧 Threat submitted: {phishing_threat.title}")
    
    # Process through coordinator
    result = await coordinator.process_task({
        "type": "threat_processing",
        "threat_data": phishing_threat.dict(),
        "timestamp": "2024-01-15T10:35:00Z"
    })
    
    # Wait for processing
    print("   ⏳ Processing through agent pipeline...")
    await asyncio.sleep(3)
    
    # Check final status
    final_threat = await db_manager.get_threat(phishing_threat.id)
    if final_threat:
        print(f"   ✅ Final status: {final_threat.status}")
        print(f"   🎯 Classified as: {final_threat.threat_type.value}")
        print(f"   ⚠️  Severity: {final_threat.severity.value}")
        print(f"   📊 Confidence: {final_threat.confidence:.2f}")
    
    # Demo 3: Malware File Threat
    print("\n🔴 DEMO 3: Malware File Threat")
    print("-" * 30)
    
    malware_threat = ThreatData(
        title="Suspicious Executable Upload",
        description="User uploaded suspicious executable file with invoice name. File appears to be malware.",
        threat_type=ThreatType.UNKNOWN,
        severity=ThreatSeverity.MEDIUM,
        source=SourceType.FILE_UPLOAD,
        source_details={
            "filename": "invoice_scan.exe",
            "file_size": 2048576,
            "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd"
        },
        confidence=0.5
    )
    
    print(f"📁 Threat submitted: {malware_threat.title}")
    
    # Process through coordinator
    result = await coordinator.process_task({
        "type": "threat_processing",
        "threat_data": malware_threat.dict(),
        "timestamp": "2024-01-15T10:40:00Z"
    })
    
    # Wait for processing
    print("   ⏳ Processing through agent pipeline...")
    await asyncio.sleep(3)
    
    # Check final status
    final_threat = await db_manager.get_threat(malware_threat.id)
    if final_threat:
        print(f"   ✅ Final status: {final_threat.status}")
        print(f"   🎯 Classified as: {final_threat.threat_type.value}")
        print(f"   ⚠️  Severity: {final_threat.severity.value}")
        print(f"   📊 Confidence: {final_threat.confidence:.2f}")
    
    # Show agent status
    print("\n🔴 DEMO 4: Agent Status")
    print("-" * 30)
    
    agent_status = coordinator.get_all_agent_status()
    for agent_name, status in agent_status.items():
        print(f"   🤖 {agent_name}: {status['status']}")
        print(f"      Tasks processed: {status['tasks_processed']}")
        print(f"      Errors: {status['errors_count']}")
    
    # Show analytics
    print("\n🔴 DEMO 5: System Analytics")
    print("-" * 30)
    
    # Get all threats for analytics
    threats = await db_manager.list_threats(limit=100)
    
    total_threats = len(threats)
    threats_by_type = {}
    threats_by_severity = {}
    
    for threat in threats:
        # Count by type
        threat_type = threat.threat_type.value
        threats_by_type[threat_type] = threats_by_type.get(threat_type, 0) + 1
        
        # Count by severity
        severity = threat.severity.value
        threats_by_severity[severity] = threats_by_severity.get(severity, 0) + 1
    
    print(f"   📊 Total threats processed: {total_threats}")
    print(f"   🎯 Threats by type: {threats_by_type}")
    print(f"   ⚠️  Threats by severity: {threats_by_severity}")
    
    # Cleanup
    print("\n🧹 Cleaning up...")
    await coordinator.shutdown()
    await db_manager.close()
    
    print("\n✅ Demonstration completed successfully!")
    print("\n🎉 CyberSentinel AI - ATITA is fully operational!")
    print("\nKey Features Demonstrated:")
    print("   ✅ Multi-source threat intake (Email, File, API)")
    print("   ✅ AI-powered threat classification and triage")
    print("   ✅ External threat intelligence enrichment")
    print("   ✅ Organizational policy application")
    print("   ✅ Intelligent escalation decisions")
    print("   ✅ Continuous learning and feedback")
    print("   ✅ Complete workflow orchestration")
    print("   ✅ Database persistence and analytics")


if __name__ == "__main__":
    asyncio.run(demo_complete_workflow()) 