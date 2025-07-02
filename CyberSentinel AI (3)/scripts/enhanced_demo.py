#!/usr/bin/env python3
"""
Enhanced CyberSentinel AI - ATITA Demonstration Script
Demonstrates the enhanced architecture with TinyLlama, RAG, and atomic agents
"""

import asyncio
import sys
from pathlib import Path
from datetime import datetime

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from core.enhanced_llm import enhanced_llm_client
from core.rag_pipeline import rag_pipeline
from agents.enhanced_agents import enhanced_coordinator
from core.config import settings
from core.logging import setup_logging


async def check_ollama_setup():
    """Check if Ollama and TinyLlama are properly set up"""
    print("🔍 Checking Ollama and TinyLlama setup...")
    
    try:
        # Check if LLM is available
        is_available = enhanced_llm_client.is_available()
        print(f"   Ollama availability: {is_available}")
        
        if is_available:
            # Test health check
            health = await enhanced_llm_client.health_check()
            print(f"   LLM Health: {health}")
            
            # Test basic generation
            response = await enhanced_llm_client.generate_response(
                "What is cybersecurity?", temperature=0.3
            )
            print(f"   Test response: {response[:100]}...")
            
        return is_available
        
    except Exception as e:
        print(f"   ❌ Ollama setup check failed: {e}")
        return False


async def setup_rag_pipeline():
    """Set up RAG pipeline with sample threat intelligence data"""
    print("📚 Setting up RAG pipeline...")
    
    try:
        # Check RAG health
        health = await rag_pipeline.health_check()
        print(f"   RAG Health: {health}")
        
        # Add sample threat intelligence data
        sample_threats = [
            {
                "id": "threat_001",
                "title": "Ransomware Attack Pattern",
                "description": "WannaCry ransomware variant targeting Windows systems with EternalBlue exploit",
                "threat_type": "ransomware",
                "severity": "critical",
                "created_at": "2024-01-15T10:00:00Z"
            },
            {
                "id": "threat_002",
                "title": "Phishing Campaign",
                "description": "Sophisticated phishing campaign targeting financial institutions with credential harvesting",
                "threat_type": "phishing",
                "severity": "high",
                "created_at": "2024-01-15T11:00:00Z"
            },
            {
                "id": "threat_003",
                "title": "DDoS Attack",
                "description": "Large-scale DDoS attack using botnet infrastructure targeting e-commerce platforms",
                "threat_type": "ddos",
                "severity": "medium",
                "created_at": "2024-01-15T12:00:00Z"
            }
        ]
        
        # Add to knowledge base
        for threat in sample_threats:
            await rag_pipeline.add_threat_intelligence(threat)
        
        print(f"   Added {len(sample_threats)} sample threats to knowledge base")
        
        # Test search functionality
        search_results = await rag_pipeline.search("ransomware attack", top_k=3)
        print(f"   Search test returned {len(search_results)} results")
        
        return True
        
    except Exception as e:
        print(f"   ❌ RAG pipeline setup failed: {e}")
        return False


async def test_enhanced_agents():
    """Test each enhanced agent individually"""
    print("🧪 Testing Enhanced Agents...")
    print("=" * 50)
    
    # Sample threat data
    test_threat = {
        "id": "test_threat_001",
        "title": "Suspicious Ransomware Email",
        "description": "User received email with ransomware attachment. Email contains urgent language and suspicious attachment named 'invoice.exe'.",
        "source": "email",
        "source_details": {
            "sender": "attacker@malicious.com",
            "subject": "URGENT: Your account has been suspended",
            "attachments": ["invoice.exe"]
        },
        "confidence": 0.5
    }
    
    # Test Router Agent
    print("\n1️⃣ Testing Router Agent")
    router_agent = enhanced_coordinator.agents["router"]
    router_result = await router_agent.process(test_threat)
    print(f"   Processing path: {router_result.get('processing_path')}")
    print(f"   Priority: {router_result.get('priority')}")
    
    # Test Retrieval Agent
    print("\n2️⃣ Testing Retrieval Agent")
    retrieval_agent = enhanced_coordinator.agents["retrieval"]
    retrieval_result = await retrieval_agent.process(test_threat, router_result)
    print(f"   Retrieved {len(retrieval_result)} context items")
    
    # Test Reasoning Agent
    print("\n3️⃣ Testing Reasoning Agent")
    reasoning_agent = enhanced_coordinator.agents["reasoning"]
    reasoning_result = await reasoning_agent.process(test_threat, retrieval_result)
    print(f"   Threat type: {reasoning_result.threat_type}")
    print(f"   Severity: {reasoning_result.severity}")
    print(f"   Confidence: {reasoning_result.confidence}")
    print(f"   Reasoning: {reasoning_result.reasoning[:100]}...")
    
    # Test Evaluator Agent
    print("\n4️⃣ Testing Evaluator Agent")
    evaluator_agent = enhanced_coordinator.agents["evaluator"]
    evaluator_result = await evaluator_agent.process(reasoning_result, retrieval_result)
    print(f"   Is safe: {evaluator_result.is_safe}")
    print(f"   Issues: {evaluator_result.issues}")
    print(f"   Recommendations: {evaluator_result.recommendations}")
    
    # Test Policy Agent
    print("\n5️⃣ Testing Policy Agent")
    policy_agent = enhanced_coordinator.agents["policy"]
    policy_result = await policy_agent.process(reasoning_result, evaluator_result)
    print(f"   Decision: {policy_result.decision}")
    print(f"   Timeline: {policy_result.timeline}")
    print(f"   Resources needed: {policy_result.resources_needed}")
    
    # Test Escalation Agent
    print("\n6️⃣ Testing Escalation Agent")
    escalation_agent = enhanced_coordinator.agents["escalation"]
    escalation_result = await escalation_agent.process(reasoning_result, policy_result)
    print(f"   Escalation required: {escalation_result.get('escalation_required')}")
    print(f"   Escalation level: {escalation_result.get('escalation_level')}")
    print(f"   Assigned to: {escalation_result.get('assigned_to')}")
    
    # Test Memory Agent
    print("\n7️⃣ Testing Memory Agent")
    memory_agent = enhanced_coordinator.agents["memory"]
    memory_result = await memory_agent.process(test_threat, reasoning_result, escalation_result)
    print(f"   Case stored: {memory_result.get('case_stored')}")
    print(f"   Similar cases: {memory_result.get('similar_cases')}")
    
    return {
        "router": router_result,
        "retrieval": retrieval_result,
        "reasoning": reasoning_result,
        "evaluator": evaluator_result,
        "policy": policy_result,
        "escalation": escalation_result,
        "memory": memory_result
    }


async def demo_complete_workflow():
    """Demonstrate the complete enhanced workflow"""
    print("🚀 Enhanced CyberSentinel AI - Complete Workflow Demo")
    print("=" * 60)
    
    # Test cases
    test_cases = [
        {
            "id": "case_001",
            "title": "Ransomware Email Threat",
            "description": "User received email with ransomware attachment. Email contains urgent language and suspicious attachment named 'invoice.exe'.",
            "source": "email",
            "source_details": {
                "sender": "attacker@malicious.com",
                "subject": "URGENT: Your account has been suspended",
                "attachments": ["invoice.exe"]
            },
            "confidence": 0.5
        },
        {
            "id": "case_002",
            "title": "Phishing Attempt",
            "description": "User clicked on suspicious link in email claiming to be from bank. Email contains urgent verification request.",
            "source": "email",
            "source_details": {
                "sender": "noreply@fakebank.com",
                "subject": "Verify your account immediately",
                "urls": ["https://fake-bank-login.com/verify"]
            },
            "confidence": 0.5
        },
        {
            "id": "case_003",
            "title": "Malware File Upload",
            "description": "User uploaded suspicious executable file with invoice name. File appears to be malware.",
            "source": "file_upload",
            "source_details": {
                "filename": "invoice_scan.exe",
                "file_size": 2048576,
                "file_hash": "a1b2c3d4e5f6789012345678901234567890abcd"
            },
            "confidence": 0.5
        }
    ]
    
    results = []
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n🔴 Processing Case {i}: {test_case['title']}")
        print("-" * 40)
        
        # Process through enhanced coordinator
        start_time = datetime.utcnow()
        result = await enhanced_coordinator.process_threat(test_case)
        end_time = datetime.utcnow()
        
        processing_time = (end_time - start_time).total_seconds()
        
        print(f"   ⏱️  Processing time: {processing_time:.2f} seconds")
        print(f"   📊 Status: {result.get('status')}")
        
        if result.get('status') == 'completed':
            threat_analysis = result.get('threat_analysis', {})
            decision = result.get('decision', {})
            escalation = result.get('escalation', {})
            
            print(f"   🎯 Threat Type: {threat_analysis.get('threat_type', 'unknown')}")
            print(f"   ⚠️  Severity: {threat_analysis.get('severity', 'unknown')}")
            print(f"   📈 Confidence: {threat_analysis.get('confidence', 0):.2f}")
            print(f"   🤖 Decision: {decision.get('decision', 'unknown')}")
            print(f"   📞 Escalation: {escalation.get('escalation_level', 'none')}")
            
            # Show reasoning
            reasoning = threat_analysis.get('reasoning', '')[:150]
            print(f"   💭 Reasoning: {reasoning}...")
        else:
            print(f"   ❌ Error: {result.get('error', 'Unknown error')}")
        
        results.append(result)
    
    # Summary
    print("\n📊 Workflow Summary")
    print("=" * 30)
    
    successful_cases = [r for r in results if r.get('status') == 'completed']
    failed_cases = [r for r in results if r.get('status') != 'completed']
    
    print(f"   ✅ Successful cases: {len(successful_cases)}/{len(results)}")
    print(f"   ❌ Failed cases: {len(failed_cases)}/{len(results)}")
    
    if successful_cases:
        avg_confidence = sum(
            case.get('threat_analysis', {}).get('confidence', 0) 
            for case in successful_cases
        ) / len(successful_cases)
        print(f"   📈 Average confidence: {avg_confidence:.2f}")
    
    return results


def show_configuration():
    """Display current enhanced architecture configuration"""
    print("⚙️ Enhanced Architecture Configuration")
    print("=" * 40)
    
    # LLM Configuration
    print("\n🤖 LLM Configuration:")
    llm_config = settings.get_enhanced_llm_config()
    for key, value in llm_config.items():
        print(f"   {key}: {value}")
    
    # RAG Configuration
    print("\n📚 RAG Configuration:")
    rag_config = settings.get_rag_config()
    for key, value in rag_config.items():
        print(f"   {key}: {value}")
    
    # Agent Configuration
    print("\n🤖 Agent Configuration:")
    agent_config = settings.get_agent_config()
    for key, value in agent_config.items():
        print(f"   {key}: {value}")
    
    # Guardrails Configuration
    print("\n🛡️ Guardrails Configuration:")
    guardrails_config = settings.get_guardrails_config()
    for key, value in guardrails_config.items():
        print(f"   {key}: {value}")


def get_recommendations():
    """Get recommendations for production deployment"""
    print("🚀 Production Deployment Recommendations")
    print("=" * 45)
    
    recommendations = [
        {
            "category": "Infrastructure",
            "items": [
                "Deploy Ollama on dedicated server with GPU support",
                "Use Redis for caching and session management",
                "Implement proper logging and monitoring",
                "Set up automated backups for knowledge base"
            ]
        },
        {
            "category": "Security",
            "items": [
                "Implement proper authentication and authorization",
                "Use HTTPS for all communications",
                "Regular security audits and penetration testing",
                "Monitor for prompt injection attacks"
            ]
        },
        {
            "category": "Performance",
            "items": [
                "Fine-tune TinyLlama on domain-specific data",
                "Optimize RAG pipeline for faster retrieval",
                "Implement request queuing and load balancing",
                "Monitor and optimize memory usage"
            ]
        },
        {
            "category": "Monitoring",
            "items": [
                "Set up comprehensive logging and metrics",
                "Monitor agent performance and health",
                "Track threat detection accuracy",
                "Implement alerting for system issues"
            ]
        }
    ]
    
    for rec in recommendations:
        print(f"\n📋 {rec['category']}:")
        for item in rec['items']:
            print(f"   • {item}")


async def main():
    """Main demonstration function"""
    print("🔁 Enhanced CyberSentinel AI - ATITA Demonstration")
    print("=" * 60)
    print("This demo showcases the enhanced architecture with:")
    print("• TinyLlama 1.1B Q4_K_M with Ollama for local LLM inference")
    print("• RAG Pipeline with nomic-embed-text + FAISS for context retrieval")
    print("• Atomic Agents Framework with strict schemas and modular design")
    print("• Guardrails for safety and compliance checks")
    print("=" * 60)
    
    # Setup logging
    setup_logging()
    
    # Check Ollama setup
    ollama_available = await check_ollama_setup()
    
    if not ollama_available:
        print("\n📋 To set up Ollama and TinyLlama:")
        print("1. Install Ollama: https://ollama.ai")
        print("2. Pull TinyLlama: ollama pull tinyllama:1.1b-chat-v1-q4_K_M")
        print("3. Start Ollama service: ollama serve")
        print("4. Run this script again")
        return
    
    # Setup RAG pipeline
    rag_ready = await setup_rag_pipeline()
    
    if not rag_ready:
        print("\n❌ RAG pipeline setup failed. Check dependencies.")
        return
    
    # Test enhanced agents
    agent_results = await test_enhanced_agents()
    print("\n✅ All enhanced agents tested successfully!")
    
    # Demo complete workflow
    workflow_results = await demo_complete_workflow()
    print("\n🎉 Enhanced workflow demo completed!")
    
    # Show configuration
    show_configuration()
    
    # Show recommendations
    get_recommendations()
    
    print("\n🎉 Enhanced architecture demo completed successfully!")
    print("\nThe enhanced architecture provides:")
    print("✅ Local LLM inference with TinyLlama")
    print("✅ RAG pipeline for context retrieval")
    print("✅ Modular agent framework with strict schemas")
    print("✅ Guardrails for safety and compliance")
    print("✅ Lightweight and efficient processing")
    print("✅ Production-ready architecture")


if __name__ == "__main__":
    asyncio.run(main()) 