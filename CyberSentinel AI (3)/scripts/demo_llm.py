"""
Demo script for LLM-enhanced CyberSentinel AI - ATITA
Shows true agentic AI capabilities with large language models
"""

import asyncio
import os
from datetime import datetime
from core.llm_agent import llm_agent
from core.ml_models import threat_classifier, severity_assessor
from core.logging import get_logger

logger = get_logger("demo_llm")

async def demo_llm_analysis():
    """Demo LLM threat analysis"""
    print("🤖 CyberSentinel AI - LLM Agent Demo")
    print("=" * 50)
    
    # Sample threat data
    threat_data = {
        "title": "Suspicious Email with Ransomware Attachment",
        "description": "Employee received email from unknown sender with .exe attachment. Email claims to be from IT department requesting immediate software update. Attachment shows signs of ransomware behavior including file encryption attempts.",
        "source": "email",
        "confidence": 0.85,
        "threat_type": "unknown",
        "severity": "medium"
    }
    
    print(f"📧 Threat: {threat_data['title']}")
    print(f"📝 Description: {threat_data['description']}")
    print(f"🎯 Source: {threat_data['source']}")
    print()
    
    # Traditional ML Analysis
    print("🔬 Traditional ML Analysis:")
    print("-" * 30)
    
    try:
        # Threat classification
        threat_type, type_confidence = threat_classifier.predict(threat_data['description'])
        print(f"   Threat Type: {threat_type} (confidence: {type_confidence:.2f})")
        
        # Severity assessment
        severity, severity_confidence = severity_assessor.predict(threat_data)
        print(f"   Severity: {severity} (confidence: {severity_confidence:.2f})")
        
    except Exception as e:
        print(f"   ML Analysis Error: {e}")
    
    print()
    
    # LLM Analysis
    print("🧠 LLM-Enhanced Analysis:")
    print("-" * 30)
    
    try:
        llm_result = await llm_agent.analyze_threat(threat_data)
        
        if "error" in llm_result:
            print(f"   ❌ LLM Error: {llm_result['error']}")
            print("   💡 To enable LLM analysis, set your API keys:")
            print("      export OPENAI_API_KEY='your-key-here'")
            print("      export ANTHROPIC_API_KEY='your-key-here'")
        else:
            print(f"   🎯 Assessment: {llm_result.get('assessment', 'N/A')}")
            print(f"   📊 Confidence: {llm_result.get('confidence', 'N/A')}")
            print(f"   ⚠️  Impact: {llm_result.get('impact', 'N/A')}")
            print(f"   🚨 Immediate Actions: {llm_result.get('immediate_actions', [])}")
            print(f"   🔍 IOCs: {llm_result.get('iocs', [])}")
            print(f"   💭 Reasoning: {llm_result.get('reasoning', 'N/A')}")
            
    except Exception as e:
        print(f"   ❌ LLM Analysis Error: {e}")
    
    print()
    
    # Decision Making Demo
    print("🎯 LLM Decision Making:")
    print("-" * 30)
    
    context = {
        "threat_severity": "high",
        "confidence": 0.85,
        "available_resources": ["automated_response", "human_analyst"],
        "time_constraint": "immediate"
    }
    
    options = ["auto_contain", "escalate_to_analyst", "block_and_isolate"]
    
    try:
        decision_result = await llm_agent.make_decision(context, options)
        
        if "error" in decision_result:
            print(f"   ❌ Decision Error: {decision_result['error']}")
        else:
            print(f"   🎯 Decision: {decision_result.get('decision', 'N/A')}")
            print(f"   📊 Confidence: {decision_result.get('confidence', 'N/A')}")
            print(f"   💭 Reasoning: {decision_result.get('reasoning', 'N/A')}")
            print(f"   ⚠️  Risks: {decision_result.get('risks', [])}")
            print(f"   ✅ Benefits: {decision_result.get('benefits', [])}")
            
    except Exception as e:
        print(f"   ❌ Decision Error: {e}")
    
    print()
    
    # Response Plan Generation
    print("📋 LLM Response Plan Generation:")
    print("-" * 40)
    
    try:
        plan_result = await llm_agent.generate_response_plan(threat_data)
        
        if "error" in plan_result:
            print(f"   ❌ Plan Error: {plan_result['error']}")
        else:
            print(f"   📋 Plan Type: {plan_result.get('plan_type', 'N/A')}")
            print(f"   ⚡ Immediate Actions: {plan_result.get('immediate_actions', [])}")
            print(f"   🔍 Investigation Steps: {plan_result.get('investigation_steps', [])}")
            print(f"   📞 Communication: {plan_result.get('communication_plan', 'N/A')}")
            print(f"   ⏰ Timeline: {plan_result.get('timeline', 'N/A')}")
            print(f"   🎯 Success Criteria: {plan_result.get('success_criteria', 'N/A')}")
            
    except Exception as e:
        print(f"   ❌ Plan Error: {e}")
    
    print()
    print("=" * 50)
    print("🎉 Demo completed!")
    print()
    print("💡 Key Benefits of LLM Integration:")
    print("   • Natural language reasoning and explanation")
    print("   • Context-aware decision making")
    print("   • Detailed threat analysis with IOCs")
    print("   • Comprehensive response planning")
    print("   • Human-like reasoning capabilities")
    print()
    print("🚀 This is true agentic AI - the system can now:")
    print("   • Understand and reason about threats")
    print("   • Make intelligent decisions with explanations")
    print("   • Generate comprehensive response plans")
    print("   • Provide human-like analysis and recommendations")

async def main():
    """Main demo function"""
    await demo_llm_analysis()

if __name__ == "__main__":
    asyncio.run(main()) 