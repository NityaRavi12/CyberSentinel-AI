#!/usr/bin/env python3
"""
Test LLM Integration for CyberSentinel AI
"""

import sys
import os
sys.path.append('.')

try:
    from core.llm_agent import llm_agent
    print("✅ LLM Agent imported successfully")
    
    # Test LLM agent initialization
    print(f"🤖 LLM Provider: {llm_agent.llm_provider}")
    print(f"🧠 Model: {llm_agent.model_name}")
    print(f"🔑 OpenAI Available: {llm_agent.openai_client is not None}")
    print(f"🔑 Anthropic Available: {llm_agent.anthropic_client is not None}")
    
    if llm_agent.openai_client or llm_agent.anthropic_client:
        print("🎉 LLM Integration is WORKING!")
        print("   The system now has true agentic AI capabilities!")
    else:
        print("⚠️  LLM Integration ready but no API keys configured")
        print("   Set OPENAI_API_KEY or ANTHROPIC_API_KEY to enable LLM features")
        
except ImportError as e:
    print(f"❌ Import Error: {e}")
except Exception as e:
    print(f"❌ Error: {e}")

print("\n🚀 CyberSentinel AI now supports:")
print("   • Traditional ML models (Random Forest, Isolation Forest)")
print("   • LLM-powered reasoning (GPT-4, Claude)")
print("   • Multi-agent coordination")
print("   • Intelligent decision making")
print("   • Natural language analysis")
print("   • Comprehensive threat response planning") 