#!/usr/bin/env python3
"""
Demo script for LLM-enhanced CyberSentinel AI - ATITA
Shows true agentic AI capabilities with large language models

This script can be converted to a Jupyter notebook by splitting at the # %% markers
"""

# %% [markdown]
# # CyberSentinel AI - LLM Integration Demo
# 
# **Agentic AI with Large Language Models**
# 
# This notebook demonstrates the advanced LLM integration capabilities of CyberSentinel AI, showing how the system uses large language models for intelligent reasoning, decision-making, and threat analysis.
# 
# ## 🎯 What You'll Learn
# 
# - How LLMs enhance traditional ML threat detection
# - Natural language reasoning and explanation
# - Intelligent decision-making with context awareness
# - Comprehensive response plan generation
# - True agentic AI capabilities

# %% [markdown]
# ## 🚀 Setup and Imports

# %%
import asyncio
import os
import sys
from pathlib import Path
from datetime import datetime
import json
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Add the project root to the Python path
project_root = Path.cwd().parent
sys.path.insert(0, str(project_root))

from core.llm_agent import llm_agent
from core.ml_models import threat_classifier, severity_assessor
from core.logging import get_logger

logger = get_logger("demo_llm")

print("✅ Imports successful!")
print(f"📁 Project root: {project_root}")

# %% [markdown]
# ## 🔧 API Key Configuration
# 
# To enable LLM features, you need to set your API keys. You can either:
# 
# 1. Set environment variables
# 2. Add them to your `.env` file
# 3. Configure them in the notebook below

# %%
# Check if API keys are available
openai_key = os.getenv('OPENAI_API_KEY')
anthropic_key = os.getenv('ANTHROPIC_API_KEY')

print("🔑 API Key Status:")
print(f"   OpenAI: {'✅ Available' if openai_key else '❌ Not set'}")
print(f"   Anthropic: {'✅ Available' if anthropic_key else '❌ Not set'}")

if not openai_key and not anthropic_key:
    print("\n💡 To enable LLM features, set your API keys:")
    print("   export OPENAI_API_KEY='your-key-here'")
    print("   export ANTHROPIC_API_KEY='your-key-here'")
    print("\n   Or add them to your .env file")
else:
    print("\n🎉 LLM features are ready to use!")

# %% [markdown]
# ## 📊 Sample Threat Data
# 
# Let's create a realistic threat scenario to demonstrate the LLM capabilities.

# %%
# Sample threat data for demonstration
threat_data = {
    "title": "Suspicious Email with Ransomware Attachment",
    "description": "Employee received email from unknown sender with .exe attachment. Email claims to be from IT department requesting immediate software update. Attachment shows signs of ransomware behavior including file encryption attempts.",
    "source": "email",
    "confidence": 0.85,
    "threat_type": "unknown",
    "severity": "medium"
}

print("📧 Threat Details:")
print(f"   Title: {threat_data['title']}")
print(f"   Description: {threat_data['description']}")
print(f"   Source: {threat_data['source']}")
print(f"   Initial Confidence: {threat_data['confidence']}")
print(f"   Initial Type: {threat_data['threat_type']}")
print(f"   Initial Severity: {threat_data['severity']}")

# %% [markdown]
# ## 🔬 Traditional ML Analysis
# 
# First, let's see how traditional machine learning models analyze this threat.

# %%
print("🔬 Traditional ML Analysis:")
print("=" * 50)

try:
    # Threat classification using ML model
    threat_type, type_confidence = threat_classifier.predict(threat_data['description'])
    print(f"   🎯 Threat Type: {threat_type} (confidence: {type_confidence:.2f})")
    
    # Severity assessment using ML model
    severity, severity_confidence = severity_assessor.predict(threat_data)
    print(f"   ⚠️  Severity: {severity} (confidence: {severity_confidence:.2f})")
    
    # Create a summary
    ml_summary = {
        'Threat Type': threat_type,
        'Type Confidence': type_confidence,
        'Severity': severity,
        'Severity Confidence': severity_confidence
    }
    
    print(f"\n📊 ML Analysis Summary:")
    for key, value in ml_summary.items():
        print(f"   {key}: {value}")
    
except Exception as e:
    print(f"   ❌ ML Analysis Error: {e}")
    print("   💡 This might be due to missing training data or model files")

# %% [markdown]
# ## 🧠 LLM-Enhanced Analysis
# 
# Now let's see how the LLM provides much richer analysis with natural language reasoning.

# %%
print("🧠 LLM-Enhanced Analysis:")
print("=" * 50)

try:
    # Use LLM for comprehensive threat analysis
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
        
        # Store LLM results for comparison
        llm_summary = llm_result
        
except Exception as e:
    print(f"   ❌ LLM Analysis Error: {e}")
    print("   💡 This might be due to API key issues or network problems")

# %% [markdown]
# ## 📊 Comparison: ML vs LLM Analysis
# 
# Let's compare the results from traditional ML and LLM analysis.

# %%
# Create comparison table
comparison_data = {
    'Aspect': ['Analysis Type', 'Threat Classification', 'Severity Assessment', 'Confidence', 'Reasoning', 'Actions Provided', 'IOCs Identified'],
    'Traditional ML': [
        'Statistical/Pattern-based',
        ml_summary.get('Threat Type', 'N/A'),
        ml_summary.get('Severity', 'N/A'),
        f"{ml_summary.get('Type Confidence', 0):.2f}",
        'Limited (confidence scores only)',
        'None',
        'None'
    ],
    'LLM-Enhanced': [
        'Natural Language/Contextual',
        llm_summary.get('assessment', 'N/A'),
        llm_summary.get('impact', 'N/A'),
        f"{llm_summary.get('confidence', 0):.2f}",
        llm_summary.get('reasoning', 'N/A'),
        str(len(llm_summary.get('immediate_actions', []))),
        str(len(llm_summary.get('iocs', [])))
    ]
}

comparison_df = pd.DataFrame(comparison_data)
print("📊 ML vs LLM Analysis Comparison:")
print(comparison_df.to_string(index=False))

print("\n💡 Key Differences:")
print("   • LLM provides natural language reasoning")
print("   • LLM identifies specific IOCs and actions")
print("   • LLM considers context and nuance")
print("   • Traditional ML is faster but less detailed")

# %% [markdown]
# ## 🎯 LLM Decision Making
# 
# Now let's see how the LLM makes intelligent decisions based on context and available options.

# %%
print("🎯 LLM Decision Making:")
print("=" * 50)

# Create decision context
context = {
    "threat_severity": "high",
    "confidence": 0.85,
    "available_resources": ["automated_response", "human_analyst", "security_tools"],
    "time_constraint": "immediate",
    "business_impact": "critical",
    "compliance_requirements": ["GDPR", "SOX"]
}

options = ["auto_contain", "escalate_to_analyst", "block_and_isolate", "investigate_further"]

print(f"📋 Decision Context:")
for key, value in context.items():
    print(f"   {key}: {value}")

print(f"\n🎯 Available Options: {options}")

# %%
try:
    # Use LLM for decision making
    decision_result = await llm_agent.make_decision(context, options)
    
    if "error" in decision_result:
        print(f"   ❌ Decision Error: {decision_result['error']}")
    else:
        print(f"   🎯 Decision: {decision_result.get('decision', 'N/A')}")
        print(f"   📊 Confidence: {decision_result.get('confidence', 'N/A')}")
        print(f"   💭 Reasoning: {decision_result.get('reasoning', 'N/A')}")
        print(f"   ⚠️  Risks: {decision_result.get('risks', [])}")
        print(f"   ✅ Benefits: {decision_result.get('benefits', [])}")
        print(f"   🤔 Alternative Considerations: {decision_result.get('alternative_considerations', 'N/A')}")
        
        # Store decision results
        decision_summary = decision_result
        
except Exception as e:
    print(f"   ❌ Decision Error: {e}")

# %% [markdown]
# ## 📋 LLM Response Plan Generation
# 
# Let's see how the LLM generates comprehensive response plans.

# %%
print("📋 LLM Response Plan Generation:")
print("=" * 50)

try:
    # Generate comprehensive response plan
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
        print(f"   📦 Resources Needed: {plan_result.get('resources_needed', [])}")
        
        # Store plan results
        plan_summary = plan_result
        
except Exception as e:
    print(f"   ❌ Plan Error: {e}")

# %% [markdown]
# ## 📊 Response Plan Visualization
# 
# Let's visualize the response plan components.

# %%
# Create visualizations of the response plan
if 'plan_summary' in locals() and 'error' not in plan_summary:
    fig, axes = plt.subplots(2, 2, figsize=(15, 12))
    
    # Immediate actions
    immediate_actions = plan_summary.get('immediate_actions', [])
    if immediate_actions:
        axes[0, 0].bar(range(len(immediate_actions)), [1]*len(immediate_actions))
        axes[0, 0].set_title('Immediate Actions')
        axes[0, 0].set_xticks(range(len(immediate_actions)))
        axes[0, 0].set_xticklabels([f'Action {i+1}' for i in range(len(immediate_actions))], rotation=45)
    
    # Investigation steps
    investigation_steps = plan_summary.get('investigation_steps', [])
    if investigation_steps:
        axes[0, 1].bar(range(len(investigation_steps)), [1]*len(investigation_steps))
        axes[0, 1].set_title('Investigation Steps')
        axes[0, 1].set_xticks(range(len(investigation_steps)))
        axes[0, 1].set_xticklabels([f'Step {i+1}' for i in range(len(investigation_steps))], rotation=45)
    
    # Resources needed
    resources = plan_summary.get('resources_needed', [])
    if resources:
        axes[1, 0].pie([1]*len(resources), labels=resources, autopct='%1.1f%%')
        axes[1, 0].set_title('Resources Needed')
    
    # Plan type
    plan_type = plan_summary.get('plan_type', 'Unknown')
    axes[1, 1].text(0.5, 0.5, f'Plan Type:\n{plan_type}', 
                    ha='center', va='center', fontsize=14, 
                    bbox=dict(boxstyle='round', facecolor='lightblue', alpha=0.8))
    axes[1, 1].set_title('Response Plan Type')
    axes[1, 1].axis('off')
    
    plt.tight_layout()
    plt.show()
else:
    print("📊 No plan data available for visualization")

# %% [markdown]
# ## 🚀 Agentic AI Capabilities Summary
# 
# Let's summarize what we've demonstrated about true agentic AI capabilities.

# %%
print("🚀 Agentic AI Capabilities Demonstrated:")
print("=" * 60)

capabilities = [
    "🧠 Natural Language Understanding",
    "💭 Contextual Reasoning",
    "🎯 Intelligent Decision Making",
    "📋 Comprehensive Planning",
    "🔍 Detailed Analysis",
    "⚡ Real-time Response",
    "📊 Risk Assessment",
    "🤝 Human-like Communication"
]

for i, capability in enumerate(capabilities, 1):
    print(f"   {i}. {capability}")

print("\n💡 Key Benefits of LLM Integration:")
benefits = [
    "• Natural language reasoning and explanation",
    "• Context-aware decision making",
    "• Detailed threat analysis with IOCs",
    "• Comprehensive response planning",
    "• Human-like reasoning capabilities",
    "• Adaptable to new threat patterns",
    "• Explainable AI decisions"
]

for benefit in benefits:
    print(f"   {benefit}")

print("\n🎯 This is true agentic AI - the system can now:")
ai_capabilities = [
    "• Understand and reason about threats",
    "• Make intelligent decisions with explanations",
    "• Generate comprehensive response plans",
    "• Provide human-like analysis and recommendations",
    "• Adapt to changing threat landscapes",
    "• Learn from feedback and improve over time"
]

for capability in ai_capabilities:
    print(f"   {capability}")

# %% [markdown]
# ## 🎉 Demo Summary
# 
# This notebook has demonstrated the advanced LLM integration capabilities of CyberSentinel AI - ATITA, showing how the system combines traditional machine learning with modern agentic AI for superior threat detection and response.

# %%
print("🎉 LLM Integration Demo Completed!")
print("=" * 50)
print("\n📊 Demo Summary:")
print(f"   • Threat analyzed: {threat_data['title']}")
print(f"   • ML analysis: {'✅ Completed' if 'ml_summary' in locals() else '❌ Failed'}")
print(f"   • LLM analysis: {'✅ Completed' if 'llm_summary' in locals() else '❌ Failed'}")
print(f"   • Decision making: {'✅ Completed' if 'decision_summary' in locals() else '❌ Failed'}")
print(f"   • Response planning: {'✅ Completed' if 'plan_summary' in locals() else '❌ Failed'}")

print("\n🚀 CyberSentinel AI - ATITA with LLM Integration is ready!")
print("   The system successfully demonstrated agentic AI capabilities")
print("   with natural language reasoning and intelligent decision-making.")

print("\n💡 Next Steps:")
print("   • Set up API keys for production use")
print("   • Configure LLM providers and models")
print("   • Integrate with your security infrastructure")
print("   • Train on your specific threat data")
print("   • Deploy in production environment") 