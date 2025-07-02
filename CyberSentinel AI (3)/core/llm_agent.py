"""
LLM Agent System for CyberSentinel AI - ATITA
Enables true agentic AI with large language models
"""

import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
import json
from core.config import settings
from core.logging import get_logger

logger = get_logger("llm_agent")

# Optional LLM imports
try:
    from openai import OpenAI  # type: ignore
    from anthropic import Anthropic  # type: ignore
    OPENAI_AVAILABLE = True
    ANTHROPIC_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False
    ANTHROPIC_AVAILABLE = False
    logger.warning("LLM libraries not available")

class LLMAgent:
    """LLM-powered agent for intelligent reasoning and decision making"""
    
    def __init__(self):
        self.openai_client = None
        self.anthropic_client = None
        self.llm_provider = getattr(settings, 'llm_provider', 'openai')
        self.model_name = getattr(settings, 'llm_model', 'gpt-4')
        self._initialize_clients()
    
    def _initialize_clients(self):
        """Initialize LLM clients"""
        if OPENAI_AVAILABLE and hasattr(settings, 'openai_api_key'):
            self.openai_client = OpenAI(api_key=settings.openai_api_key)
            logger.info("OpenAI client initialized")
        
        if ANTHROPIC_AVAILABLE and hasattr(settings, 'anthropic_api_key'):
            self.anthropic_client = Anthropic(api_key=settings.anthropic_api_key)
            logger.info("Anthropic client initialized")
    
    async def analyze_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to analyze threat with reasoning"""
        if not self.openai_client and not self.anthropic_client:
            return {"error": "No LLM clients available"}
        
        prompt = self._create_threat_analysis_prompt(threat_data)
        
        try:
            if self.llm_provider == "openai" and self.openai_client:
                response = await self._call_openai(prompt)
            elif self.llm_provider == "anthropic" and self.anthropic_client:
                response = await self._call_anthropic(prompt)
            else:
                return {"error": "No available LLM provider"}
            
            return self._parse_llm_response(response)
            
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return {"error": str(e)}
    
    async def make_decision(self, context: Dict[str, Any], options: List[str]) -> Dict[str, Any]:
        """Use LLM to make intelligent decisions"""
        if not self.openai_client and not self.anthropic_client:
            return {"decision": "escalate", "reasoning": "LLM not available"}
        
        prompt = self._create_decision_prompt(context, options)
        
        try:
            if self.llm_provider == "openai" and self.openai_client:
                response = await self._call_openai(prompt)
            elif self.llm_provider == "anthropic" and self.anthropic_client:
                response = await self._call_anthropic(prompt)
            else:
                return {"decision": "escalate", "reasoning": "No LLM provider available"}
            
            return self._parse_decision_response(response)
            
        except Exception as e:
            logger.error(f"LLM decision failed: {e}")
            return {"decision": "escalate", "reasoning": f"LLM error: {str(e)}"}
    
    async def generate_response_plan(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Use LLM to generate response plans"""
        if not self.openai_client and not self.anthropic_client:
            return {"plan": "escalate_to_human", "reasoning": "LLM not available"}
        
        prompt = self._create_response_plan_prompt(threat_data)
        
        try:
            if self.llm_provider == "openai" and self.openai_client:
                response = await self._call_openai(prompt)
            elif self.llm_provider == "anthropic" and self.anthropic_client:
                response = await self._call_anthropic(prompt)
            else:
                return {"plan": "escalate_to_human", "reasoning": "No LLM provider available"}
            
            return self._parse_plan_response(response)
            
        except Exception as e:
            logger.error(f"LLM plan generation failed: {e}")
            return {"plan": "escalate_to_human", "reasoning": f"LLM error: {str(e)}"}
    
    async def _call_openai(self, prompt: str) -> str:
        """Call OpenAI API"""
        if self.openai_client is None:
            raise RuntimeError("OpenAI client is not initialized")
        response = self.openai_client.chat.completions.create(
            model=self.model_name,
            messages=[
                {"role": "system", "content": "You are a cybersecurity expert AI agent. Provide clear, actionable analysis and decisions."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3,
            max_tokens=1000
        )
        return response.choices[0].message.content
    
    async def _call_anthropic(self, prompt: str) -> str:
        """Call Anthropic API"""
        if self.anthropic_client is None:
            raise RuntimeError("Anthropic client is not initialized")
        response = self.anthropic_client.messages.create(
            model="claude-3-sonnet-20240229",
            max_tokens=1000,
            temperature=0.3,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )
        return response.content[0].text
    
    def _create_threat_analysis_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Create prompt for threat analysis"""
        return f"""
        Analyze this cybersecurity threat and provide detailed reasoning:
        
        Threat Data:
        - Title: {threat_data.get('title', 'N/A')}
        - Description: {threat_data.get('description', 'N/A')}
        - Source: {threat_data.get('source', 'N/A')}
        - Confidence: {threat_data.get('confidence', 'N/A')}
        - Type: {threat_data.get('threat_type', 'N/A')}
        - Severity: {threat_data.get('severity', 'N/A')}
        
        Please provide:
        1. Threat assessment with confidence level
        2. Potential impact analysis
        3. Recommended immediate actions
        4. Key indicators of compromise (IOCs) to look for
        5. Similar threat patterns or campaigns
        
        Respond in JSON format:
        {{
            "assessment": "detailed threat assessment",
            "confidence": 0.85,
            "impact": "high/medium/low",
            "immediate_actions": ["action1", "action2"],
            "iocs": ["indicator1", "indicator2"],
            "similar_patterns": "description of similar threats",
            "reasoning": "detailed reasoning for assessment"
        }}
        """
    
    def _create_decision_prompt(self, context: Dict[str, Any], options: List[str]) -> str:
        """Create prompt for decision making"""
        return f"""
        As a cybersecurity AI agent, make a decision based on this context:
        
        Context: {json.dumps(context, indent=2)}
        
        Available options: {options}
        
        Consider:
        1. Threat severity and confidence
        2. Available resources and time
        3. Potential impact of each decision
        4. Compliance and policy requirements
        
        Respond in JSON format:
        {{
            "decision": "chosen_option",
            "confidence": 0.85,
            "reasoning": "detailed reasoning for decision",
            "risks": ["risk1", "risk2"],
            "benefits": ["benefit1", "benefit2"],
            "alternative_considerations": "other factors considered"
        }}
        """
    
    def _create_response_plan_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Create prompt for response plan generation"""
        return f"""
        Generate a comprehensive response plan for this cybersecurity threat:
        
        Threat: {json.dumps(threat_data, indent=2)}
        
        Create a detailed response plan including:
        1. Immediate containment actions
        2. Investigation steps
        3. Communication plan
        4. Recovery procedures
        5. Lessons learned documentation
        
        Respond in JSON format:
        {{
            "plan_type": "automated/escalated/hybrid",
            "immediate_actions": ["action1", "action2"],
            "investigation_steps": ["step1", "step2"],
            "communication_plan": "who to notify and when",
            "recovery_procedures": ["procedure1", "procedure2"],
            "timeline": "estimated timeline for response",
            "resources_needed": ["resource1", "resource2"],
            "success_criteria": "how to measure success"
        }}
        """
    
    def _parse_llm_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response for threat analysis"""
        try:
            # Try to extract JSON from response
            if "{" in response and "}" in response:
                start = response.find("{")
                end = response.rfind("}") + 1
                json_str = response[start:end]
                return json.loads(json_str)
            else:
                return {"analysis": response, "error": "Could not parse structured response"}
        except json.JSONDecodeError:
            return {"analysis": response, "error": "Invalid JSON response"}
    
    def _parse_decision_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response for decision making"""
        try:
            if "{" in response and "}" in response:
                start = response.find("{")
                end = response.rfind("}") + 1
                json_str = response[start:end]
                return json.loads(json_str)
            else:
                return {"decision": "escalate", "reasoning": response}
        except json.JSONDecodeError:
            return {"decision": "escalate", "reasoning": response}
    
    def _parse_plan_response(self, response: str) -> Dict[str, Any]:
        """Parse LLM response for response plans"""
        try:
            if "{" in response and "}" in response:
                start = response.find("{")
                end = response.rfind("}") + 1
                json_str = response[start:end]
                return json.loads(json_str)
            else:
                return {"plan": "escalate_to_human", "reasoning": response}
        except json.JSONDecodeError:
            return {"plan": "escalate_to_human", "reasoning": response}

# Global LLM agent instance
llm_agent = LLMAgent()
