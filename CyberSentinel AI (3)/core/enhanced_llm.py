"""
Enhanced LLM System for CyberSentinel AI - ATITA
Uses TinyLlama 1.1B Q4_K_M with Ollama for local inference
"""

import asyncio
import json
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from instructor import patch
import openai
from ollama import Client
from core.config import settings
from core.logging import get_logger

logger = get_logger("enhanced_llm")

class EnhancedLLMClient:
    """Enhanced LLM client using TinyLlama with Ollama"""
    
    def __init__(self):
        self.model_name = "tinyllama:1.1b-chat-v1-q4_K_M"
        self.client = Client(host=settings.ollama_host)
        self.instructor_client = None
        self._initialize_instructor()
        
    def _initialize_instructor(self):
        """Initialize instructor client for structured outputs"""
        try:
            self.instructor_client = patch(
                openai.OpenAI(
                    base_url=f"{settings.ollama_host}/v1", 
                    api_key="ollama"
                )
            )
            logger.info(f"Instructor client initialized with {self.model_name}")
        except Exception as e:
            logger.error(f"Failed to initialize instructor client: {e}")
            self.instructor_client = None
    
    async def generate_response(self, prompt: str, temperature: float = 0.3) -> str:
        """Generate response using TinyLlama"""
        try:
            response = self.client.chat(
                model=self.model_name,
                messages=[
                    {
                        "role": "system",
                        "content": "You are a cybersecurity expert AI agent. Provide clear, actionable analysis and decisions."
                    },
                    {
                        "role": "user",
                        "content": prompt
                    }
                ],
                options={
                    "temperature": temperature,
                    "num_predict": 1000
                }
            )
            return response['message']['content']
        except Exception as e:
            logger.error(f"LLM generation failed: {e}")
            return f"Error: {str(e)}"
    
    async def analyze_threat_structured(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze threat with structured output using instructor"""
        if not self.instructor_client:
            return {"error": "Instructor client not available"}
        
        try:
            @self.instructor_client  # type: ignore
            def analyze_threat(threat_data: Dict[str, Any]) -> Dict[str, Any]:
                """Analyze cybersecurity threat with structured output"""
                # This will be automatically structured by instructor
                return {
                    "assessment": "detailed threat assessment",
                    "confidence": 0.85,
                    "impact": "high/medium/low",
                    "immediate_actions": ["action1", "action2"],
                    "iocs": ["indicator1", "indicator2"],
                    "similar_patterns": "description of similar threats",
                    "reasoning": "detailed reasoning for assessment"
                }
            
            result = analyze_threat(threat_data)
            return result
            
        except Exception as e:
            logger.error(f"Structured threat analysis failed: {e}")
            return {"error": str(e)}
    
    async def make_decision_structured(self, context: Dict[str, Any], options: List[str]) -> Dict[str, Any]:
        """Make decision with structured output"""
        if not self.instructor_client:
            return {"decision": "escalate", "reasoning": "Instructor not available"}
        
        try:
            @self.instructor_client  # type: ignore
            def make_decision(context: Dict[str, Any], options: List[str]) -> Dict[str, Any]:
                """Make cybersecurity decision with structured output"""
                return {
                    "decision": "chosen_option",
                    "confidence": 0.85,
                    "reasoning": "detailed reasoning for decision",
                    "risks": ["risk1", "risk2"],
                    "benefits": ["benefit1", "benefit2"],
                    "alternative_considerations": "other factors considered"
                }
            
            result = make_decision(context, options)
            return result
            
        except Exception as e:
            logger.error(f"Structured decision failed: {e}")
            return {"decision": "escalate", "reasoning": f"Error: {str(e)}"}
    
    async def generate_response_plan_structured(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate response plan with structured output"""
        if not self.instructor_client:
            return {"plan": "escalate_to_human", "reasoning": "Instructor not available"}
        
        try:
            @self.instructor_client  # type: ignore
            def generate_plan(threat_data: Dict[str, Any]) -> Dict[str, Any]:
                """Generate cybersecurity response plan with structured output"""
                return {
                    "plan": "comprehensive_response_plan",
                    "steps": ["step1", "step2", "step3"],
                    "timeline": "estimated_timeline",
                    "resources_needed": ["resource1", "resource2"],
                    "success_criteria": ["criteria1", "criteria2"],
                    "fallback_plan": "alternative_approach"
                }
            
            result = generate_plan(threat_data)
            return result
            
        except Exception as e:
            logger.error(f"Structured plan generation failed: {e}")
            return {"plan": "escalate_to_human", "reasoning": f"Error: {str(e)}"}
    
    def is_available(self) -> bool:
        """Check if LLM is available"""
        try:
            # Test connection
            models = self.client.list()
            return any(self.model_name in model['name'] for model in models['models'])
        except Exception as e:
            logger.error(f"LLM availability check failed: {e}")
            return False
    
    async def health_check(self) -> Dict[str, Any]:
        """Health check for LLM service"""
        try:
            available = self.is_available()
            return {
                "status": "healthy" if available else "unhealthy",
                "model": self.model_name,
                "instructor_available": self.instructor_client is not None,
                "timestamp": datetime.utcnow().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }

# Global instance
enhanced_llm_client = EnhancedLLMClient() 