"""
Configuration management for CyberSentinel AI - ATITA
"""

import os
from pathlib import Path
from typing import Optional
from pydantic_settings import BaseSettings
from pydantic import validator

class Settings(BaseSettings):
    """Application settings"""
    
    # Application settings
    app_name: str = "CyberSentinel AI - ATITA"
    app_version: str = "1.0.0"
    debug: bool = False
    environment: str = "development"
    
    # Server settings
    host: str = "0.0.0.0"
    port: int = 8000
    workers: int = 1
    
    # Database settings
    database_url: str = "sqlite:///./cybersentinel.db"
    database_pool_size: int = 10
    database_max_overflow: int = 20
    
    # Security settings
    secret_key: str = "your-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    
    # Rate limiting
    rate_limit_requests: int = 100
    rate_limit_window: int = 60  # seconds
    
    # CORS settings
    cors_origins: list = ["http://localhost:3000", "https://cybersentinel.ai"]
    cors_allow_credentials: bool = True
    
    # Trusted hosts
    trusted_hosts: list = ["localhost", "127.0.0.1", "cybersentinel.ai"]
    
    # Redis settings
    redis_url: str = "redis://localhost:6379/0"
    redis_max_connections: int = 10
    
    # ML Model settings
    model_path: str = "./data/models"
    model_cache_ttl: int = 86400  # 24 hours
    
    # Threat Intelligence settings
    virustotal_api_key: Optional[str] = None
    alienvault_api_key: Optional[str] = None
    threatfox_api_key: Optional[str] = None
    
    # Email settings
    smtp_host: Optional[str] = None
    smtp_port: int = 587
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    smtp_use_tls: bool = True
    
    # Logging settings
    log_level: str = "INFO"
    log_file: str = "./logs/cybersentinel.log"
    log_max_size: int = 10 * 1024 * 1024  # 10MB
    log_backup_count: int = 5
    
    # Monitoring settings
    enable_metrics: bool = True
    metrics_port: int = 9090
    health_check_interval: int = 30  # seconds
    
    # Agent settings
    agent_timeout: int = 300  # 5 minutes
    agent_retry_attempts: int = 3
    agent_heartbeat_interval: int = 60  # seconds
    
    # Threat processing settings
    max_concurrent_threats: int = 10
    threat_processing_timeout: int = 600  # 10 minutes
    auto_escalation_threshold: float = 0.8
    
    # File upload settings
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    allowed_file_types: list = [".txt", ".pdf", ".doc", ".docx", ".eml", ".pcap"]
    upload_path: str = "./uploads"
    
    # Backup settings
    backup_enabled: bool = True
    backup_interval: int = 86400  # 24 hours
    backup_retention_days: int = 30
    backup_path: str = "./backups"
    
    # API settings
    api_rate_limit: int = 1000
    api_rate_limit_window: int = 3600  # 1 hour
    api_version: str = "v1"
    
    # Notification settings
    enable_notifications: bool = True
    notification_channels: list = ["email", "webhook"]
    webhook_url: Optional[str] = None
    
    # Performance settings
    enable_caching: bool = True
    cache_ttl: int = 3600  # 1 hour
    enable_compression: bool = True
    
    # Development settings
    enable_swagger: bool = True
    enable_reload: bool = False
    
    # Enhanced Architecture Settings
    # Ollama settings
    ollama_host: str = "http://localhost:11434"
    ollama_model: str = "tinyllama:1.1b-chat-v1-q4_K_M"
    
    # RAG Pipeline settings
    rag_knowledge_base_path: str = "./data/knowledge_base"
    rag_embedding_model: str = "nomic-embed-text-v1.5"
    rag_index_dimension: int = 768
    rag_search_top_k: int = 10
    
    # Enhanced LLM settings
    enhanced_llm_enabled: bool = True
    enhanced_llm_temperature: float = 0.3
    enhanced_llm_max_tokens: int = 1000
    
    # Agent Framework settings
    agent_framework: str = "enhanced"  # "original" or "enhanced"
    agent_memory_enabled: bool = True
    agent_structured_outputs: bool = True
    
    # Fine-tuning settings
    finetuning_enabled: bool = False
    finetuning_model_path: str = "./data/finetuned_models"
    finetuning_lora_r: int = 16
    finetuning_lora_alpha: int = 32
    finetuning_lora_dropout: float = 0.1
    
    # Guardrails settings
    guardrails_enabled: bool = True
    guardrails_hallucination_threshold: float = 0.8
    guardrails_policy_compliance_check: bool = True
    
    # Legacy LLM settings (for backward compatibility)
    llm_provider: str = "ollama"  # ollama, openai, anthropic
    llm_model: str = "tinyllama:1.1b-chat-v1-q4_K_M"
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    llm_enabled: bool = True
    llm_temperature: float = 0.3
    llm_max_tokens: int = 1000
    
    @validator('secret_key')
    def validate_secret_key(cls, v):
        if v == "your-secret-key-change-in-production":
            print("WARNING: Using default secret key. Change this in production!")
        if len(v) < 32:
            raise ValueError("Secret key must be at least 32 characters long")
        return v
    
    @validator('environment')
    def validate_environment(cls, v):
        if v not in ['development', 'staging', 'production']:
            raise ValueError("Environment must be development, staging, or production")
        return v
    
    @validator('log_level')
    def validate_log_level(cls, v):
        valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
        if v.upper() not in valid_levels:
            raise ValueError(f"Log level must be one of {valid_levels}")
        return v.upper()
    
    def is_production(self) -> bool:
        """Check if running in production"""
        return self.environment == "production"
    
    def is_development(self) -> bool:
        """Check if running in development"""
        return self.environment == "development"
    
    def get_database_url(self) -> str:
        """Get database URL with proper formatting"""
        if self.database_url.startswith("sqlite"):
            return self.database_url
        elif self.database_url.startswith("postgresql"):
            return f"{self.database_url}?pool_size={self.database_pool_size}&max_overflow={self.database_max_overflow}"
        else:
            return self.database_url
    
    def get_redis_config(self) -> dict:
        """Get Redis configuration"""
        return {
            "url": self.redis_url,
            "max_connections": self.redis_max_connections,
            "retry_on_timeout": True,
            "socket_keepalive": True,
            "socket_keepalive_options": {},
            "health_check_interval": 30
        }
    
    def get_cors_config(self) -> dict:
        """Get CORS configuration"""
        return {
            "allow_origins": self.cors_origins,
            "allow_credentials": self.cors_allow_credentials,
            "allow_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["*"],
            "expose_headers": ["Content-Length", "X-Total-Count"]
        }
    
    def get_security_headers(self) -> dict:
        """Get security headers configuration"""
        return {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()"
        }
    
    def get_enhanced_llm_config(self) -> dict:
        """Get enhanced LLM configuration"""
        return {
            "model_name": self.ollama_model,
            "host": self.ollama_host,
            "temperature": self.enhanced_llm_temperature,
            "max_tokens": self.enhanced_llm_max_tokens,
            "enabled": self.enhanced_llm_enabled
        }
    
    def get_rag_config(self) -> dict:
        """Get RAG pipeline configuration"""
        return {
            "knowledge_base_path": self.rag_knowledge_base_path,
            "embedding_model": self.rag_embedding_model,
            "index_dimension": self.rag_index_dimension,
            "search_top_k": self.rag_search_top_k
        }
    
    def get_agent_config(self) -> dict:
        """Get agent framework configuration"""
        return {
            "framework": self.agent_framework,
            "memory_enabled": self.agent_memory_enabled,
            "structured_outputs": self.agent_structured_outputs,
            "timeout": self.agent_timeout,
            "retry_attempts": self.agent_retry_attempts
        }
    
    def get_guardrails_config(self) -> dict:
        """Get guardrails configuration"""
        return {
            "enabled": self.guardrails_enabled,
            "hallucination_threshold": self.guardrails_hallucination_threshold,
            "policy_compliance_check": self.guardrails_policy_compliance_check
        }
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

# Global settings instance
settings = Settings()

def create_directories():
    """Create necessary directories"""
    directories = [
        settings.model_path,
        settings.upload_path,
        settings.backup_path,
        settings.rag_knowledge_base_path,
        settings.finetuning_model_path,
        Path(settings.log_file).parent
    ]
    
    for directory in directories:
        Path(directory).mkdir(parents=True, exist_ok=True)

# Create directories on import
create_directories() 