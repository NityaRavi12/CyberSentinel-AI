#!/usr/bin/env python3
"""
Setup script for Enhanced CyberSentinel AI - ATITA
Automates the setup of Ollama, TinyLlama, and dependencies
"""

import os
import sys
import subprocess
import platform
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors"""
    print(f"🔄 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed: {e}")
        print(f"Error output: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible"""
    print("🐍 Checking Python version...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 9):
        print(f"❌ Python 3.9+ required, found {version.major}.{version.minor}")
        return False
    print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
    return True

def install_ollama():
    """Install Ollama based on platform"""
    system = platform.system().lower()
    
    if system == "linux":
        return run_command(
            "curl -fsSL https://ollama.ai/install.sh | sh",
            "Installing Ollama on Linux"
        )
    elif system == "darwin":  # macOS
        return run_command(
            "curl -fsSL https://ollama.ai/install.sh | sh",
            "Installing Ollama on macOS"
        )
    elif system == "windows":
        print("⚠️  Ollama installation on Windows requires manual setup")
        print("Please visit: https://ollama.ai/download/windows")
        return False
    else:
        print(f"❌ Unsupported platform: {system}")
        return False

def pull_tinyllama():
    """Pull TinyLlama model"""
    return run_command(
        "ollama pull tinyllama:1.1b-chat-v1-q4_K_M",
        "Pulling TinyLlama model"
    )

def install_python_dependencies():
    """Install Python dependencies"""
    return run_command(
        "pip install -r requirements.txt",
        "Installing Python dependencies"
    )

def setup_environment():
    """Set up environment file"""
    env_file = Path(".env")
    env_example = Path("env.example")
    
    if not env_file.exists() and env_example.exists():
        print("📝 Setting up environment file...")
        try:
            import shutil
            shutil.copy(env_example, env_file)
            print("✅ Environment file created from template")
            print("⚠️  Please edit .env file with your configuration")
            return True
        except Exception as e:
            print(f"❌ Failed to create environment file: {e}")
            return False
    else:
        print("✅ Environment file already exists")
        return True

def create_directories():
    """Create necessary directories"""
    directories = [
        "data/models",
        "data/knowledge_base",
        "data/finetuned_models",
        "logs",
        "uploads",
        "backups"
    ]
    
    print("📁 Creating directories...")
    for directory in directories:
        try:
            Path(directory).mkdir(parents=True, exist_ok=True)
            print(f"   ✅ Created {directory}")
        except Exception as e:
            print(f"   ❌ Failed to create {directory}: {e}")
            return False
    
    return True

def test_ollama_connection():
    """Test Ollama connection"""
    print("🔍 Testing Ollama connection...")
    try:
        result = subprocess.run(
            "ollama list", 
            shell=True, 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        if result.returncode == 0:
            print("✅ Ollama is running and accessible")
            if "tinyllama" in result.stdout:
                print("✅ TinyLlama model is available")
                return True
            else:
                print("⚠️  TinyLlama model not found, pulling...")
                return pull_tinyllama()
        else:
            print("❌ Ollama is not running")
            print("Please start Ollama with: ollama serve")
            return False
    except subprocess.TimeoutExpired:
        print("❌ Ollama connection timeout")
        return False
    except Exception as e:
        print(f"❌ Ollama test failed: {e}")
        return False

def run_health_check():
    """Run a basic health check"""
    print("🏥 Running health check...")
    
    # Test imports
    try:
        sys.path.insert(0, str(Path.cwd()))
        from core.config import settings
        from core.logging import setup_logging
        print("✅ Core modules imported successfully")
    except Exception as e:
        print(f"❌ Core module import failed: {e}")
        return False
    
    # Test configuration
    try:
        print(f"✅ Configuration loaded: {settings.app_name}")
        print(f"✅ Environment: {settings.environment}")
        print(f"✅ LLM Provider: {settings.llm_provider}")
        print(f"✅ Agent Framework: {settings.agent_framework}")
    except Exception as e:
        print(f"❌ Configuration test failed: {e}")
        return False
    
    return True

def main():
    """Main setup function"""
    print("🔁 Enhanced CyberSentinel AI - ATITA Setup")
    print("=" * 50)
    
    # Check Python version
    if not check_python_version():
        sys.exit(1)
    
    # Install Python dependencies
    if not install_python_dependencies():
        print("❌ Failed to install Python dependencies")
        sys.exit(1)
    
    # Set up environment
    if not setup_environment():
        print("❌ Failed to set up environment")
        sys.exit(1)
    
    # Create directories
    if not create_directories():
        print("❌ Failed to create directories")
        sys.exit(1)
    
    # Install Ollama
    if not install_ollama():
        print("⚠️  Ollama installation failed or requires manual setup")
        print("Please install Ollama manually and run this script again")
    
    # Test Ollama
    if not test_ollama_connection():
        print("❌ Ollama test failed")
        print("Please ensure Ollama is running with: ollama serve")
        sys.exit(1)
    
    # Run health check
    if not run_health_check():
        print("❌ Health check failed")
        sys.exit(1)
    
    print("\n🎉 Enhanced CyberSentinel AI setup completed successfully!")
    print("\n📋 Next steps:")
    print("1. Edit .env file with your configuration")
    print("2. Start Ollama: ollama serve")
    print("3. Run the demo: python scripts/enhanced_demo.py")
    print("4. Or run the notebook: jupyter notebook notebooks/enhanced_architecture_demo.ipynb")
    print("\n🚀 Your enhanced cybersecurity AI system is ready!")

if __name__ == "__main__":
    main() 