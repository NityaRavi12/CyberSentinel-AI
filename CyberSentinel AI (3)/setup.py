from setuptools import setup, find_packages

setup(
    name="cybersentinel-ai",
    version="1.0.0",
    description="CyberSentinel AI - Advanced Cybersecurity System with Multi-Agent Architecture",
    author="CyberSentinel Team",
    packages=find_packages(),
    install_requires=[
        "torch",
        "transformers",
        "peft",
        "datasets",
        "faiss-cpu",
        "nomic",
        "instructor",
        "ollama",
        "fastapi",
        "uvicorn",
        "pydantic",
        "pyyaml",
        "numpy",
        "pandas",
        "scikit-learn",
        "requests",
        "aiohttp"
    ],
    python_requires=">=3.8",
) 