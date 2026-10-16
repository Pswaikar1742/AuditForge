"""AuditForge Application Configuration."""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load .env if present
load_dotenv()

class Config:
    """Central configuration for AuditForge."""
    
    # Storage
    DB_PATH: str = os.getenv("AUDITFORGE_DB_PATH", "auditforge.db")
    
    # Open-Weight AI (Ollama)
    OLLAMA_HOST: str = os.getenv("OLLAMA_HOST", "http://localhost:11434")
    OLLAMA_MODEL: str = os.getenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    OLLAMA_TIMEOUT: float = float(os.getenv("OLLAMA_TIMEOUT_SECONDS", "30.0"))
    
    # Sandbox (Docker)
    DOCKER_IMAGE: str = os.getenv("DOCKER_IMAGE", "auditforge-probe:latest")
    DOCKER_TIMEOUT: float = float(os.getenv("DOCKER_TIMEOUT_SECONDS", "15.0"))
    DOCKER_MEMORY_LIMIT: str = os.getenv("DOCKER_MEMORY_LIMIT", "256m")
    DOCKER_CPU_QUOTA: int = int(os.getenv("DOCKER_CPU_QUOTA", "50000"))
    DOCKER_NETWORK_MODE: str = os.getenv("DOCKER_NETWORK_MODE", "none")
    
    # API & Dashboard
    API_HOST: str = os.getenv("API_HOST", "127.0.0.1")
    API_PORT: int = int(os.getenv("API_PORT", "8000"))
    DASHBOARD_PORT: int = int(os.getenv("DASHBOARD_PORT", "5173"))
    
    # Logging
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")

config = Config()
