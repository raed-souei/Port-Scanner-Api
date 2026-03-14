"""
Configuration management for the Port Scanner API.
"""

import os
from typing import List, Optional
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""
    
    # Application
    APP_NAME: str = "Port Scanner API"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    
    # Server
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    
    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./portscanner.db"
    
    # Security - Allowed networks for scanning (CIDR notation)
    # Empty list means no restrictions (not recommended for production)
    ALLOWED_NETWORKS: List[str] = []
    
    # Scan defaults
    DEFAULT_TIMEOUT: float = 2.0
    DEFAULT_MAX_CONCURRENT: int = 100
    DEFAULT_RATE_LIMIT: Optional[int] = None
    
    # CORS
    CORS_ORIGINS: List[str] = ["*"]
    
    # Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    
    class Config:
        env_file = ".env"
        case_sensitive = True
        
        @classmethod
        def parse_env_var(cls, field_name: str, raw_val: str) -> any:
            """Parse environment variables for list types."""
            if field_name in ["ALLOWED_NETWORKS", "CORS_ORIGINS"]:                
                return [item.strip() for item in raw_val.split(",") if item.strip()]
            return cls.json_loads(raw_val)


# Global settings instance
settings = Settings()


def get_settings() -> Settings:
    """Get application settings."""
    return settings


def configure_logging():
    """Configure application logging."""
    import logging
    
    logging.basicConfig(
        level=getattr(logging, settings.LOG_LEVEL.upper()),
        format=settings.LOG_FORMAT
    )
    
    # Reduce noise from some libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
