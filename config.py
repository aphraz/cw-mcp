#!/usr/bin/env python3
"""
Configuration management for Cloudways MCP Server
"""

import os
from cryptography.fernet import Fernet
import structlog

# Cloudways API Configuration
CLOUDWAYS_API_BASE = "https://api.cloudways.com/api/v1"
TOKEN_URL = f"{CLOUDWAYS_API_BASE}/oauth/access_token"

# Environment Configuration
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    raise ValueError("ENCRYPTION_KEY environment variable is required")

REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
REDIS_POOL_SIZE = int(os.getenv("REDIS_POOL_SIZE", "500"))
HTTP_POOL_SIZE = int(os.getenv("HTTP_POOL_SIZE", "500"))
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "90"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))

# Logging Configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_FORMAT = os.getenv("LOG_FORMAT", "console")  # console, json
LOG_FILE = os.getenv("LOG_FILE")  # Optional file output
ENABLE_PERFORMANCE_LOGGING = os.getenv("ENABLE_PERFORMANCE_LOGGING", "true").lower() == "true"
ENABLE_SECURITY_LOGGING = os.getenv("ENABLE_SECURITY_LOGGING", "true").lower() == "true"

# Configure structured logging based on environment
def configure_logging():
    """Configure structlog based on environment variables"""
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.UnicodeDecoder(),
    ]
    
    if LOG_FORMAT == "json":
        processors.append(structlog.processors.JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    structlog.configure(
        processors=processors,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    # Set log level
    import logging
    logging.basicConfig(
        level=getattr(logging, LOG_LEVEL, logging.INFO),
        filename=LOG_FILE if LOG_FILE else None,
        format="%(message)s"
    )

# Initialize encryption
fernet = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)