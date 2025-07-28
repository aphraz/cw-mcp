#!/usr/bin/env python3
"""
Test script to demonstrate logging functionality
"""

import os
import time

# Set environment variables for testing
os.environ["LOG_LEVEL"] = "DEBUG"
os.environ["LOG_TO_FILE"] = "true"
os.environ["LOG_FILE_PATH"] = "logs/test-cloudways-mcp.log"
os.environ["LOG_FORMAT"] = "console"

# Import after setting environment variables
import structlog
import logging
import logging.handlers

# Logging Configuration (must be defined before setup_logging)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO").upper()
LOG_TO_FILE = os.getenv("LOG_TO_FILE", "true").lower() == "true"
LOG_FILE_PATH = os.getenv("LOG_FILE_PATH", "logs/test-cloudways-mcp.log")
LOG_ROTATION_SIZE = os.getenv("LOG_ROTATION_SIZE", "1MB")  # Small for testing
LOG_RETENTION_COUNT = int(os.getenv("LOG_RETENTION_COUNT", "3"))
LOG_FORMAT = os.getenv("LOG_FORMAT", "console")

def setup_logging():
    """Configure logging with file rotation and multiple output formats"""
    
    # Create logs directory if it doesn't exist
    if LOG_TO_FILE:
        log_dir = os.path.dirname(LOG_FILE_PATH)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir, exist_ok=True)
    
    # Configure standard library logging
    stdlib_logger = logging.getLogger()
    stdlib_logger.setLevel(getattr(logging, LOG_LEVEL))
    
    # Clear any existing handlers
    stdlib_logger.handlers.clear()
    
    # Choose processors based on format
    if LOG_FORMAT == "json":
        renderer = structlog.processors.JSONRenderer()
    elif LOG_FORMAT == "structured":
        renderer = structlog.dev.ConsoleRenderer(colors=False)
    else:  # console
        renderer = structlog.dev.ConsoleRenderer(colors=True)
    
    # Base processors for all outputs
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
    ]
    
    # Add console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(getattr(logging, LOG_LEVEL))
    stdlib_logger.addHandler(console_handler)
    
    # Add file handler with rotation if enabled
    if LOG_TO_FILE:
        try:
            # Parse size (e.g., "1MB" -> 1 * 1024 * 1024)
            size_str = LOG_ROTATION_SIZE.upper()
            if size_str.endswith('MB'):
                max_bytes = int(size_str[:-2]) * 1024 * 1024
            elif size_str.endswith('KB'):
                max_bytes = int(size_str[:-2]) * 1024
            elif size_str.endswith('GB'):
                max_bytes = int(size_str[:-2]) * 1024 * 1024 * 1024
            else:
                max_bytes = int(size_str)  # Assume bytes
            
            file_handler = logging.handlers.RotatingFileHandler(
                LOG_FILE_PATH,
                maxBytes=max_bytes,
                backupCount=LOG_RETENTION_COUNT,
                encoding='utf-8'
            )
            file_handler.setLevel(getattr(logging, LOG_LEVEL))
            stdlib_logger.addHandler(file_handler)
            
        except Exception as e:
            print(f"Warning: Failed to setup file logging: {e}")
            print(f"Continuing with console logging only")
    
    # Configure structlog
    structlog.configure(
        processors=processors + [renderer],
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        wrapper_class=structlog.stdlib.BoundLogger,
        cache_logger_on_first_use=True,
    )
    
    return structlog.get_logger(__name__)

def test_logging():
    """Test different logging scenarios"""
    
    print("🧪 Testing Cloudways MCP Logging System")
    print("=" * 50)
    
    # Initialize logging
    logger = setup_logging()
    
    print(f"📊 Log Level: {LOG_LEVEL}")
    print(f"📁 Log to File: {LOG_TO_FILE}")
    print(f"📄 Log File: {LOG_FILE_PATH}")
    print(f"🎨 Log Format: {LOG_FORMAT}")
    print("=" * 50)
    
    # Test different log levels
    logger.debug("Debug message: System initialization started", component="startup")
    logger.info("Info message: Redis connected successfully", 
               url="redis://localhost:6379/0", 
               pool_size=200)
    logger.warning("Warning message: Rate limit approaching", 
                  customer_id="customer_abc123", 
                  usage=85)
    logger.error("Error message: API request failed", 
                endpoint="/server", 
                status_code=401,
                error="Authentication failed")
    
    # Test customer activity simulation
    customer_id = "customer_test123"
    logger.info("New customer created", 
               customer_id=customer_id, 
               email="test@example.com")
    
    logger.debug("Using fresh cached token", 
                customer_id=customer_id,
                time_until_expiry=3540.5)
    
    logger.info("API request successful", 
               customer_id=customer_id,
               endpoint="/server",
               status_code=200)
    
    # Test token management
    logger.info("Token near expiry, refreshing immediately", 
               customer_id=customer_id,
               time_until_expiry=45.2)
    
    logger.info("Successfully refreshed token", 
               customer_id=customer_id)
    
    # Test background operations
    logger.debug("Background refresh skipped - another process refreshing", 
                customer_id=customer_id)
    
    logger.info("Background token refresh successful", 
               customer_id=customer_id)
    
    # Test rate limiting
    logger.warning("Rate limit exceeded", 
                  customer_id=customer_id, 
                  endpoint="/server")
    
    # Test system events
    logger.info("HTTP client initialized", 
               max_connections=100,
               keepalive_connections=20)
    
    logger.info("Token manager initialized with proactive renewal")
    
    # Test error scenarios
    logger.error("Failed to get customer from headers", 
                error="Missing x-cloudways-email header")
    
    logger.warning("Background token refresh failed", 
                  customer_id=customer_id, 
                  error="Connection timeout")
    
    print("\n✅ Logging test completed!")
    
    # Check if log file was created
    if LOG_TO_FILE and os.path.exists(LOG_FILE_PATH):
        file_size = os.path.getsize(LOG_FILE_PATH)
        print(f"📄 Log file created: {LOG_FILE_PATH}")
        print(f"📏 File size: {file_size} bytes")
        
        # Show last few lines
        print("\n📋 Last 5 log entries:")
        print("-" * 40)
        try:
            with open(LOG_FILE_PATH, 'r') as f:
                lines = f.readlines()
                for line in lines[-5:]:
                    print(line.strip())
        except Exception as e:
            print(f"Error reading log file: {e}")
    
    print(f"\n🎯 Test completed! Check {LOG_FILE_PATH} for file output.")

if __name__ == "__main__":
    test_logging()
