#!/usr/bin/env python3
"""
Simple test to verify logging works
"""

import os
import sys

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Test basic logging
print("🧪 Testing basic logging functionality...")

try:
    # Set environment variables
    os.environ["LOG_LEVEL"] = "INFO"
    os.environ["LOG_TO_FILE"] = "true"
    os.environ["LOG_FILE_PATH"] = "logs/simple-test.log"
    os.environ["LOG_FORMAT"] = "console"
    
    import logging
    import logging.handlers
    
    # Create logs directory
    os.makedirs("logs", exist_ok=True)
    
    # Setup basic file logging
    logger = logging.getLogger("test")
    logger.setLevel(logging.INFO)
    
    # File handler
    file_handler = logging.handlers.RotatingFileHandler(
        "logs/simple-test.log",
        maxBytes=1024*1024,  # 1MB
        backupCount=3
    )
    file_handler.setLevel(logging.INFO)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    
    # Formatter
    formatter = logging.Formatter(
        '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    # Test logging
    logger.info("✅ Basic logging test successful")
    logger.info("📁 Log file should be created at: logs/simple-test.log")
    logger.warning("⚠️  This is a warning message")
    logger.error("❌ This is an error message")
    
    # Check if file was created
    if os.path.exists("logs/simple-test.log"):
        size = os.path.getsize("logs/simple-test.log")
        print(f"\n✅ Log file created successfully!")
        print(f"📄 File: logs/simple-test.log")
        print(f"📏 Size: {size} bytes")
        
        # Read and display content
        with open("logs/simple-test.log", "r") as f:
            content = f.read()
            print(f"\n📋 File content:")
            print("-" * 40)
            print(content)
    else:
        print("❌ Log file was not created")
        
except Exception as e:
    print(f"❌ Error: {e}")
    import traceback
    traceback.print_exc()

print("\n🎯 Simple logging test completed!")
