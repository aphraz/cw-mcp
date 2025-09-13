#!/usr/bin/env python3
"""
Test script for MCP server initialization
"""

import asyncio
import json
import sys
from pathlib import Path

# Add the project directory to Python path
project_dir = Path(__file__).parent
sys.path.insert(0, str(project_dir))

async def test_basic_initialization():
    """Test basic server initialization"""
    print("Testing basic MCP server initialization...")
    
    try:
        from server import mcp
        print("✓ MCP server instance created successfully")
        
        # Try to get server info
        if hasattr(mcp, 'server_info'):
            info = await mcp.server_info()
            print(f"✓ Server info: {json.dumps(info, indent=2)}")
        
        # Check if tools are registered
        from tools import basic, servers, apps, security
        print("✓ All tool modules imported successfully")
        
        # Check tool registration
        tools_count = len(mcp._tools) if hasattr(mcp, '_tools') else 0
        print(f"✓ {tools_count} tools registered")
        
        return True
        
    except Exception as e:
        print(f"✗ Error during initialization: {e}")
        import traceback
        traceback.print_exc()
        return False

async def test_dependencies():
    """Test dependency initialization"""
    print("\nTesting dependency initialization...")
    
    try:
        import httpx
        import redis.asyncio as redis
        from config import REDIS_URL, HTTP_POOL_SIZE
        
        # Test Redis connection
        try:
            redis_client = redis.from_url(REDIS_URL, decode_responses=True)
            await redis_client.ping()
            print(f"✓ Redis connection successful: {REDIS_URL}")
            await redis_client.close()
        except Exception as e:
            print(f"⚠ Redis connection failed: {e}")
            print("  (This is OK if Redis is not required for basic operation)")
        
        # Test HTTP client
        async with httpx.AsyncClient() as client:
            print("✓ HTTP client initialized successfully")
        
        return True
        
    except Exception as e:
        print(f"✗ Error testing dependencies: {e}")
        return False

async def main():
    """Run all tests"""
    print("=" * 50)
    print("MCP Server Initialization Test")
    print("=" * 50)
    
    # Set minimal environment if not set
    import os
    if not os.getenv("ENCRYPTION_KEY"):
        os.environ["ENCRYPTION_KEY"] = "test-key-for-testing-only-replace-in-production="
        print("⚠ Using test encryption key (not for production)")
    
    results = []
    results.append(await test_basic_initialization())
    results.append(await test_dependencies())
    
    print("\n" + "=" * 50)
    if all(results):
        print("✓ All tests passed!")
    else:
        print("⚠ Some tests failed. Check the output above.")
    print("=" * 50)

if __name__ == "__main__":
    asyncio.run(main())
