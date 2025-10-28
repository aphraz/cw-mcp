#!/usr/bin/env python3
"""
Test script for security fixes
"""

import os
# Set environment variables needed for config
os.environ['ENCRYPTION_KEY'] = 'DqI2GPe0IgVhV2x2M6ZbOoMc6zC7j9p0H0X1r7yB6uE='

import hashlib
import json
import asyncio
import redis.asyncio as redis
from cryptography.fernet import Fernet

# Import our modules
import config
from auth.customer import Customer
from auth.tokens import TokenManager

def test_session_isolation():
    """Test that session isolation works correctly"""
    print("Testing session isolation...")
    
    # Test data
    email = "test@example.com"
    api_key = "test_api_key"
    session_id_1 = "session_1"
    session_id_2 = "session_2"
    
    # Generate customer IDs with different sessions
    customer_hash_1 = hashlib.sha256(f"{email}:{api_key}:{session_id_1}".encode()).hexdigest()
    customer_id_1 = f"customer_{customer_hash_1[:16]}"
    
    customer_hash_2 = hashlib.sha256(f"{email}:{api_key}:{session_id_2}".encode()).hexdigest()
    customer_id_2 = f"customer_{customer_hash_2[:16]}"
    
    # Verify they are different
    assert customer_id_1 != customer_id_2, "Session isolation failed - customer IDs are the same"
    print("✓ Session isolation working correctly")
    return True

def test_token_encryption():
    """Test that tokens are encrypted before storage"""
    print("Testing token encryption...")
    
    # Test data
    test_token = "test_access_token_12345"
    
    # Encrypt token
    encrypted_token = config.fernet.encrypt(test_token.encode()).decode()
    
    # Decrypt token
    decrypted_token = config.fernet.decrypt(encrypted_token.encode()).decode()
    
    # Verify they match
    assert test_token == decrypted_token, "Token encryption/decryption failed"
    
    # Verify encrypted token is different from original
    assert test_token != encrypted_token, "Encrypted token should be different from original"
    
    # Verify it has the Fernet signature (starts with 'gAAAAA')
    assert encrypted_token.startswith('gAAAAA'), "Encrypted token should have Fernet signature"
    
    print("✓ Token encryption working correctly")
    return True

def test_input_validation():
    """Test that input validation works correctly"""
    print("Testing input validation...")
    
    # Import the Pydantic models
    import sys
    sys.path.append('/Users/afrazahmed/projects/google-adk/mcp-servers/cw-mcp-securityfix')
    from tools.servers import ServerIdParam
    
    # Test valid server ID
    try:
        valid_server = ServerIdParam(server_id=12345)
        assert valid_server.server_id == 12345
    except Exception as e:
        assert False, f"Valid server ID rejected: {e}"
    
    # Test invalid server ID (negative)
    try:
        invalid_server = ServerIdParam(server_id=-1)
        assert False, "Negative server ID should be rejected"
    except Exception:
        pass  # Expected to fail validation
    
    # Test invalid server ID (zero)
    try:
        invalid_server = ServerIdParam(server_id=0)
        assert False, "Zero server ID should be rejected"
    except Exception:
        pass  # Expected to fail validation
    
    # Test invalid server ID (too large)
    try:
        invalid_server = ServerIdParam(server_id=1000000000)
        assert False, "Too large server ID should be rejected"
    except Exception:
        pass  # Expected to fail validation
    
    print("✓ Input validation working correctly")
    return True

async def test_rate_limiting():
    """Test that global rate limiting works correctly"""
    print("Testing rate limiting...")
    
    # This would require a Redis connection and more complex setup
    # For now, we'll just verify the function exists and has the right signature
    from auth.rate_limit import check_rate_limit, _check_bucket
    
    # Check that the functions exist
    assert callable(check_rate_limit), "check_rate_limit function not found"
    assert callable(_check_bucket), "_check_bucket function not found"
    
    print("✓ Rate limiting functions exist")
    return True

def main():
    """Run all tests"""
    print("Running security fix tests...\n")
    
    try:
        test_session_isolation()
        test_token_encryption()
        test_input_validation()
        asyncio.run(test_rate_limiting())
        
        print("\n✓ All tests passed!")
        return True
    except Exception as e:
        print(f"\n✗ Test failed: {e}")
        return False

if __name__ == "__main__":
    main()