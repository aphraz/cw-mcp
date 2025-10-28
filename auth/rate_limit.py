#!/usr/bin/env python3
"""
Rate limiting for Cloudways MCP Server
"""

import json
import time
from typing import Optional, Dict, Any
import redis.asyncio as redis
import structlog

from config import RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW

logger = structlog.get_logger(__name__)

async def check_rate_limit(customer_id: str, endpoint: str, 
                         redis_client: Optional[redis.Redis] = None) -> bool:
    """Check if customer has exceeded rate limit for endpoint"""
    if not redis_client:
        return True
    
    try:
        # Check BOTH endpoint-specific AND global customer limits
        endpoint_key = f"rate_limit:{customer_id}:{endpoint}"
        global_key = f"rate_limit:global:{customer_id}"
        
        now = time.time()
        
        # Check endpoint-specific limit
        endpoint_allowed = await _check_bucket(endpoint_key, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW, now, redis_client)
        if not endpoint_allowed:
            logger.warning("Endpoint rate limit exceeded", customer_id=customer_id, endpoint=endpoint)
            return False
        
        # Check global limit (e.g., 200 requests/min across all endpoints)
        GLOBAL_LIMIT = 200
        global_allowed = await _check_bucket(global_key, GLOBAL_LIMIT, RATE_LIMIT_WINDOW, now, redis_client)
        if not global_allowed:
            logger.warning("Global rate limit exceeded", customer_id=customer_id)
            return False
            
        return True
            
    except Exception as e:
        logger.error("Rate limit check failed", error=str(e))
        return True

async def _check_bucket(key: str, max_tokens: int, window: int, now: float, redis_client: redis.Redis) -> bool:
    """Check if a token bucket allows a request"""
    bucket_data = await redis_client.get(key)
    if bucket_data:
        bucket = json.loads(bucket_data)
        tokens = bucket["tokens"]
        last_refill = bucket["last_refill"]
    else:
        tokens = max_tokens
        last_refill = now
    
    # Token bucket refill
    time_passed = now - last_refill
    tokens_to_add = time_passed * (max_tokens / window)
    tokens = min(max_tokens, tokens + tokens_to_add)
    
    if tokens >= 1:
        tokens -= 1
        await redis_client.setex(key, window * 2, json.dumps({
            "tokens": tokens,
            "last_refill": now
        }))
        return True
    else:
        # Log rate limit event
        try:
            from ..utils.logging import log_rate_limit_event
            # Extract customer_id from key for logging
            if "global" in key:
                customer_id = key.split(":")[-1] if ":" in key else "unknown"
                endpoint = "global"
            else:
                parts = key.split(":")
                customer_id = parts[1] if len(parts) > 1 else "unknown"
                endpoint = parts[2] if len(parts) > 2 else "unknown"
            log_rate_limit_event(customer_id, endpoint, "exceeded", int(tokens))
        except:
            pass
        return False

async def get_rate_limit_status(customer_id: str, 
                              redis_client: Optional[redis.Redis] = None) -> Dict[str, Any]:
    """Get current rate limit status for customer"""
    if not redis_client:
        return {"status": "error", "message": "Rate limiting not available"}
    
    try:
        keys = await redis_client.keys(f"rate_limit:{customer_id}:*")
        stats = {}
        
        for key in keys:
            endpoint = key.split(":")[-1]
            bucket_data = await redis_client.get(key)
            if bucket_data:
                bucket = json.loads(bucket_data)
                stats[endpoint] = {
                    "tokens_remaining": int(bucket["tokens"]),
                    "max_tokens": RATE_LIMIT_REQUESTS
                }
        
        return {
            "customer_id": customer_id,
            "rate_limits": stats,
            "requests_per_minute": RATE_LIMIT_REQUESTS
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}