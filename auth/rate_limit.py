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
        key = f"rate_limit:{customer_id}:{endpoint}"
        now = time.time()
        
        bucket_data = await redis_client.get(key)
        if bucket_data:
            bucket = json.loads(bucket_data)
            tokens = bucket["tokens"]
            last_refill = bucket["last_refill"]
        else:
            tokens = RATE_LIMIT_REQUESTS
            last_refill = now
        
        # Token bucket refill
        time_passed = now - last_refill
        tokens_to_add = time_passed * (RATE_LIMIT_REQUESTS / RATE_LIMIT_WINDOW)
        tokens = min(RATE_LIMIT_REQUESTS, tokens + tokens_to_add)
        
        if tokens >= 1:
            tokens -= 1
            await redis_client.setex(key, RATE_LIMIT_WINDOW * 2, json.dumps({
                "tokens": tokens,
                "last_refill": now
            }))
            return True
        else:
            logger.warning("Rate limit exceeded", customer_id=customer_id, endpoint=endpoint)
            return False
            
    except Exception as e:
        logger.error("Rate limit check failed", error=str(e))
        return True

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