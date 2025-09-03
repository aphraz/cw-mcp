#!/usr/bin/env python3
"""
Customer management for Cloudways MCP Server
"""

import json
import hashlib
from datetime import datetime
from typing import Optional
import redis.asyncio as redis
from fastmcp import Context
from fastmcp.server.dependencies import get_http_request
import structlog

from ..config import fernet

logger = structlog.get_logger(__name__)

class Customer:
    def __init__(self, customer_id: str, email: str, cloudways_email: str, 
                 cloudways_api_key: str, created_at: datetime):
        self.customer_id = customer_id
        self.email = email
        self.cloudways_email = cloudways_email
        self.cloudways_api_key = cloudways_api_key
        self.created_at = created_at
        self.last_seen = datetime.utcnow()

async def get_customer_from_headers(ctx: Context, redis_client: Optional[redis.Redis] = None) -> Optional[Customer]:
    """Extract customer information from request headers"""
    try:
        http_request = get_http_request()
        email = http_request.headers.get("x-cloudways-email")
        api_key = http_request.headers.get("x-cloudways-api-key")

        if not email or not api_key:
            raise ValueError("Missing authentication headers")
        
        customer_hash = hashlib.sha256(f"{email}:{api_key}".encode()).hexdigest()
        customer_id = f"customer_{customer_hash[:16]}"
        
        # Check cache
        if redis_client:
            try:
                cached_data = await redis_client.get(f"customer:{customer_id}")
                if cached_data:
                    data = json.loads(cached_data)
                    decrypted_key = fernet.decrypt(data["encrypted_api_key"].encode()).decode()
                    
                    customer = Customer(
                        customer_id=customer_id,
                        email=data["email"],
                        cloudways_email=data["cloudways_email"],
                        cloudways_api_key=decrypted_key,
                        created_at=datetime.fromisoformat(data["created_at"])
                    )
                    logger.debug("Customer loaded from cache", customer_id=customer_id)
                    return customer
            except Exception as e:
                logger.warning("Failed to load customer from cache", error=str(e))
        
        # Create new customer
        customer = Customer(customer_id, email, email, api_key, datetime.utcnow())
        await _cache_customer(customer, redis_client)
        logger.info("New customer created", customer_id=customer_id)
        
        # Log security event
        try:
            from ..utils.logging import log_authentication_event
            log_authentication_event("new_customer", customer_id, True, {"email": email})
        except:
            pass  # Don't fail customer creation if logging fails
        
        return customer
        
    except Exception as e:
        logger.error("Failed to get customer from headers", error=str(e))
        return None

async def _cache_customer(customer: Customer, redis_client: Optional[redis.Redis] = None):
    """Cache customer data in Redis"""
    if not redis_client:
        return
    
    try:
        encrypted_api_key = fernet.encrypt(customer.cloudways_api_key.encode()).decode()
        customer_data = {
            "customer_id": customer.customer_id,
            "email": customer.email,
            "cloudways_email": customer.cloudways_email,
            "encrypted_api_key": encrypted_api_key,
            "created_at": customer.created_at.isoformat(),
            "last_seen": customer.last_seen.isoformat()
        }
        await redis_client.setex(f"customer:{customer.customer_id}", 3600, json.dumps(customer_data))
    except Exception as e:
        logger.error("Failed to cache customer", error=str(e))