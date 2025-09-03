#!/usr/bin/env python3
"""
Token management for Cloudways MCP Server
"""

import asyncio
import json
import time
from typing import Dict, Any, Optional
import httpx
import redis.asyncio as redis
import structlog

from config import TOKEN_URL
from auth.customer import Customer

logger = structlog.get_logger(__name__)

class TokenManager:
    """Enhanced token manager with proactive renewal and race condition protection"""
    
    def __init__(self, redis_client: redis.Redis, http_client: httpx.AsyncClient):
        self.redis_client = redis_client
        self.http_client = http_client
        self.refresh_threshold = 300  # Refresh when 5 minutes remaining
        self.min_refresh_threshold = 60  # Minimum 1 minute before expiry
        
    async def get_token(self, customer: Customer) -> str:
        """Get token with proactive renewal and race condition protection"""
        token_key = f"token:{customer.customer_id}"
        meta_key = f"token_meta:{customer.customer_id}"
        lock_key = f"token_lock:{customer.customer_id}"
        
        try:
            # Check if we have a valid cached token
            cached_token = await self.redis_client.get(token_key)
            token_meta = await self.redis_client.get(meta_key)
            
            if cached_token and token_meta:
                meta = json.loads(token_meta)
                expires_at = meta.get("expires_at", 0)
                current_time = time.time()
                time_until_expiry = expires_at - current_time
                
                if time_until_expiry > self.refresh_threshold:
                    logger.debug("Using fresh cached token", customer_id=customer.customer_id)
                    return cached_token
                    
                elif time_until_expiry > self.min_refresh_threshold:
                    # Background refresh
                    asyncio.create_task(self._refresh_token_background(customer))
                    logger.debug("Using cached token with background refresh", customer_id=customer.customer_id)
                    return cached_token
                
                logger.info("Token near expiry, refreshing immediately", customer_id=customer.customer_id)
            
            # Need immediate refresh with lock protection
            lock_acquired = await self._acquire_refresh_lock(lock_key)
            
            if not lock_acquired:
                await asyncio.sleep(0.1)
                refreshed_token = await self.redis_client.get(token_key)
                if refreshed_token:
                    logger.debug("Using token refreshed by another process", customer_id=customer.customer_id)
                    return refreshed_token
            
            try:
                token_data = await self._fetch_new_token(customer)
                await self._cache_token_with_metadata(customer, token_data)
                logger.info("Successfully refreshed token", customer_id=customer.customer_id)
                return token_data["access_token"]
            finally:
                await self._release_refresh_lock(lock_key)
                
        except Exception as e:
            logger.error("Token management failed", customer_id=customer.customer_id, error=str(e))
            raise RuntimeError(f"Authentication failed: {str(e)}")
    
    async def _acquire_refresh_lock(self, lock_key: str) -> bool:
        try:
            result = await self.redis_client.set(lock_key, "locked", ex=30, nx=True)
            return result is True
        except Exception:
            return False
    
    async def _release_refresh_lock(self, lock_key: str):
        try:
            await self.redis_client.delete(lock_key)
        except Exception as e:
            logger.warning("Failed to release refresh lock", error=str(e))
    
    async def _refresh_token_background(self, customer: Customer):
        try:
            lock_key = f"token_lock:{customer.customer_id}"
            if await self._acquire_refresh_lock(lock_key):
                try:
                    token_data = await self._fetch_new_token(customer)
                    await self._cache_token_with_metadata(customer, token_data)
                    logger.info("Background token refresh successful", customer_id=customer.customer_id)
                finally:
                    await self._release_refresh_lock(lock_key)
        except Exception as e:
            logger.warning("Background token refresh failed", customer_id=customer.customer_id, error=str(e))
    
    async def _fetch_new_token(self, customer: Customer) -> Dict[str, Any]:
        resp = await self.http_client.post(TOKEN_URL, data={
            "email": customer.cloudways_email,
            "api_key": customer.cloudways_api_key
        }, timeout=30.0)
        
        resp.raise_for_status()
        data = resp.json()
        
        if not data.get("access_token"):
            raise ValueError("No access_token returned from Cloudways API")
        
        return data
    
    async def _cache_token_with_metadata(self, customer: Customer, token_data: Dict[str, Any]):
        token = token_data.get("access_token")
        expires_in = token_data.get("expires_in", 3600)
        current_time = time.time()
        
        # Store token
        token_ttl = max(expires_in - self.min_refresh_threshold, 300)
        await self.redis_client.setex(f"token:{customer.customer_id}", token_ttl, token)
        
        # Store metadata
        metadata = {
            "expires_at": current_time + expires_in,
            "expires_in": expires_in,
            "created_at": current_time,
            "refresh_threshold": self.refresh_threshold
        }
        await self.redis_client.setex(f"token_meta:{customer.customer_id}", expires_in, json.dumps(metadata))

async def get_cloudways_token(customer: Customer, token_manager: Optional[TokenManager] = None, 
                            redis_client: Optional[redis.Redis] = None, 
                            http_client: Optional[httpx.AsyncClient] = None) -> str:
    """Get Cloudways API token for customer"""
    
    if token_manager:
        return await token_manager.get_token(customer)
    
    # Fallback method
    if redis_client:
        cached_token = await redis_client.get(f"token:{customer.customer_id}")
        if cached_token:
            return cached_token
    
    if not http_client:
        raise ValueError("HTTP client required for token fetch")
    
    resp = await http_client.post(TOKEN_URL, data={
        "email": customer.cloudways_email,
        "api_key": customer.cloudways_api_key
    })
    resp.raise_for_status()
    data = resp.json()
    token = data.get("access_token")
    
    if not token:
        raise ValueError("No access_token returned")
    
    if redis_client:
        await redis_client.setex(f"token:{customer.customer_id}", 3540, token)
    
    return token