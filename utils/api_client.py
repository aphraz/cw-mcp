#!/usr/bin/env python3
"""
API client utilities for Cloudways MCP Server with OAuth browser authentication
"""

from typing import Optional, Dict, Any
import httpx
import redis.asyncio as redis
from fastmcp import Context
import structlog

from config import CLOUDWAYS_API_BASE
from auth.customer import get_customer_from_session
from auth.tokens import get_cloudways_token
from auth.rate_limit import check_rate_limit
from auth.oauth_error import OAuthErrorResponse

logger = structlog.get_logger(__name__)

async def make_api_request(ctx: Context, endpoint: str, params: Optional[Dict[str, Any]] = None,
                         redis_client: Optional[redis.Redis] = None,
                         http_client: Optional[httpx.AsyncClient] = None,
                         token_manager = None,
                         session_manager = None,
                         browser_authenticator = None) -> Dict[str, Any]:
    """Make authenticated API request to Cloudways with OAuth browser authentication"""
    import time
    start_time = time.time()

    try:
        customer = await get_customer_from_session(ctx, session_manager, browser_authenticator, redis_client)
        if not customer:
            logger.warning("API request failed - no authentication", endpoint=endpoint)
            return {"status": "error", "message": "Authentication required"}
        
        # Log rate limit check
        rate_limit_ok = await check_rate_limit(customer.customer_id, endpoint, redis_client)
        if not rate_limit_ok:
            logger.warning("API request blocked by rate limit", 
                         customer_id=customer.customer_id,
                         customer_email=customer.email,
                         endpoint=endpoint)
            return {"status": "error", "message": "Rate limit exceeded", "retry_after": 60}
        
        token = await get_cloudways_token(customer, token_manager, redis_client, http_client)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        
        if not http_client:
            raise ValueError("HTTP client required")
        
        # Make request with timing
        request_start = time.time()
        resp = await http_client.get(f"{CLOUDWAYS_API_BASE}{endpoint}", headers=headers, params=params)
        request_time = time.time() - request_start
        
        resp.raise_for_status()
        result = resp.json()
        
        # Log successful request with metrics
        total_time = time.time() - start_time
        logger.info("API request successful", 
                   customer_id=customer.customer_id,
                   customer_email=customer.email,
                   endpoint=endpoint,
                   status_code=resp.status_code,
                   request_time_ms=round(request_time * 1000, 2),
                   total_time_ms=round(total_time * 1000, 2),
                   response_size=len(str(result)))
        
        # Log to dedicated API logger
        from utils.logging import log_api_call
        log_api_call(endpoint, "GET", resp.status_code, 
                    round(request_time * 1000, 2), customer.customer_id)
        
        return result
        
    except OAuthErrorResponse as e:
        # Return OAuth error dictionary for browser authentication
        logger.info("API request requires authentication", endpoint=endpoint, error=e.oauth_error.error)
        return e.oauth_error.to_dict()
    except httpx.HTTPStatusError as e:
        request_time = time.time() - start_time
        logger.error("API request failed - HTTP error",
                    endpoint=endpoint,
                    status_code=e.response.status_code,
                    request_time_ms=round(request_time * 1000, 2),
                    response_text=e.response.text[:200])
        return {"status": "error", "message": f"HTTP error: {e.response.status_code}"}
    except Exception as e:
        request_time = time.time() - start_time
        logger.error("API request failed - exception",
                    endpoint=endpoint,
                    error_type=type(e).__name__,
                    error=str(e),
                    request_time_ms=round(request_time * 1000, 2))
        return {"status": "error", "message": f"Request failed: {str(e)}"}

async def make_api_request_post(ctx: Context, endpoint: str, data: Optional[Dict[str, Any]] = None,
                              redis_client: Optional[redis.Redis] = None,
                              http_client: Optional[httpx.AsyncClient] = None,
                              token_manager = None,
                              session_manager = None,
                              browser_authenticator = None) -> Dict[str, Any]:
    """Make authenticated POST API request to Cloudways with OAuth browser authentication"""
    try:
        customer = await get_customer_from_session(ctx, session_manager, browser_authenticator, redis_client)
        if not customer:
            return {"status": "error", "message": "Authentication required"}
        
        if not await check_rate_limit(customer.customer_id, endpoint, redis_client):
            return {"status": "error", "message": "Rate limit exceeded", "retry_after": 60}
        
        token = await get_cloudways_token(customer, token_manager, redis_client, http_client)
        headers = {"Authorization": f"Bearer {token}", "Accept": "application/json"}
        
        if not http_client:
            raise ValueError("HTTP client required")
        
        resp = await http_client.post(f"{CLOUDWAYS_API_BASE}{endpoint}", headers=headers, data=data or {})
        resp.raise_for_status()
        result = resp.json()
        
        logger.info("API POST request successful", customer_id=customer.customer_id, customer_email=customer.email, endpoint=endpoint)
        return result
        
    except OAuthErrorResponse as e:
        # Return OAuth error dictionary for browser authentication
        logger.info("API POST request requires authentication", endpoint=endpoint, error=e.oauth_error.error)
        return e.oauth_error.to_dict()
    except httpx.HTTPStatusError as e:
        logger.error("API POST request failed", endpoint=endpoint, status_code=e.response.status_code)
        return {"status": "error", "message": f"HTTP error: {e.response.status_code}"}
    except Exception as e:
        logger.error("API POST request failed", endpoint=endpoint, error=str(e))
        return {"status": "error", "message": f"Request failed: {str(e)}"}