#!/usr/bin/env python3
"""
Enhanced logging utilities for Cloudways MCP Server
"""

import time
import uuid
from typing import Dict, Any, Optional, Callable
from functools import wraps
import structlog
from fastmcp import Context

from config import *

logger = structlog.get_logger(__name__)

# Request tracing context
_request_context = {}

def generate_request_id() -> str:
    """Generate unique request ID for tracing"""
    return str(uuid.uuid4())[:8]

def set_request_context(request_id: str, customer_id: Optional[str] = None, 
                       endpoint: Optional[str] = None):
    """Set request context for logging"""
    _request_context['request_id'] = request_id
    _request_context['customer_id'] = customer_id
    _request_context['endpoint'] = endpoint
    _request_context['start_time'] = time.time()

def get_request_context() -> Dict[str, Any]:
    """Get current request context"""
    return _request_context.copy()

def clear_request_context():
    """Clear request context"""
    _request_context.clear()

def get_logger_with_context(name: str):
    """Get logger with request context automatically included"""
    base_logger = structlog.get_logger(name)
    context = get_request_context()
    return base_logger.bind(**context)

def log_tool_execution(tool_name: str):
    """Decorator to log tool execution with timing and context"""
    def decorator(func: Callable):
        @wraps(func)
        async def wrapper(ctx: Context, *args, **kwargs):
            request_id = generate_request_id()
            start_time = time.time()
            
            # Get customer info for context (basic version)
            customer_id = "unknown"
            try:
                from auth.customer import get_customer_from_headers
                customer = await get_customer_from_headers(ctx)
                if customer:
                    customer_id = customer.customer_id
            except:
                pass
            
            # Set up logging context
            set_request_context(request_id, customer_id, tool_name)
            tool_logger = get_logger_with_context(f"tools.{tool_name}")
            
            # Log tool start
            tool_logger.info("Tool execution started", 
                           tool=tool_name,
                           args=str(args)[:200],  # Truncate long args
                           kwargs=str(kwargs)[:200])
            
            try:
                # Execute tool
                result = await func(ctx, *args, **kwargs)
                
                # Calculate execution time
                execution_time = time.time() - start_time
                
                # Log success
                tool_logger.info("Tool execution completed",
                               tool=tool_name,
                               execution_time_ms=round(execution_time * 1000, 2),
                               result_status=result.get('status', 'unknown') if isinstance(result, dict) else 'success')
                
                return result
                
            except Exception as e:
                # Calculate execution time
                execution_time = time.time() - start_time
                
                # Log error with full context
                tool_logger.error("Tool execution failed",
                                tool=tool_name,
                                execution_time_ms=round(execution_time * 1000, 2),
                                error_type=type(e).__name__,
                                error_message=str(e),
                                args=str(args)[:200],
                                kwargs=str(kwargs)[:200])
                
                # Re-raise the exception
                raise
                
            finally:
                clear_request_context()
        
        return wrapper
    return decorator

def log_security_event(event_type: str, customer_id: str, details: Dict[str, Any]):
    """Log security-related events for audit trail"""
    security_logger = structlog.get_logger("security")
    security_logger.warning("Security event",
                          event_type=event_type,
                          customer_id=customer_id,
                          **details)

def log_performance_metric(metric_name: str, value: float, unit: str = "ms", 
                         additional_context: Optional[Dict[str, Any]] = None):
    """Log performance metrics"""
    perf_logger = structlog.get_logger("performance")
    context = additional_context or {}
    perf_logger.info("Performance metric",
                    metric=metric_name,
                    value=value,
                    unit=unit,
                    **context)

def log_api_call(endpoint: str, method: str, status_code: int, 
                response_time_ms: float, customer_id: str):
    """Log external API calls to Cloudways"""
    api_logger = structlog.get_logger("api.cloudways")
    api_logger.info("External API call",
                   endpoint=endpoint,
                   method=method,
                   status_code=status_code,
                   response_time_ms=response_time_ms,
                   customer_id=customer_id)

def log_rate_limit_event(customer_id: str, endpoint: str, action: str, 
                        tokens_remaining: int):
    """Log rate limiting events"""
    rate_limit_logger = structlog.get_logger("rate_limit")
    rate_limit_logger.info("Rate limit event",
                          customer_id=customer_id,
                          endpoint=endpoint,
                          action=action,
                          tokens_remaining=tokens_remaining)

def log_authentication_event(event_type: str, customer_id: str, success: bool, 
                            details: Optional[Dict[str, Any]] = None):
    """Log authentication events"""
    auth_logger = structlog.get_logger("auth")
    auth_logger.info("Authentication event",
                    event_type=event_type,
                    customer_id=customer_id,
                    success=success,
                    **(details or {}))

class LoggingMiddleware:
    """Middleware to add request logging to all MCP requests"""
    
    def __init__(self):
        self.logger = structlog.get_logger("middleware")
    
    async def __call__(self, request, call_next):
        request_id = generate_request_id()
        start_time = time.time()
        
        self.logger.info("Request started",
                        request_id=request_id,
                        method=getattr(request, 'method', 'UNKNOWN'),
                        path=getattr(request, 'url', {}).get('path', 'unknown'))
        
        try:
            response = await call_next(request)
            duration = time.time() - start_time
            
            self.logger.info("Request completed",
                           request_id=request_id,
                           duration_ms=round(duration * 1000, 2),
                           status=getattr(response, 'status_code', 'unknown'))
            
            return response
            
        except Exception as e:
            duration = time.time() - start_time
            
            self.logger.error("Request failed",
                            request_id=request_id,
                            duration_ms=round(duration * 1000, 2),
                            error_type=type(e).__name__,
                            error_message=str(e))
            raise