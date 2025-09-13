#!/usr/bin/env python3
"""
Production deployment script with gunicorn for high performance
"""

import os
import multiprocessing

# Server configuration
bind = "0.0.0.0:7000"
workers = int(os.getenv("WORKERS", multiprocessing.cpu_count() * 2 + 1))
worker_class = "uvicorn.workers.UvicornWorker"
worker_connections = 1000
max_requests = 10000
max_requests_jitter = 1000
timeout = 30
keepalive = 5

# Logging
accesslog = "-" if os.getenv("ACCESS_LOG", "false").lower() == "true" else None
errorlog = "-"
loglevel = os.getenv("LOG_LEVEL", "info").lower()

# Performance
preload_app = True  # Load app before forking workers
daemon = False

# Process naming
proc_name = "cloudways-mcp"

def when_ready(server):
    """Called just after the server is started"""
    print(f"🚀 Cloudways MCP Server ready with {workers} workers")
    print(f"📍 Listening on http://{bind}")

def worker_int(worker):
    """Called just after a worker exited on SIGINT or SIGQUIT"""
    print(f"Worker {worker.pid} interrupted")

def pre_fork(server, worker):
    """Called just before a worker is forked"""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked"""
    # Each worker gets its own Redis and HTTP connection pools
    print(f"Worker {worker.pid} spawned")

def worker_exit(server, worker):
    """Called just after a worker has been exited"""
    print(f"Worker {worker.pid} exited")
