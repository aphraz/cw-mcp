#!/bin/bash
# Production startup script for Cloudways MCP Server

# Exit on error
set -e

# Load environment variables if .env exists
if [ -f .env ]; then
    export $(cat .env | grep -v '^#' | xargs)
fi

# Check required environment variables
if [ -z "$ENCRYPTION_KEY" ]; then
    echo "Error: ENCRYPTION_KEY environment variable is required"
    exit 1
fi

# Set production defaults
export WORKERS=${WORKERS:-4}
export REDIS_URL=${REDIS_URL:-"redis://localhost:6379/0"}
export REDIS_POOL_SIZE=${REDIS_POOL_SIZE:-500}
export HTTP_POOL_SIZE=${HTTP_POOL_SIZE:-500}
export LOG_LEVEL=${LOG_LEVEL:-"INFO"}

echo "Starting Cloudways MCP Server in production mode"
echo "Workers: $WORKERS"
echo "Redis: $REDIS_URL"
echo "Log Level: $LOG_LEVEL"

# Use gunicorn for production deployment
# Falls back to uvicorn if gunicorn is not installed
if command -v gunicorn &> /dev/null; then
    echo "Using Gunicorn (recommended for production)"
    exec gunicorn main:app -c gunicorn_config.py
else
    echo "Gunicorn not found, using Uvicorn"
    echo "For better performance, install gunicorn: pip install gunicorn"
    exec python main.py
fi
