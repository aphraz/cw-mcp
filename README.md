# Cloudways MCP Server

A comprehensive Model Context Protocol (MCP) server for managing Cloudways infrastructure. This server provides a secure, modular, and scalable interface to the Cloudways API with **43+ tools** covering all aspects of server and application management.

## 🚀 Features

- **Complete Cloudways API Coverage**: 43+ tools organized into logical categories
- **Modular Architecture**: Clean separation of concerns with dedicated modules for different functionalities
- **Enterprise Security**: Multi-layered authentication, rate limiting, and audit logging
- **High Performance**: Asynchronous design with Redis caching and HTTP connection pooling
- **Production Ready**: Structured logging, error handling, and monitoring capabilities
- **MCP Compatible**: Full Model Context Protocol support for AI assistant integration

## 📊 Tools Overview

### Basic Operations (18 tools)
- **Authentication & Info**: `ping`, `customer_info`, `rate_limit_status`
- **Server Management**: `list_servers`, `get_server_details`
- **Application Management**: `get_app_details`, `get_app_credentials`, `get_app_settings`, `get_app_monitoring_summary`
- **Project Management**: `list_projects`, `list_team_members`, `get_alerts`
- **Infrastructure Discovery**: `get_ssh_keys`, `get_available_providers`, `get_available_regions`, `get_available_server_sizes`, `get_available_apps`, `get_available_packages`

### Server Operations (12 tools)
- **Power Management**: `start_server`, `stop_server`, `restart_server`
- **Backup & Recovery**: `backup_server`, `get_server_settings`
- **Storage Management**: `get_server_disk_usage`, `optimize_server_disk`
- **Service Control**: `get_server_services_status`, `change_service_state`
- **Caching**: `manage_server_varnish`
- **Monitoring**: `get_server_monitoring_detail`, `get_server_analytics`

### Application Management (8 tools)
- **Deployment**: `clone_app`, `backup_app`, `restore_app`, `rollback_app_restore`
- **Performance**: `clear_app_cache`, `get_app_varnish_settings`, `manage_app_varnish`
- **Configuration**: `reset_app_file_permissions`, `enforce_app_https`
- **Domain Management**: `update_app_cname`, `delete_app_cname`
- **Analytics**: `get_app_analytics_traffic`, `get_app_analytics_php`, `get_app_analytics_mysql`

### Security & Access Control (5 tools)
- **IP Management**: `get_whitelisted_ips_ssh`, `get_whitelisted_ips_mysql`, `update_whitelisted_ips`
- **Security Monitoring**: `check_ip_blacklisted`
- **Tool Access**: `allow_ip_siab`, `allow_ip_adminer`
- **SSL Management**: `install_ssl_certificate`, `remove_ssl_certificate`, `install_letsencrypt`, `renew_letsencrypt`, `set_letsencrypt_auto_renewal`, `revoke_letsencrypt`
- **Git Deployment**: `generate_git_ssh_key`, `get_git_ssh_key`, `git_clone`, `git_pull`, `get_git_deployment_history`, `get_git_branch_names`

## 🏗 Architecture

```
cw-mcp/
├── main.py                 # Application entry point
├── server.py              # FastMCP server instance  
├── config.py              # Configuration management
├── requirements.txt       # Dependencies
│
├── auth/                  # Authentication & Security
│   ├── customer.py       # Customer session management
│   ├── tokens.py         # API token handling with auto-renewal
│   └── rate_limit.py     # Token bucket rate limiting
│
├── tools/                 # MCP Tools (43+ tools total)
│   ├── basic.py          # Core operations (18 tools)
│   ├── servers.py        # Server management (12 tools) 
│   ├── apps.py           # Application management (8 tools)
│   └── security.py       # Security & access control (5 tools)
│
└── utils/                # Shared Utilities
    ├── api_client.py     # HTTP client with retry logic
    └── logging.py        # Structured logging setup
```

## 🔧 Installation & Setup

### Prerequisites
- Python 3.11+
- Redis server (for caching and session management)
- Cloudways API credentials

### Installation Steps

1. **Clone and setup environment**:
   ```bash
   cd ~/projects/google-adk/mcp-servers/cw-mcp
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Configure environment variables**:
   ```bash
   # Generate encryption key for secure credential storage
   export ENCRYPTION_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
   
   # Redis configuration
   export REDIS_URL="redis://localhost:6379/0"
   
   # Optional performance tuning
   export REDIS_POOL_SIZE="500"
   export HTTP_POOL_SIZE="500"
   export RATE_LIMIT_REQUESTS="90"
   export RATE_LIMIT_WINDOW="60"
   ```

### Encryption Key Management

The server requires a Fernet encryption key for secure credential storage.

#### Generating a New Key

```bash
# Generate and set encryption key
export ENCRYPTION_KEY=$(python -c 'from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())')
```

#### Exporting an Existing Key

```bash
# Save current key to file
echo $ENCRYPTION_KEY > encryption_key.txt

# Create environment file
echo "ENCRYPTION_KEY=$ENCRYPTION_KEY" > .env

# Load from environment file
export $(cat .env | xargs)
```

#### Key Validation

```python
# validate_key.py
from cryptography.fernet import Fernet
import os

key = os.getenv('ENCRYPTION_KEY')
if not key:
    print("ENCRYPTION_KEY not set")
    exit(1)

try:
    fernet = Fernet(key.encode())
    test_data = b"test"
    encrypted = fernet.encrypt(test_data)
    decrypted = fernet.decrypt(encrypted)
    
    if decrypted == test_data:
        print("Encryption key is valid")
    else:
        print("Key validation failed")
except Exception as e:
    print(f"Invalid encryption key: {e}")
```

#### Important Notes

- Key must be 44 characters long (base64-encoded)
- Generated using `Fernet.generate_key()`
- Do not commit keys to version control
- Changing the key invalidates existing encrypted data in Redis

3. **Start the server**:
   ```bash
   python main.py
   ```

   Server will be available at: `http://localhost:7000/mcp`

## 🔐 Authentication

The server uses header-based authentication with encrypted credential storage:

```http
x-cloudways-email: your-email@domain.com
x-cloudways-api-key: your-cloudways-api-key
```

### Security Features
- **Credential Encryption**: API keys encrypted with Fernet before Redis storage
- **Token Auto-Renewal**: Proactive OAuth token refresh before expiration
- **Rate Limiting**: Token bucket algorithm (90 requests/60 seconds by default)
- **Audit Logging**: Comprehensive request/response logging with structured data

## 📝 Usage Examples

### Basic Server Management
```python
# List all servers
servers = await list_servers()

# Get server details with monitoring data
details = await get_server_details({"server_id": 378350})

# Start/stop server operations
await start_server({"server_id": 378350})
await stop_server({"server_id": 378350})
```

### Application Operations
```python
# Deploy application via Git
await git_clone({
    "server_id": 378350,
    "app_id": 1185437,
    "repo_url": "git@github.com:user/repo.git",
    "branch": "main"
})

# Backup and restore operations
await backup_app({"server_id": 378350, "app_id": 1185437})
await restore_app({
    "server_id": 378350,
    "app_id": 1185437, 
    "backup_id": "backup_123"
})
```

### Security Management
```python
# Whitelist IPs for database access
await update_whitelisted_ips({
    "server_id": 378350,
    "ips": ["192.168.1.100", "10.0.0.5"]
})

# SSL certificate management
await install_letsencrypt({"server_id": 378350, "app_id": 1185437})
```

## ⚙️ Configuration Options

| Variable | Default | Description |
|----------|---------|-------------|
| `ENCRYPTION_KEY` | *Required* | Fernet encryption key for credential storage |
| `REDIS_URL` | `redis://localhost:6379/0` | Redis connection string |
| `REDIS_POOL_SIZE` | `500` | Redis connection pool size |
| `HTTP_POOL_SIZE` | `500` | HTTP connection pool size |
| `RATE_LIMIT_REQUESTS` | `90` | Requests per time window |
| `RATE_LIMIT_WINDOW` | `60` | Rate limit window (seconds) |
| `LOG_LEVEL` | `INFO` | Logging verbosity |
| `LOG_FORMAT` | `console` | Log format (console/json) |

## 📊 Monitoring & Observability

### Structured Logging
- **Performance Metrics**: Request timing and resource usage
- **Security Events**: Authentication failures, rate limiting
- **API Interactions**: Full request/response logging with sanitized credentials
- **Error Tracking**: Comprehensive error context and stack traces

### Health Checks
- `ping` - Basic connectivity and authentication test
- `rate_limit_status` - Current rate limit status
- `customer_info` - Session and authentication status

## 🔄 Development & Extension

### Adding New Tools
1. Choose appropriate module in `tools/` directory
2. Follow existing patterns for error handling and authentication
3. Use type hints with Pydantic models for parameters
4. Include comprehensive docstrings
5. Test with various authentication scenarios

### Tool Development Template
```python
@mcp.tool
async def your_new_tool(ctx: Context, params: YourParamModel) -> Dict[str, Any]:
    """
    Tool description for MCP client
    
    Args:
        params: Parameter model with validation
    
    Returns:
        Standardized response dictionary
    """
    return await make_api_request(
        ctx, "/your/endpoint", 
        params.dict(), 
        redis_client, http_client, token_manager
    )
```

## 🚀 Production Deployment

### Docker Deployment
```dockerfile
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt
COPY . .
EXPOSE 7000
CMD ["python", "main.py"]
```

### Environment Considerations
- **Redis**: Use Redis Cluster for high availability
- **Load Balancing**: Multiple server instances behind load balancer
- **SSL/TLS**: Terminate SSL at load balancer or reverse proxy
- **Monitoring**: Integrate with Prometheus/Grafana for metrics

## 📄 License

This project is part of the internal tooling ecosystem and follows company licensing guidelines.

## 🤝 Contributing

1. Follow existing code patterns and documentation standards
2. Ensure comprehensive error handling and logging
3. Add tests for new functionality
4. Update documentation for any new tools or features

---

**Server Status**: Production Ready ✅  
**API Coverage**: 43+ Tools Across All Cloudways Functions  
**Last Updated**: September 2025