# 🚀 Cloudways MCP Server

An MCP (Model Context Protocol) server for seamless integration with the Cloudways API. This server enables AI assistants like Claude to access and manage your Cloudways infrastructure.

## ✨ Key Features

### 🔒 **Security & Isolation**
- **Customer Isolation**: Each customer gets encrypted, isolated data storage
- **Encrypted API Keys**: All sensitive data encrypted at rest using Fernet encryption
- **Token Auto-Renewal**: Proactive token refresh prevents authentication failures
- **Rate Limiting**: Token bucket algorithm with per-customer limits (90 req/min)

### ⚡ **Performance & Reliability**
- **Connection Pooling**: Optimized HTTP and Redis connection pools for high concurrency
- **Background Token Refresh**: Zero-downtime token renewal with race condition protection
- **Distributed Locking**: Redis-based locks prevent concurrent token refresh conflicts
- **Graceful Fallbacks**: Robust error handling with fallback mechanisms

### 📊 **Monitoring & Observability**
- **Structured Logging**: Comprehensive logging with structured data for debugging
- **Token Status Monitoring**: Real-time token health and expiration tracking
- **Rate Limit Monitoring**: Per-customer rate limit status and usage analytics
- **Customer Analytics**: Track customer usage patterns and last activity

### 🛠️ **Current Capabilities (Read-Only)**
- ✅ **Server Management**: List, monitor, and inspect server configurations
- ✅ **Application Management**: Access app details, credentials, and settings  
- ✅ **Monitoring Data**: Bandwidth, disk usage, and performance metrics
- ✅ **Team & Projects**: View team members, projects, and organizational structure
- ✅ **Infrastructure Discovery**: Available providers, regions, sizes, and packages
- ✅ **Alerting**: Access all system alerts and notifications

### 🚧 **Future Roadmap**
- 🔄 **Write Operations**: Create, modify, and delete resources
- 🎛️ **Server Management**: Start, stop, restart, and scale servers
- 📦 **Application Deployment**: Deploy new applications and manage existing ones
- ⚙️ **Configuration Management**: Update server and application settings
- 🔐 **Security Operations**: Manage SSH keys, SSL certificates, and firewall rules

## 🏗️ Architecture

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Claude AI     │────│  MCP Server     │────│  Cloudways API  │
│                 │    │                 │    │                 │
│ • Natural Lang  │    │ • Token Mgmt    │    │ • REST Endpoints│
│ • Context Aware │    │ • Rate Limiting │    │ • Authentication│
│ • Multi-tenant  │    │ • Encryption    │    │ • Resource Data │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                       ┌─────────────────┐
                       │   Redis Cache   │
                       │                 │
                       │ • Token Storage │
                       │ • Rate Limits   │
                       │ • Customer Data │
                       └─────────────────┘
```

## 🚀 Quick Start

### Prerequisites

- **Python 3.8+** - For running the MCP server
- **Node.js 18+ and NPM** - Required for Claude Desktop to connect via `npx mcp-remote`
- **Redis server** - For production features (token management, rate limiting, customer isolation)
- **Cloudways account** with API access
- **Homebrew** (macOS) - For easy installation of dependencies

### Installation

#### 1. **Install System Dependencies (macOS)**

**Install Node.js and NPM:**
```bash
# Using Homebrew (recommended)
brew install node

# Verify installation
node --version  # Should show v18+ 
npm --version   # Should show npm version
```

**Install and Setup Redis:**
```bash
# Install Redis using Homebrew
brew install redis

# Start Redis as a background service (auto-restart on boot)
brew services start redis

# Verify Redis is running
redis-cli ping  # Should respond with "PONG"
```

**Alternative Redis Setup:**
```bash
# If you prefer to run Redis manually (not as a service)
/opt/homebrew/opt/redis/bin/redis-server /opt/homebrew/etc/redis.conf

# To stop the Redis service later
brew services stop redis
```

#### 2. **Clone and Setup Project**

**Clone the repository**:
```bash
git clone <repository-url>
cd cloudways-mcp
```

**Create Python virtual environment**:
```bash
python3 -m venv venv
source venv/bin/activate  # On macOS/Linux
```

**Install Python dependencies**:
```bash
pip install -r requirements.txt
```

#### 3. **Configure Environment Variables**

Create a `.env` file in the project root:
```bash
# Environment Variables for Cloudways MCP Server

# Encryption key (auto-generated if not set)
ENCRYPTION_KEY=""

# Redis connection URL
REDIS_URL="redis://localhost:6379/0"

# Rate limiting configuration (requests per minute per customer)
RATE_LIMIT_REQUESTS="90"

# Optional: Logging level
LOG_LEVEL="INFO"
```

#### 4. **Start the MCP Server**

```bash
# Make sure you're in the virtual environment
source venv/bin/activate

# Start the server
python cw-mcp.py
```

The server will start on `http://127.0.0.1:7000/mcp` and you should see:
```
==================================================
🚀 Cloudways MCP Server
==================================================
INFO: Started server process [XXXX]
INFO: Uvicorn running on http://127.0.0.1:7000 (Press CTRL+C to quit)
```

#### 5. **Verify Setup**

**Test Redis Connection:**
```bash
redis-cli ping  # Should return "PONG"
```

**Test MCP Server:**
```bash
# Check if server is running
curl -v "http://127.0.0.1:7000/mcp/"
# Should return a 406 error (expected - means server is working)
```

**Check Server Logs:**
The server logs will show successful startup and any connection attempts from Claude Desktop.

## 🔧 Claude Desktop Integration

### Configuration File Location

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

### Example Configuration

```json
{
  "mcpServers": {
    "cloudways": {
      "command": "npx",
      "args": [
        "-y",
        "mcp-remote",
        "http://127.0.0.1:7000/mcp",
        "--header",
        "x-cloudways-email: ${CLOUDWAYS_EMAIL}",
        "--header",
        "x-cloudways-api-key: ${CLOUDWAYS_API_KEY}"
      ],
      "env": {
        "CLOUDWAYS_EMAIL": "your@cloudways-email.com",
        "CLOUDWAYS_API_KEY": "your-cloudways-api-key"
      }
    }
  }
}
```

### Getting Your API Key

1. Log into [Cloudways Platform](https://platform.cloudways.com)
2. Go to **Account Settings** → **API**
3. Generate or copy your API key

## 🛠️ Available Tools

### 🖥️ **Server Operations**
| Tool | Description | Example Usage |
|------|-------------|---------------|
| `list_servers` | Get all servers in your account | "Show me all my servers" |
| `get_server_details` | Get detailed server information | "Show details for server ID 12345" |
| `get_ssh_keys` | Get SSH keys for a server | "What SSH keys are on server 12345?" |

### 📱 **Application Operations**
| Tool | Description | Example Usage |
|------|-------------|---------------|
| `get_app_details` | Get application details | "Show me app 67890 on server 12345" |
| `get_app_credentials` | Get app login credentials | "What are the credentials for app 67890?" |
| `get_app_settings` | Get application settings | "Show settings for my WordPress app" |
| `get_app_monitoring_summary` | Get app performance metrics | "How much bandwidth is app 67890 using?" |

### 📊 **Monitoring & Analytics**
| Tool | Description | Example Usage |
|------|-------------|---------------|
| `get_server_details` | Server bandwidth and disk usage | "Show server 12345 resource usage" |
| `get_app_monitoring_summary` | Application metrics | "App performance for the last month" |
| `get_alerts` | All system alerts | "Show me any critical alerts" |

### 👥 **Organization & Projects**
| Tool | Description | Example Usage |
|------|-------------|---------------|
| `list_projects` | Get all projects | "What projects do I have?" |
| `list_team_members` | Get team member list | "Who has access to my account?" |

### 🌐 **Infrastructure Discovery**
| Tool | Description | Example Usage |
|------|-------------|---------------|
| `get_available_providers` | Cloud providers (AWS, DO, etc.) | "What cloud providers are available?" |
| `get_available_regions` | Available regions per provider | "Show me AWS regions" |
| `get_available_server_sizes` | Server size options | "What server sizes can I choose?" |
| `get_available_apps` | Installable applications | "What apps can I install?" |
| `get_available_packages` | Available packages & versions | "Show me PHP versions available" |

### 🔧 **System & Debugging**
| Tool | Description | Example Usage |
|------|-------------|---------------|
| `ping` | Test connectivity | "Test my connection" |
| `customer_info` | Your account information | "Show my account details" |
| `get_token_status` | Token health and expiry info | "Check my authentication status" |
| `rate_limit_status` | API usage and limits | "How many API calls have I made?" |

## 💬 Example Claude Conversations

### Server Management
```
You: "Show me all my Cloudways servers and their status"
Claude: I'll get your server list and check their status...

You: "Which server is using the most bandwidth this month?"
Claude: Looking at your server monitoring data...

You: "Show me the PHP version on server 12345"
Claude: Let me check the server details and package information...
```

### Application Management
```

You: "What are the database credentials for my e-commerce app?"
Claude: I'll retrieve the application credentials securely...

You: "Show me all WordPress sites across all my servers"
Claude: Let me scan through your applications to find WordPress installations...
```

### Infrastructure Planning
```
You: "I want to deploy a new Laravel app. What options do I have?"
Claude: Let me show you available server sizes, and regions...

```

## 🔒 Security & Privacy

### Data Protection
- **Encryption at Rest**: All API keys encrypted using Fernet symmetric encryption
- **Customer Isolation**: Each customer's data is completely isolated and namespaced
- **No Data Persistence**: Tokens and sensitive data have automatic expiration
- **Memory-Safe**: Sensitive data cleared from memory after use

### Authentication Flow
1. **Header-Based Auth**: Credentials passed via headers
2. **Token Exchange**: API key exchanged for short-lived access tokens
3. **Proactive Renewal**: Tokens refreshed 5 minutes before expiry
4. **Race Protection**: Distributed locks prevent concurrent refresh attempts

### Rate Limiting
- **Per-Customer Limits**: 90 requests per minute per customer
- **Token Bucket Algorithm**: Smooth traffic distribution
- **Graceful Degradation**: Clear error messages when limits exceeded

### Debug Mode
Enable verbose logging:
```bash
export LOG_LEVEL=DEBUG
python cw-mcp.py
```

## 🔧 Troubleshooting

### Common Issues and Solutions

#### **Node.js/NPM Issues**

**Problem**: `zsh: command not found: node`
```bash
# Solution: Install Node.js
brew install node

# If Homebrew is not installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

**Problem**: `npx: command not found`
```bash
# NPX comes with npm, reinstall Node.js
brew uninstall node
brew install node
```

#### **Redis Issues**

**Problem**: `Connection refused` when testing Redis
```bash
# Check if Redis is running
brew services list | grep redis

# Start Redis if not running
brew services start redis

# If Redis was installed via different method
redis-server /opt/homebrew/etc/redis.conf
```

**Problem**: Redis connection timeout
```bash
# Check Redis status
redis-cli ping

# If Redis is on different port/host, update .env file
REDIS_URL="redis://localhost:6380/0"  # Use correct port
```

#### **MCP Server Issues**

**Problem**: `ModuleNotFoundError` when starting server
```bash
# Ensure virtual environment is activated
source venv/bin/activate

# Reinstall dependencies
pip install -r requirements.txt
```

**Problem**: Port 7000 already in use
```bash
# Find process using port 7000
lsof -i :7000

# Kill the process (replace PID with actual process ID)
kill -9 <PID>

# Or use a different port by modifying cw-mcp.py
```

**Problem**: Server starts but Claude Desktop can't connect
```bash
# Verify server is listening
curl -v "http://127.0.0.1:7000/mcp/"

# Should return 406 error (this is correct!)
# Check Claude Desktop config file has correct URL
```

#### **Claude Desktop Connection Issues**

**Problem**: MCP server not recognized by Claude Desktop
1. Restart Claude Desktop completely
2. Check the configuration file location:
   - macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
3. Verify JSON syntax is valid
4. Ensure the MCP server is running before starting Claude Desktop

**Problem**: Authentication errors
1. Verify your Cloudways credentials are correct
2. Check that your API key has proper permissions
3. Test credentials manually via Cloudways API

#### **Cloudways API Issues**

**Problem**: `Invalid API key` errors
```bash
# Test your credentials directly
curl -X POST "https://api.cloudways.com/api/v1/oauth/access_token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "email=your@email.com&api_key=your-api-key"
```

**Problem**: Rate limiting errors
- The server implements 90 requests/minute per customer
- Wait a minute and try again
- Check server logs for rate limit status

### Getting Help

**Enable Debug Logging:**
```bash
# In your .env file
LOG_LEVEL=DEBUG

# Or export temporarily
export LOG_LEVEL=DEBUG
python cw-mcp.py
```

**Check Server Status:**
```bash
# Process check
ps aux | grep cw-mcp

# Port check  
lsof -i :7000

# Connection test
curl -v "http://127.0.0.1:7000/mcp/"
```

## 🆘 Support

- **Issues**: Open a GitHub issue for bugs or feature requests


---

**⚠️ Current Limitation**: This server currently supports **read-only operations** only. Write operations (create, update, delete) are planned for future releases to ensure maximum safety and reliability.
