# Cloudways MCP Server

A simple MCP (Model Context Protocol) server for interacting with the Cloudways API. This server provides read-only access to your Cloudways resources.

## Features

- Simple environment variable authentication
- Automatic token management and refresh
- Read-only operations for:
  - Servers and their details
  - Applications and their settings
  - Monitoring data
  - Projects
  - Team members
  - Alerts
  - SSH keys
  - Available providers, regions, and server sizes

## Installation

1. Clone or download this repository
2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Configuration

Set your Cloudways credentials as environment variables:

```bash
export CLOUDWAYS_EMAIL="your@email.com"
export CLOUDWAYS_API_KEY="your-api-key"
```

You can get your API key from: https://platform.cloudways.com/api

## Usage

### Running the Server

```bash
python server.py
```

Or make it executable:
```bash
chmod +x server.py
./server.py
```

### Claude Desktop Configuration

Add this to your Claude Desktop configuration file:

**macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
**Windows**: `%APPDATA%/Claude/claude_desktop_config.json`

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
        "CLOUDWAYS_EMAIL": "your primary cloudways email",
        "CLOUDWAYS_API_KEY": "<cloudways API Key>"
      }
    }
  }
}
```

### Available Tools

#### Server Operations
- `list_servers` - Get list of all servers
- `get_server_details` - Get details of a specific server
- `get_server_status` - Get status of services on a server
- `get_server_settings` - Get server settings and package versions
- `get_server_monitoring_summary` - Get bandwidth and disk usage summary
- `get_ssh_keys` - Get SSH keys for a server

#### Application Operations
- `get_app_details` - Get details of a specific application
- `get_app_credentials` - Get application credentials
- `get_app_settings` - Get application settings
- `get_app_monitoring_summary` - Get app bandwidth and disk usage

#### Other Operations
- `list_projects` - Get list of projects
- `list_team_members` - Get list of team members
- `get_alerts` - Get all alerts
- `get_available_providers` - Get list of cloud providers
- `get_available_regions` - Get available regions
- `get_available_server_sizes` - Get available server sizes
- `get_available_apps` - Get list of installable applications
- `get_available_packages` - Get available packages and versions

## Example Usage in Claude

List servers:
```
Can you show me my Cloudways servers?
```

Get server details:
```
Show me details for server ID 12345
```

Check server status:
```
What's the status of services on server 12345?
```

## Security Notes

- The server only exposes read-only operations
- API credentials are stored as environment variables
- Token automatically refreshes before expiration
- No credentials are logged or persisted

## Alternative Setup Methods

### Using a Shell Script

Create a `run-cloudways-mcp.sh` file:

```bash
#!/bin/bash
export CLOUDWAYS_EMAIL="your@email.com"
export CLOUDWAYS_API_KEY="your-api-key"
python /Users/afraz/projects/cloudways-mcp/server.py
```

Then in Claude Desktop config:
```json
{
  "mcpServers": {
    "cloudways": {
      "command": "/path/to/run-cloudways-mcp.sh"
    }
  }
}
```

### Using .env File (Optional)

If you prefer using a `.env` file, install `python-dotenv`:

```bash
pip install python-dotenv
```

Create a `.env` file:
```
CLOUDWAYS_EMAIL=your@email.com
CLOUDWAYS_API_KEY=your-api-key
```

Then add this to the top of `server.py` (after imports):
```python
from dotenv import load_dotenv
load_dotenv()
```
