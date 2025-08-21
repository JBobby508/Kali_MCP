# Kali_MCP

# Kali MCP Server

A Model Context Protocol (MCP) server that enables AI agents to interact with Kali Linux penetration testing tools through a secure API interface. This system provides remote execution capabilities for security testing tools like Nmap, SSH connections, and general command execution.

## Architecture Overview

The system consists of two main components:

1. **KaliServer.py** - Flask-based API server running on Kali Linux
2. **MCPClient.py** - MCP client that bridges AI agents to the Kali API

```
AI Agent (Claude) ↔ MCP Client ↔ HTTP API ↔ Kali Server ↔ Kali Tools
```

## Features

### Core Capabilities
- **Nmap Integration** - Execute network scans with customizable parameters
- **SSH Connection Management** - Establish persistent SSH connections to remote hosts
- **Command Execution** - Run arbitrary shell commands on Kali or remote systems
- **Health Monitoring** - Server status and tool availability checking

### Security Features
- Timeout management for long-running commands
- Connection pooling for SSH sessions
- Error handling and logging
- Non-blocking command execution

### Advanced Features
- Working directory specification for commands
- STDIN input support for interactive commands
- SSH connection routing for remote command execution
- Comprehensive logging and debugging

## Installation

### Prerequisites

**Kali Linux Machine:**
- Python 3.7+
- Flask (`pip install flask`)
- Paramiko (`pip install paramiko`)
- Standard Kali tools (nmap, ssh, etc.)

**MCP Client Machine:**
- Python 3.7+
- FastMCP (`pip install fastmcp`)
- Requests (`pip install requests`)

### Setup Steps

1. **Clone/Download the files to appropriate machines**

2. **On Kali Linux machine, start the API server:**
```bash
python3 KaliServer.py --port 5000 --debug
```

3. **On client machine, update the server IP in MCPClient.py:**
```python
DEFAULT_KALI_SERVER = "http://YOUR_KALI_IP:5000"
```

4. **Start the MCP client:**
```bash
python3 MCPClient.py --server http://YOUR_KALI_IP:5000
```

## Configuration

### KaliServer.py Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--port` | 5000 | API server listening port |
| `--debug` | False | Enable debug mode and verbose logging |
| `API_PORT` (env) | 5000 | Environment variable for port |
| `DEBUG_MODE` (env) | 0 | Environment variable for debug mode |
| `COMMAND_TIMEOUT` | 180 | Default command timeout in seconds |

### MCPClient.py Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--server` | http://192.168.1.170:5000 | Kali API server URL |
| `--timeout` | 300 | Request timeout in seconds |
| `--debug` | False | Enable debug logging |

## API Endpoints

### Health Check
```http
GET /health
```
Returns server status and tool availability.

### Command Execution
```http
POST /api/command
Content-Type: application/json

{
    "command": "ls -la"
}
```

### Advanced Command Execution
```http
POST /api/command/advanced
Content-Type: application/json

{
    "command": "ls -la",
    "workdir": "/tmp",
    "stdin": "input data",
    "ssh_connection_id": "ssh_1"
}
```

### Nmap Scanning
```http
POST /api/tools/nmap
Content-Type: application/json

{
    "target": "192.168.1.1",
    "scan_type": "-sV",
    "ports": "80,443",
    "additional_args": "-T4 -Pn"
}
```

### SSH Connection Management
```http
POST /api/ssh/connect
Content-Type: application/json

{
    "host": "192.168.1.100",
    "username": "user",
    "password": "password",
    "port": 22
}
```

## MCP Tools Available

### 1. nmap_scan
Execute Nmap scans against targets.

**Parameters:**
- `target` (required): IP address or hostname to scan
- `scan_type` (optional): Nmap scan type (default: "-sV")
- `ports` (optional): Specific ports to scan
- `additional_args` (optional): Additional Nmap arguments

**Example Usage:**
```python
# Through AI agent
"Scan 192.168.1.1 for web services"
"Run a SYN scan on ports 1-1000 against target.com"
```

### 2. ssh_connect
Establish persistent SSH connections.

**Parameters:**
- `host` (required): Target hostname/IP
- `username` (required): SSH username
- `password` (required): SSH password
- `port` (optional): SSH port (default: 22)

**Returns:** Connection ID for subsequent operations

### 3. ssh_disconnect
Close SSH connections.

**Parameters:**
- `connection_id` (optional): Specific connection to close
- `disconnect_all` (optional): Close all connections

### 4. ssh_status
Get status of all SSH connections.

**Returns:** Active connections, idle times, and connection health

### 5. run_command
Execute arbitrary shell commands.

**Parameters:**
- `command` (required): Shell command to execute
- `workdir` (optional): Working directory
- `stdin` (optional): Input to pipe to command
- `ssh_connection_id` (optional): Route through SSH connection

### 6. server_health
Check Kali server health and tool availability.

## Usage Examples

### Basic Network Scanning
```python
# AI agent can request:
"Scan 192.168.1.0/24 for open ports"
"Check if SSH is running on 10.0.0.1"
"Perform a service version scan on target.example.com"
```

### SSH-based Operations
```python
# Establish connection
"Connect to server 192.168.1.100 with username admin"

# Execute commands remotely
"List files in /etc on the connected server"
"Check running processes on the remote machine"

# Disconnect
"Close all SSH connections"
```

### Advanced Command Execution
```python
# Local commands with specific working directory
"Run 'find . -name *.conf' in the /etc directory"

# Commands with input
"Run 'grep searchterm' and pipe this text to it: [text content]"
```

## Security Considerations

### Network Security
- Run the API server on a secured network
- Use firewall rules to restrict access to the API port
- Consider VPN connections for remote access

### Authentication
- The current implementation uses basic password authentication for SSH
- Consider implementing API keys or token-based authentication
- SSH key-based authentication is recommended over passwords

### Command Execution
- Commands run with the privileges of the server process
- Be cautious with commands that require elevated privileges
- Implement command whitelisting for production environments

### Logging
- All commands and connections are logged
- Review logs regularly for suspicious activity
- Consider centralized logging for audit trails

## Troubleshooting

### Common Issues

**1. Connection Refused**
```
Error: Request failed: Connection refused
```
- Verify Kali server is running
- Check firewall settings on Kali machine
- Confirm correct IP address and port

**2. SSH Authentication Failures**
```
Error: SSH authentication failed
```
- Verify username and password
- Check if SSH service is running on target
- Confirm network connectivity to target

**3. Command Timeouts**
```
Error: Command timed out after 180 seconds
```
- Increase timeout for long-running commands
- Check if command is hanging or requires interaction
- Consider running commands in background

**4. Tool Not Found**
```
Error: Tool 'nmap' not available
```
- Install missing tools on Kali machine
- Update tool paths if installed in non-standard locations
- Check tool permissions

### Debug Mode

Enable debug mode for verbose logging:

**Kali Server:**
```bash
python3 KaliServer.py --debug
```

**MCP Client:**
```bash
python3 MCPClient.py --debug
```

## Development and Extension

### Adding New Tools

1. **Add endpoint in KaliServer.py:**
```python
@app.route("/api/tools/newtool", methods=["POST"])
def new_tool():
    # Implementation here
    pass
```

2. **Add MCP tool in MCPClient.py:**
```python
@mcp.tool()
def new_tool(param1: str, param2: str = "default") -> Dict[str, Any]:
    """Tool description"""
    data = {"param1": param1, "param2": param2}
    return kali_client.safe_post("api/tools/newtool", data)
```

### Code Structure

**KaliServer.py Key Classes:**
- `SSHConnectionManager`: Handles persistent SSH connections
- `CommandExecutor`: Manages command execution with timeouts
- Flask routes: API endpoint handlers

**MCPClient.py Key Classes:**
- `KaliToolsClient`: HTTP client for API communication
- `setup_mcp_server()`: Defines available MCP tools
- Error handling and logging utilities

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with appropriate logging
4. Test with both local and remote operations
5. Submit a pull request

## License

This project is intended for educational and authorized security testing purposes only. Use responsibly and in accordance with applicable laws and regulations.

## Acknowledgments

- Inspired by [project_astro](https://github.com/whit3rabbit0/project_astro)
- Built using FastMCP framework
- Designed for integration with Anthropic's Claude AI
