#!/usr/bin/env python3

# This script connect the MCP AI agent to Kali Linux terminal and API Server.
# It allows the AI agent to leverage tools and execute commands on a Kali Linux machine
# by communicating with a corresponding server application (Kaliserver.py).

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import json # Added for potential direct use, though requests.exceptions.JSONDecodeError is primary

from fastmcp import FastMCP # FastMCP is likely a framework for creating AI agent tools

# Configure logging
# Sets up basic logging to stdout with a specific format.
logging.basicConfig(
    level=logging.INFO, # Default logging level
    format="%(asctime)s [%(levelname)s] %(message)s", # Log message format
    handlers=[
        logging.StreamHandler(sys.stdout) # Output logs to standard output
    ]
)
logger = logging.getLogger(__name__) # Get a logger instance for this module

# Default configuration
DEFAULT_KALI_SERVER = "http://<Kali IP>:5000" # Default URL for the Kali API server. Change to your linux IP if it's on a different machine.
DEFAULT_REQUEST_TIMEOUT = 300  # 5 minutes default timeout for API requests to the Kali server.

class KaliToolsClient:
    """
    Client for communicating with the Kali Linux Tools API Server (Kaliserver.py).
    This class handles making HTTP GET and POST requests to the server's API endpoints.
    """
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        """
        Initialize the Kali Tools Client.
        
        Args:
            server_url: URL of the Kali Tools API Server.
            timeout: Request timeout in seconds for API calls.
        """
        self.server_url = server_url.rstrip("/") # Remove trailing slash from server URL if present
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {self.server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """
        Perform a GET request to a specified endpoint on the Kali API server.
        Includes error handling for network issues and unexpected responses.
        
        Args:
            endpoint: API endpoint path (e.g., "health", "api/tools/nmap").
            params: Optional dictionary of query parameters to append to the URL.
            
        Returns:
            A dictionary containing the JSON response from the server, or an error dictionary if the request fails.
        """
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}" # Construct the full URL

        try:
            logger.debug(f"GET {url} with params: {params}")
            # Make the GET request
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status() # Raise an HTTPError for bad responses (4XX or 5XX)
            return response.json() # Parse the JSON response
        except requests.exceptions.JSONDecodeError as e:
            # Handle errors when response is not valid JSON
            logger.error(f"JSON decode failed for GET {url}: {str(e)}")
            logger.debug(f"Response text that failed to parse: {response.text}")
            return {"error": f"JSON decode failed: {str(e)}", "response_text": response.text, "success": False}
        except requests.exceptions.RequestException as e:
            # Handle network-related errors (DNS failure, connection refused, timeout, etc.)
            logger.error(f"Request failed for GET {url}: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a POST request with JSON data to a specified endpoint on the Kali API server.
        Includes error handling for network issues and unexpected responses.
        
        Args:
            endpoint: API endpoint path (e.g., "api/command", "api/tools/ssh").
            json_data: A dictionary containing the JSON payload to send in the request body.
            
        Returns:
            A dictionary containing the JSON response from the server, or an error dictionary if the request fails.
        """
        url = f"{self.server_url}/{endpoint}" # Construct the full URL
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            # Make the POST request
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status() # Raise an HTTPError for bad responses (4XX or 5XX)
            return response.json() # Parse the JSON response
        except requests.exceptions.JSONDecodeError as e:
            # Handle errors when response is not valid JSON
            logger.error(f"JSON decode failed for POST {url}: {str(e)}")
            logger.debug(f"Response text that failed to parse: {response.text}")
            return {"error": f"JSON decode failed: {str(e)}", "response_text": response.text, "success": False}
        except requests.exceptions.RequestException as e:
            # Handle network-related errors
            logger.error(f"Request failed for POST {url}: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """
        Execute a generic shell command on the Kali server via the "/api/command" endpoint.
        
        Args:
            command: The shell command string to execute.
            
        Returns:
            A dictionary containing the command execution results (stdout, stderr, return code).
        """
        logger.info(f"Requesting execution of command: {command}")
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """
        Check the health of the Kali Tools API Server by querying its "/health" endpoint.
        
        Returns:
            A dictionary containing health status information from the server.
        """
        logger.info("Checking Kali API server health.")
        return self.safe_get("health")

def setup_mcp_server(kali_client: KaliToolsClient, log_level: str = "INFO") -> FastMCP:
    """
    Set up and configure the FastMCP server instance.
    This function defines the tools that the MCP agent (e.g., an LLM like Claude) can use.
    Each tool corresponds to an action that can be performed on the Kali server.

    Args:
        kali_client: An initialized KaliToolsClient instance for communication with the Kali API server.
        log_level: The logging level for the FastMCP server (e.g., "INFO", "DEBUG").

    Returns:
        A configured FastMCP instance with tools registered.
    """
    mcp = FastMCP("kali-mcp", log_level=log_level) # Initialize the MCP server, "kali-mcp" is likely its name or ID.
    logger.info(f"Setting up MCP server with log level {log_level} and registering tools.")

    # Define the "nmap_scan" tool
    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        
        # docstrings are included as prompts to the LLM 
        """
        MCP Tool: Execute an Nmap scan against a target using the Kali server.
        This function will be callable by the AI agent.

        Args:
            target: The IP address or hostname to scan.
            scan_type: Nmap scan type (e.g., "-sV" for version detection, "-sS" for SYN scan). Defaults to "-sV".
            ports: Specific ports to scan (e.g., "80,443", "1-1000"). Defaults to Nmap's default.
            additional_args: Any other Nmap arguments (e.g., "-T4", "-Pn").

        Returns:
            The result of the Nmap scan from the Kali server.
        """
        logger.info(f"Nmap tool called: target={target}, scan_type={scan_type}, ports='{ports}', args='{additional_args}'")
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        # Forward the request to the Kali server's nmap endpoint
        return kali_client.safe_post("api/tools/nmap", data)

    # Define the "ssh_connect" tool for establishing persistent SSH connections
    @mcp.tool()
    def ssh_connect(host: str, username: str, password: str, port: int = 22) -> Dict[str, Any]:
        """
        MCP Tool: Establish a persistent SSH connection to a remote host.
        This connection can then be used to execute multiple commands without re-authenticating.
        
        Args:
            host: The IP address or hostname of the remote machine to connect to.
            username: SSH username for authentication.
            password: SSH password for authentication.
            port: SSH port (default: 22).
        
        Returns:
            Connection information including the connection_id needed for subsequent commands.
        """
        logger.info(f"SSH connect tool called: host={host}, username={username}, port={port}")
        data = {
            "host": host,
            "username": username,
            "password": password,
            "port": port
        }
        return kali_client.safe_post("api/ssh/connect", data)

    # Define the "ssh_disconnect" tool for closing SSH connections
    @mcp.tool()
    def ssh_disconnect(connection_id: str = "", disconnect_all: bool = False) -> Dict[str, Any]:
        """
        MCP Tool: Disconnect a specific SSH connection or all SSH connections.
        
        Args:
            connection_id: The ID of the specific SSH connection to disconnect. 
                          Required if disconnect_all is False.
            disconnect_all: If True, disconnect all active SSH connections.
        
        Returns:
            Disconnection status and information.
        """
        logger.info(f"SSH disconnect tool called: connection_id={connection_id}, disconnect_all={disconnect_all}")
        
        if disconnect_all:
            data = {"all": True}
        else:
            if not connection_id:
                return {"success": False, "error": "connection_id is required when disconnect_all is False"}
            data = {"connection_id": connection_id}
        
        return kali_client.safe_post("api/ssh/disconnect", data)

    # Define the "ssh_status" tool for checking SSH connection status
    @mcp.tool()
    def ssh_status() -> Dict[str, Any]:
        """
        MCP Tool: Get the status of all active SSH connections.
        Shows connection details, idle time, and whether connections are still active.
        
        Returns:
            Status information for all SSH connections.
        """
        logger.info("SSH status tool called")
        return kali_client.safe_get("api/ssh/status")

    # Define the "run_command" tool - Enhanced to support SSH routing
    @mcp.tool()
    def run_command(command: str, workdir: str = "", stdin: str = "", ssh_connection_id: str = "") -> Dict[str, Any]:
        """
        MCP Tool: Execute an arbitrary shell command on the Kali server or through a persistent SSH connection.
        This provides the same functionality as mcp-server-commands but through our existing API architecture.
        
        Args:
            command: The shell command to execute (e.g., "ls -la", "cat /etc/passwd").
            workdir: Optional working directory to execute the command in (local execution only).
            stdin: Optional text to pipe into the command's STDIN.
            ssh_connection_id: Optional SSH connection ID to route the command through a persistent SSH connection.
                              If provided, the command will be executed on the remote host via SSH.
            
        Returns:
            The result of the command execution from the Kali server or remote SSH host.
        """
        execution_context = f"SSH connection {ssh_connection_id}" if ssh_connection_id else "local Kali server"
        logger.info(f"Run command tool called: command='{command[:100]}...', context={execution_context}")
        
        data = {
            "command": command,
            "workdir": workdir,
            "stdin": stdin
        }
        
        # Add SSH connection routing if specified
        if ssh_connection_id:
            data["ssh_connection_id"] = ssh_connection_id
        
        # Forward the request to the Kali server's advanced command endpoint
        return kali_client.safe_post("api/command/advanced", data)

    # Define the "server_health" tool
    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        MCP Tool: Check the health status of the backend Kali API server.
        This function will be callable by the AI agent.

        Returns:
            Server health information including SSH connection status.
        """
        logger.info("Server health tool called.")
        # Use the KaliToolsClient's check_health method
        return kali_client.check_health()

    logger.info("MCP tools registered: nmap_scan, ssh_connect, ssh_disconnect, ssh_status, run_command, server_health")
    return mcp

def parse_args():
    """
    Parse command line arguments for the MCP client script.
    Allows configuration of server URL, timeout, and debug logging.
    """
    parser = argparse.ArgumentParser(description="Run the Kali MCP Client")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging level")
    return parser.parse_args()

def main():
    """
    Main entry point for the MCP client application.
    Initializes the Kali Tools client, checks server health, sets up the MCP server, and starts it.
    """
    args = parse_args() # Parse command-line arguments
    
    # Configure logging level based on the --debug flag
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.info("Debug logging enabled by command line argument.")
    
    # Initialize the Kali Tools client with configured server URL and timeout
    logger.info(f"Initializing KaliToolsClient with server: {args.server}, timeout: {args.timeout}s")
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    # Perform an initial health check of the Kali API server
    logger.info("Performing initial health check of Kali API server...")
    health = kali_client.check_health()
    if "error" in health:
        # Log a warning if the server is unreachable or reports an error
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("MCP client will start, but tool execution will likely fail until server is available.")
    else:
        # Log successful connection and server status details
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health.get('status', 'N/A')}")
        if not health.get("all_essential_tools_available", True): # Default to True if key is missing to avoid false alarm
            logger.warning("Kali server reported that not all essential tools are available.")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools on Kali server: {', '.join(missing_tools)}")
        
        # Report SSH connection status
        ssh_status = health.get("ssh_connections", {})
        active_connections = ssh_status.get("active_connections", 0)
        if active_connections > 0:
            logger.info(f"Found {active_connections} active SSH connection(s) on server")
        else:
            logger.info("No active SSH connections on server")
    
    # Set up the MCP server with the defined tools
    mcp_log_level = "DEBUG" if args.debug else "INFO"
    mcp = setup_mcp_server(kali_client, log_level=mcp_log_level)
    
    logger.info(f"Starting Kali MCP client server with log level: {mcp_log_level}...")
    # Run the MCP server, making it available for the AI agent to connect and use tools.
    # This call will typically block and listen for incoming requests for tool execution.
    mcp.run()

if __name__ == "__main__":
    # This ensures main() is called only when the script is executed directly,
    # not when imported as a module.
    main()
