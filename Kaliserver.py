#!/usr/bin/env python3

# This script implements a Flask-based API server that runs on a Kali Linux machine.
# It exposes endpoints to execute shell commands, run specific penetration testing tools (like Nmap),
# and perform actions via SSH on other machines.
# This server acts as the backend for MCPClient.py, allowing an AI agent to interact with Kali Linux.

# some of the code here was inspired from https://github.com/whit3rabbit0/project_astro , be sure to check them out

import argparse
import json
import logging
import os
import subprocess
import sys
import traceback
import threading
import time
from typing import Dict, Any, Optional
from flask import Flask, request, jsonify
import paramiko

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
) 
logger = logging.getLogger(__name__)

# Configuration
API_PORT = int(os.environ.get("API_PORT", 5000))
DEBUG_MODE = os.environ.get("DEBUG_MODE", "0").lower() in ("1", "true", "yes", "y")
COMMAND_TIMEOUT = 180  # 3 minutes default timeout (previously 5, adjusted for consistency with comment)

app = Flask(__name__)

class SSHConnectionManager:
    """
    Manages persistent SSH connections to remote hosts.
    Allows connecting once and executing multiple commands through the same connection.
    """
    
    def __init__(self):
        self.connections = {}  # Format: {connection_id: {"client": paramiko.SSHClient, "host": str, "username": str, "last_used": float}}
        self.connection_counter = 0
        self.lock = threading.Lock()
    
    def connect(self, host: str, username: str, password: str, port: int = 22) -> Dict[str, Any]:
        """
        Establish a persistent SSH connection.
        
        Args:
            host: The hostname/IP to connect to
            username: SSH username
            password: SSH password  
            port: SSH port (default 22)
            
        Returns:
            Dictionary with connection info or error
        """
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            # Set keepalive to maintain connection
            client.connect(
                host, 
                port=port,
                username=username, 
                password=password, 
                timeout=30
            )
            
            # Test the connection
            transport = client.get_transport()
            transport.set_keepalive(30)  # Send keepalive every 30 seconds
            
            with self.lock:
                self.connection_counter += 1
                connection_id = f"ssh_{self.connection_counter}"
                
                self.connections[connection_id] = {
                    "client": client,
                    "host": host,
                    "username": username,
                    "port": port,
                    "last_used": time.time(),
                    "connected_at": time.time()
                }
            
            logger.info(f"Established persistent SSH connection {connection_id} to {username}@{host}:{port}")
            
            return {
                "success": True,
                "connection_id": connection_id,
                "host": host,
                "username": username,
                "port": port,
                "message": f"Successfully connected to {username}@{host}:{port}"
            }
            
        except paramiko.AuthenticationException:
            logger.error(f"SSH authentication failed for {username}@{host}:{port}")
            return {"success": False, "error": "SSH authentication failed"}
        except paramiko.SSHException as ssh_ex:
            logger.error(f"SSH connection error to {host}:{port}: {str(ssh_ex)}")
            return {"success": False, "error": f"SSH connection error: {str(ssh_ex)}"}
        except Exception as e:
            logger.error(f"Error establishing SSH connection to {host}:{port}: {str(e)}")
            return {"success": False, "error": f"Connection error: {str(e)}"}
    
    def disconnect(self, connection_id: str) -> Dict[str, Any]:
        """
        Close a specific SSH connection.
        
        Args:
            connection_id: The ID of the connection to close
            
        Returns:
            Dictionary with disconnection status
        """
        with self.lock:
            if connection_id not in self.connections:
                return {"success": False, "error": f"Connection {connection_id} not found"}
            
            try:
                connection_info = self.connections[connection_id]
                client = connection_info["client"]
                client.close()
                
                host = connection_info["host"]
                username = connection_info["username"]
                
                del self.connections[connection_id]
                
                logger.info(f"Disconnected SSH connection {connection_id} ({username}@{host})")
                
                return {
                    "success": True,
                    "connection_id": connection_id,
                    "message": f"Successfully disconnected from {username}@{host}"
                }
                
            except Exception as e:
                logger.error(f"Error disconnecting SSH connection {connection_id}: {str(e)}")
                # Still remove from connections dict even if close failed
                if connection_id in self.connections:
                    del self.connections[connection_id]
                return {"success": False, "error": f"Error during disconnection: {str(e)}"}
    
    def disconnect_all(self) -> Dict[str, Any]:
        """
        Close all SSH connections.
        
        Returns:
            Dictionary with disconnection status
        """
        with self.lock:
            disconnected_count = 0
            errors = []
            
            connection_ids = list(self.connections.keys())
            
            for connection_id in connection_ids:
                try:
                    result = self.disconnect(connection_id)
                    if result["success"]:
                        disconnected_count += 1
                    else:
                        errors.append(f"{connection_id}: {result['error']}")
                except Exception as e:
                    errors.append(f"{connection_id}: {str(e)}")
            
            logger.info(f"Disconnected {disconnected_count} SSH connections")
            
            return {
                "success": len(errors) == 0,
                "disconnected_count": disconnected_count,
                "errors": errors,
                "message": f"Disconnected {disconnected_count} connections" + (f" with {len(errors)} errors" if errors else "")
            }
    
    def execute_command(self, connection_id: str, command: str, timeout: int = 30) -> Dict[str, Any]:
        """
        Execute a command through a persistent SSH connection.
        
        Args:
            connection_id: The ID of the SSH connection to use
            command: The command to execute
            timeout: Command timeout in seconds
            
        Returns:
            Dictionary with command execution results
        """
        with self.lock:
            if connection_id not in self.connections:
                return {"success": False, "error": f"SSH connection {connection_id} not found"}
            
            connection_info = self.connections[connection_id]
            client = connection_info["client"]
            
            # Update last used time
            connection_info["last_used"] = time.time()
        
        try:
            # Check if connection is still alive
            transport = client.get_transport()
            if not transport or not transport.is_active():
                with self.lock:
                    if connection_id in self.connections:
                        del self.connections[connection_id]
                return {"success": False, "error": f"SSH connection {connection_id} is no longer active"}
            
            logger.info(f"Executing command on SSH connection {connection_id}: {command[:100]}...")
            
            stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            
            output_stdout = stdout.read().decode(errors='replace')
            output_stderr = stderr.read().decode(errors='replace') 
            exit_status = stdout.channel.recv_exit_status()
            
            logger.debug(f"SSH command on {connection_id} completed with exit status: {exit_status}")
            
            return {
                "success": True,
                "connection_id": connection_id,
                "command": command,
                "stdout": output_stdout,
                "stderr": output_stderr,
                "return_code": exit_status,
                "command_success": exit_status == 0
            }
            
        except Exception as e:
            logger.error(f"Error executing command on SSH connection {connection_id}: {str(e)}")
            return {"success": False, "error": f"Command execution error: {str(e)}"}
    
    def get_connections_status(self) -> Dict[str, Any]:
        """
        Get status of all active SSH connections.
        
        Returns:
            Dictionary with connection status information
        """
        with self.lock:
            status = {
                "active_connections": len(self.connections),
                "connections": {}
            }
            
            current_time = time.time()
            
            for conn_id, conn_info in self.connections.items():
                try:
                    transport = conn_info["client"].get_transport()
                    is_active = transport and transport.is_active()
                    
                    status["connections"][conn_id] = {
                        "host": conn_info["host"],
                        "username": conn_info["username"],
                        "port": conn_info["port"],
                        "connected_at": conn_info["connected_at"],
                        "last_used": conn_info["last_used"],
                        "idle_time": current_time - conn_info["last_used"],
                        "is_active": is_active
                    }
                except Exception as e:
                    status["connections"][conn_id] = {
                        "host": conn_info.get("host", "unknown"),
                        "username": conn_info.get("username", "unknown"),
                        "error": str(e),
                        "is_active": False
                    }
            
            return status

# Global SSH connection manager instance
ssh_manager = SSHConnectionManager()

class CommandExecutor:
    """
    Handles the execution of shell commands with improved timeout management and non-blocking output reading.
    This class uses threading to read stdout and stderr streams continuously, preventing deadlocks
    that can occur with subprocess.communicate() on long-running commands or commands that produce
    a lot of output.
    """
    
    def __init__(self, command: str, timeout: int = COMMAND_TIMEOUT, workdir: str = None, stdin_input: str = None):
        """
        Initialize the CommandExecutor.

        Args:
            command: The shell command string to be executed.
            timeout: The maximum time (in seconds) to wait for the command to complete.
            workdir: Optional working directory to execute the command in.
            stdin_input: Optional text to pipe into the command's STDIN.
        """
        self.command = command
        self.timeout = timeout
        self.workdir = workdir
        self.stdin_input = stdin_input
        self.process = None
        self.stdout_data = ""
        self.stderr_data = ""
        self.stdout_thread = None
        self.stderr_thread = None
        self.return_code = None
        self.timed_out = False
    
    def _read_stdout(self):
        """Thread target function to continuously read lines from the process's stdout."""
        try:
            for line in iter(self.process.stdout.readline, ''):
                self.stdout_data += line
        except Exception as e:
            logger.debug(f"Exception in _read_stdout thread: {e}")
        finally:
            if self.process and self.process.stdout:
                self.process.stdout.close()
    
    def _read_stderr(self):
        """Thread target function to continuously read lines from the process's stderr."""
        try:
            for line in iter(self.process.stderr.readline, ''):
                self.stderr_data += line
        except Exception as e:
            logger.debug(f"Exception in _read_stderr thread: {e}")
        finally:
            if self.process and self.process.stderr:
                self.process.stderr.close()
    
    def execute(self) -> Dict[str, Any]:
        """
        Execute the command, manage its lifecycle (start, wait, timeout, terminate/kill),
        and collect its output and status.

        Returns:
            A dictionary containing:
                - "stdout": The standard output of the command.
                - "stderr": The standard error of the command.
                - "return_code": The exit code of the command (-1 if timed out or other error).
                - "success": Boolean indicating if the command likely succeeded (return code 0, or timed out with output).
                - "timed_out": Boolean indicating if the command execution timed out.
                - "partial_results": Boolean indicating if partial results might be available (true if timed out with some output).
        """
        logger.info(f"Executing command: '{self.command}' with timeout: {self.timeout}s")
        
        try:
            # Prepare the command execution environment
            popen_kwargs = {
                "shell": True,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "text": True,
                "bufsize": 1
            }
            
            # Set working directory if specified
            if self.workdir:
                if os.path.isdir(self.workdir):
                    popen_kwargs["cwd"] = self.workdir
                    logger.debug(f"Executing command in working directory: {self.workdir}")
                else:
                    logger.warning(f"Working directory does not exist: {self.workdir}")
            
            # Add stdin pipe if we have input to send
            if self.stdin_input:
                popen_kwargs["stdin"] = subprocess.PIPE
            
            self.process = subprocess.Popen(self.command, **popen_kwargs)
            
            self.stdout_thread = threading.Thread(target=self._read_stdout)
            self.stderr_thread = threading.Thread(target=self._read_stderr)
            self.stdout_thread.daemon = True
            self.stderr_thread.daemon = True
            self.stdout_thread.start()
            self.stderr_thread.start()
            
            # Send stdin input if provided
            if self.stdin_input and self.process.stdin:
                try:
                    self.process.stdin.write(self.stdin_input)
                    self.process.stdin.close()
                    logger.debug(f"Sent {len(self.stdin_input)} characters to stdin")
                except Exception as e:
                    logger.warning(f"Failed to write to stdin: {e}")
            
            try:
                self.return_code = self.process.wait(timeout=self.timeout)
                self.stdout_thread.join(timeout=5)
                self.stderr_thread.join(timeout=5)
            except subprocess.TimeoutExpired:
                self.timed_out = True
                logger.warning(f"Command '{self.command}' timed out after {self.timeout} seconds. Terminating process.")
                
                self.process.terminate()
                try:
                    self.process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    logger.warning(f"Process for '{self.command}' did not terminate gracefully. Killing.")
                    self.process.kill()
                
                self.return_code = -1
                self.stdout_thread.join(timeout=5)
                self.stderr_thread.join(timeout=5)
            
            success = (self.return_code == 0) or (self.timed_out and (self.stdout_data or self.stderr_data))
            
            return {
                "stdout": self.stdout_data,
                "stderr": self.stderr_data,
                "return_code": self.return_code,
                "success": success,
                "timed_out": self.timed_out,
                "partial_results": self.timed_out and bool(self.stdout_data or self.stderr_data)
            }
        
        except Exception as e:
            logger.error(f"Error executing command '{self.command}': {str(e)}")
            logger.error(traceback.format_exc())
            return {
                "stdout": self.stdout_data,
                "stderr": f"Error executing command: {str(e)}\n{self.stderr_data}",
                "return_code": -1,
                "success": False,
                "timed_out": False,
                "partial_results": bool(self.stdout_data or self.stderr_data)
            }


def execute_command(command: str, workdir: str = None, stdin_input: str = None) -> Dict[str, Any]:
    """
    Wrapper function to execute a shell command using the CommandExecutor class.
    
    Args:
        command: The command string to execute.
        workdir: Optional working directory to execute the command in.
        stdin_input: Optional text to pipe into the command's STDIN.
        
    Returns:
        A dictionary containing the execution result (stdout, stderr, return_code, success, etc.).
    """
    executor = CommandExecutor(command, workdir=workdir, stdin_input=stdin_input)
    return executor.execute()


@app.route("/api/command", methods=["POST"])
def generic_command():
    """
    Flask API endpoint to execute an arbitrary shell command.
    Expects a JSON payload with a "command" key: {"command": "your command here"}
    """
    try:
        data = request.get_json()
        if not data or "command" not in data:
            logger.warning("Generic command endpoint called with missing 'command' in JSON payload.")
            return jsonify({"error": "JSON payload must contain a 'command' field"}), 400
        
        command = data.get("command", "")
        
        if not command:
            logger.warning("Command endpoint called with empty 'command' parameter.")
            return jsonify({"error": "'command' parameter cannot be empty"}), 400
        
        logger.info(f"Received request to execute generic command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in /api/command endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error processing command request: {str(e)}"}), 500


@app.route("/api/command/advanced", methods=["POST"])
def advanced_command():
    """
    Flask API endpoint to execute an arbitrary shell command with advanced options.
    Supports working directory, stdin input, SSH connection routing, and other advanced features.
    Expects a JSON payload: {"command": "...", "workdir": "...", "stdin": "...", "ssh_connection_id": "..."}
    """
    try:
        data = request.get_json()
        if not data or "command" not in data:
            logger.warning("Advanced command endpoint called with missing 'command' in JSON payload.")
            return jsonify({"error": "JSON payload must contain a 'command' field"}), 400
        
        command = data.get("command", "")
        workdir = data.get("workdir", "")
        stdin_input = data.get("stdin", "")
        ssh_connection_id = data.get("ssh_connection_id", "")
        
        if not command:
            logger.warning("Advanced command endpoint called with empty 'command' parameter.")
            return jsonify({"error": "'command' parameter cannot be empty"}), 400
        
        # Check if we should route this through an SSH connection
        if ssh_connection_id:
            logger.info(f"Routing command through SSH connection {ssh_connection_id}: {command}")
            result = ssh_manager.execute_command(ssh_connection_id, command, timeout=COMMAND_TIMEOUT)
            return jsonify(result)
        
        # Log the request with appropriate detail levels
        log_msg = f"Received advanced command request: {command}"
        if workdir:
            log_msg += f" (workdir: {workdir})"
        if stdin_input:
            log_msg += f" (stdin: {len(stdin_input)} chars)"
        logger.info(log_msg)
        
        # Execute the command locally with advanced options
        result = execute_command(command, workdir=workdir or None, stdin_input=stdin_input or None)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in /api/command/advanced endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error processing advanced command request: {str(e)}"}), 500


# SSH Connection Management Endpoints
@app.route("/api/ssh/connect", methods=["POST"])
def ssh_connect():
    """
    Flask API endpoint to establish a persistent SSH connection.
    Expects JSON payload: {"host": "...", "username": "...", "password": "...", "port": 22}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "JSON payload required"}), 400
        
        host = data.get("host", "")
        username = data.get("username", "")
        password = data.get("password", "")
        port = data.get("port", 22)
        
        if not all([host, username, password]):
            return jsonify({"error": "host, username, and password are required"}), 400
        
        result = ssh_manager.connect(host, username, password, port)
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in /api/ssh/connect endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/ssh/disconnect", methods=["POST"])
def ssh_disconnect():
    """
    Flask API endpoint to disconnect a specific SSH connection or all connections.
    Expects JSON payload: {"connection_id": "..."} or {"all": true}
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "JSON payload required"}), 400
        
        if data.get("all"):
            result = ssh_manager.disconnect_all()
        else:
            connection_id = data.get("connection_id", "")
            if not connection_id:
                return jsonify({"error": "connection_id is required (or use 'all': true)"}), 400
            result = ssh_manager.disconnect(connection_id)
        
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in /api/ssh/disconnect endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/ssh/status", methods=["GET"])  
def ssh_status():
    """
    Flask API endpoint to get status of all SSH connections.
    """
    try:
        result = ssh_manager.get_connections_status()
        return jsonify(result)
        
    except Exception as e:
        logger.error(f"Error in /api/ssh/status endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500


@app.route("/api/tools/nmap", methods=["POST"])
def nmap():
    """
    Flask API endpoint to execute an Nmap scan.
    Expects a JSON payload with Nmap parameters:
    { 
        "target": "<target_ip_or_host>", 
        "scan_type": "<nmap_scan_options_like_-sV>", 
        "ports": "<port_range_e.g._80,443>", 
        "additional_args": "<other_nmap_flags_e.g_-T4>"
    }
    """
    try:
        params = request.get_json()
        if not params:
            logger.warning("Nmap endpoint called with no JSON payload.")
            return jsonify({"error": "JSON payload required for Nmap scan"}), 400

        target = params.get("target", "")
        scan_type = params.get("scan_type", "-sCV")
        ports = params.get("ports", "")
        additional_args = params.get("additional_args", "-T4 -Pn")
        
        if not target:
            logger.warning("Nmap API called without 'target' parameter.")
            return jsonify({"error": "'target' parameter is required for Nmap scan"}), 400        
        
        command_parts = ["nmap", scan_type]
        
        if ports:
            command_parts.extend(["-p", ports])
        
        if additional_args:
            command_parts.append(additional_args)
        
        command_parts.append(target)
        command = " ".join(command_parts)
        
        logger.info(f"Received request to execute Nmap command: {command}")
        result = execute_command(command)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in /api/tools/nmap endpoint: {str(e)}")
        logger.error(traceback.format_exc())
        return jsonify({"error": f"Server error processing Nmap request: {str(e)}"}), 500

# Health check endpoint
@app.route("/health", methods=["GET"])
def health_check():
    """
    Flask API endpoint to check the health of the Kali API server.
    It also checks for the availability of essential command-line tools on the server.
    """
    logger.info("Health check requested.")
    essential_tools = ["nmap", "ssh"]
    tools_status = {}
    
    for tool in essential_tools:
        try:
            result = execute_command(f"which {tool}")
            tools_status[tool] = result["success"] and bool(result["stdout"])
        except Exception as e:
            logger.error(f"Error checking for tool '{tool}': {e}")
            tools_status[tool] = False
    
    all_essential_tools_available = all(tools_status.values())
    
    # Include SSH connection status in health check
    ssh_status = ssh_manager.get_connections_status()
    
    status_message = "healthy" if all_essential_tools_available else "degraded"
    if not all_essential_tools_available:
        logger.warning(f"Health check: Server is {status_message} due to missing essential tools.")

    return jsonify({
        "status": status_message,
        "message": f"Kali Linux Tools API Server is running. Essential tool status: {'All available' if all_essential_tools_available else 'Some missing'}",
        "tools_status": tools_status,
        "all_essential_tools_available": all_essential_tools_available,
        "ssh_connections": ssh_status
    })

@app.route("/mcp/capabilities", methods=["GET"])
def get_capabilities():
    # This endpoint is intended to return tool capabilities, similar to an existing MCP server.
    # Currently, it's not implemented and will return a 501 Not Implemented or similar if called as is.
    logger.warning("Placeholder endpoint /mcp/capabilities called.")
    return jsonify({"message": "Endpoint not yet implemented: /mcp/capabilities"}), 501

@app.route("/mcp/tools/kali_tools/<tool_name>", methods=["POST"])
def execute_tool(tool_name):
    # This endpoint is intended for direct tool execution, potentially bypassing the /api/tools/* structure.
    # It's not implemented and needs a handler for different 'tool_name' values.
    logger.warning(f"Placeholder endpoint /mcp/tools/kali_tools/{tool_name} called.")
    return jsonify({"message": f"Endpoint not yet implemented: /mcp/tools/kali_tools/{tool_name}"}), 501

def parse_args():
    """
    Parse command line arguments for the Kali API server script.
    Allows configuration of the listening port and debug mode.
    """
    parser = argparse.ArgumentParser(description="Run the Kali Linux API Server")
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode and verbose logging")
    parser.add_argument("--port", type=int, default=API_PORT, 
                      help=f"Port for the API server (default: {API_PORT}, or from API_PORT env var)")
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    # Apply command line arguments to global configuration
    effective_debug_mode = DEBUG_MODE or args.debug
    effective_api_port = args.port
    
    if effective_debug_mode:
        # Set Flask debug mode and logging level if debug is enabled
        os.environ["DEBUG_MODE"] = "1"
        logger.setLevel(logging.DEBUG)
        logger.info("Debug mode enabled.")
    else:
        logger.info("Running in production mode (debug disabled).")
    
    if args.port != API_PORT and args.port is not None:
        logger.info(f"Overriding API port with command line argument: {args.port}")
        effective_api_port = args.port
    else:
        effective_api_port = API_PORT

    logger.info(f"Starting Kali Linux Tools API Server on host 0.0.0.0, port {effective_api_port}")
    app.run(host="0.0.0.0", port=effective_api_port, debug=effective_debug_mode)
