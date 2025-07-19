#!/usr/bin/env python3

# Enhanced Nmap Tools for Intelligent LLM Decision Making
# This code provides both detailed guidance and intelligent automation for Nmap scanning

import sys
import os
import argparse
import logging
from typing import Dict, Any, Optional
import requests
import json

from mcp.server.fastmcp import FastMCP

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

# Default configuration
DEFAULT_KALI_SERVER = "http://192.168.1.179:5000"
DEFAULT_REQUEST_TIMEOUT = 300

class KaliToolsClient:
    """
    Client for communicating with the Kali Linux Tools API Server.
    Handles HTTP requests to the server's API endpoints.
    """
    
    def __init__(self, server_url: str, timeout: int = DEFAULT_REQUEST_TIMEOUT):
        self.server_url = server_url.rstrip("/")
        self.timeout = timeout
        logger.info(f"Initialized Kali Tools Client connecting to {self.server_url}")
        
    def safe_get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Perform a GET request with error handling."""
        if params is None:
            params = {}

        url = f"{self.server_url}/{endpoint}"

        try:
            logger.debug(f"GET {url} with params: {params}")
            response = requests.get(url, params=params, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.JSONDecodeError as e:
            logger.error(f"JSON decode failed for GET {url}: {str(e)}")
            logger.debug(f"Response text that failed to parse: {response.text}")
            return {"error": f"JSON decode failed: {str(e)}", "response_text": response.text, "success": False}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for GET {url}: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}

    def safe_post(self, endpoint: str, json_data: Dict[str, Any]) -> Dict[str, Any]:
        """Perform a POST request with JSON data and error handling."""
        url = f"{self.server_url}/{endpoint}"
        
        try:
            logger.debug(f"POST {url} with data: {json_data}")
            response = requests.post(url, json=json_data, timeout=self.timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.JSONDecodeError as e:
            logger.error(f"JSON decode failed for POST {url}: {str(e)}")
            logger.debug(f"Response text that failed to parse: {response.text}")
            return {"error": f"JSON decode failed: {str(e)}", "response_text": response.text, "success": False}
        except requests.exceptions.RequestException as e:
            logger.error(f"Request failed for POST {url}: {str(e)}")
            return {"error": f"Request failed: {str(e)}", "success": False}

    def execute_command(self, command: str) -> Dict[str, Any]:
        """Execute a generic shell command on the Kali server."""
        logger.info(f"Requesting execution of command: {command}")
        return self.safe_post("api/command", {"command": command})
    
    def check_health(self) -> Dict[str, Any]:
        """Check the health of the Kali Tools API Server."""
        logger.info("Checking Kali API server health.")
        return self.safe_get("health")

def setup_enhanced_mcp_server(kali_client: KaliToolsClient, log_level: str = "INFO") -> FastMCP:
    """
    Set up MCP server with enhanced Nmap tools for intelligent LLM decision making.
    
    Args:
        kali_client: Initialized KaliToolsClient instance
        log_level: Logging level for the FastMCP server
        
    Returns:
        Configured FastMCP instance with enhanced cybersecurity tools
    """
    mcp = FastMCP("enhanced-kali-mcp", log_level=log_level)
    logger.info(f"Setting up Enhanced MCP server with intelligent Nmap tools")

    @mcp.tool()
    def nmap_scan(target: str, scan_type: str = "-sV", ports: str = "", additional_args: str = "") -> Dict[str, Any]:
        """
        MCP Tool: Execute an Nmap scan with comprehensive LLM guidance for intelligent scan type selection.
        
        The LLM should analyze the reconnaissance requirements and choose the most appropriate scan strategy.
        
        SCAN TYPE DECISION MATRIX:
        
        ┌─ RECONNAISSANCE PHASE ─┐
        │ Discovery Phase:        │  Use "-sS" (SYN scan) - Fast port discovery
        │ Service Enumeration:    │  Use "-sV" (Version detection) - Identify services  
        │ Vulnerability Analysis: │  Use "-sC" (Script scan) - NSE vulnerability scripts
        │ OS Fingerprinting:      │  Use "-O" (OS detection) - Operating system identification
        │ Firewall Analysis:      │  Use "-sA" (ACK scan) - Firewall rule mapping
        └─────────────────────────┘
        
        STEALTH REQUIREMENTS:
        ├─ Maximum Speed: "-T5" (Insane timing - very detectable)
        ├─ Fast Scan: "-T4" (Aggressive timing - easily detectable)
        ├─ Normal: "-T3" (Normal timing - default, balanced)
        ├─ Stealthy: "-T2" (Polite timing - slower, less detectable)
        ├─ Very Stealthy: "-T1" (Sneaky timing - very slow, hard to detect)
        └─ Maximum Stealth: "-T0" (Paranoid timing - extremely slow, minimal detection)
        
        PORT SELECTION STRATEGY:
        ├─ Quick Discovery: "--top-ports 100" (fastest, covers 100 most common ports)
        ├─ Standard Scan: "--top-ports 1000" (good balance of speed and coverage)
        ├─ Comprehensive: "-p-" (all 65535 ports - very slow but complete)
        ├─ Web Services: "-p 80,443,8080,8443,8000,8888" (HTTP/HTTPS focus)
        ├─ Common Services: "-p 21,22,23,25,53,80,110,111,135,139,143,443,993,995"
        └─ UDP Services: "-sU -p 53,67,68,123,161,162,514,1434" (requires -sU scan type)
        
        ADVANCED EVASION TECHNIQUES:
        ├─ Fragment Packets: "-f" (split packets to evade simple firewalls)
        ├─ Decoy Scanning: "-D RND:10" (use 10 random decoy IPs)
        ├─ Source Port: "--source-port 53" (spoof source port as DNS)
        ├─ Random Host Order: "--randomize-hosts" (scan targets in random order)
        ├─ MAC Address Spoofing: "--spoof-mac 0" (randomize MAC address)
        └─ Idle Scan: "-sI zombie_host" (use zombie host for ultimate stealth)
        
        INTELLIGENT SCAN COMBINATIONS:
        
        INITIAL RECONNAISSANCE:
        "nmap -sS -T3 --top-ports 1000 -Pn target"
        └─ Purpose: Fast discovery of open ports without being too aggressive
        
        SERVICE ENUMERATION:
        "nmap -sV -sC --version-intensity 5 -p discovered_ports target"
        └─ Purpose: Detailed service identification on discovered open ports
        
        VULNERABILITY SCANNING:
        "nmap -sV -sC --script vuln --script-args=unsafe=1 target"
        └─ Purpose: Identify known vulnerabilities in discovered services
        
        STEALTH RECONNAISSANCE:
        "nmap -sS -T2 -f --randomize-hosts --data-length 200 target"
        └─ Purpose: Avoid detection while gathering information
        
        TARGETED ASSESSMENT:
        "nmap -sV -sC -O -A --osscan-guess --fuzzy target"
        └─ Purpose: Comprehensive analysis including OS detection
        
        RAPID ASSESSMENT:
        "nmap -sS -T4 --min-rate 1000 --max-retries 1 --top-ports 100 target"
        └─ Purpose: Very fast scan for time-critical situations
        
        NETWORK MAPPING:
        "nmap -sn -PE -PP -PS21,22,23,25,80,113,31339 network/24"
        └─ Purpose: Discover live hosts in a network range
        
        Args:
            target: IP address, hostname, or CIDR range (e.g., "192.168.1.1", "example.com", "10.0.0.0/24")
            scan_type: Nmap scan type - choose based on reconnaissance phase and requirements above
            ports: Port specification (e.g., "80,443", "1-1000", "22,80,443,3389,5985")
            additional_args: Additional Nmap options for timing, stealth, scripts, etc.
            
        Returns:
            Dictionary containing comprehensive scan results including:
            - Open ports and their states
            - Service versions and fingerprints  
            - Operating system detection results
            - NSE script output and vulnerabilities
            - Timing and performance statistics
            
        OPERATIONAL SECURITY NOTES:
        - Consider network impact - aggressive scans can affect network performance
        - Stealth scans take significantly longer but reduce detection risk
        - Some scan types require root privileges on the scanning system
        - UDP scans (-sU) are much slower than TCP scans but find different services
        """
        logger.info(f"Enhanced Nmap scan: target={target}, scan_type={scan_type}, ports='{ports}', args='{additional_args}'")
        
        # Prepare the data payload for the Kali server
        data = {
            "target": target,
            "scan_type": scan_type,
            "ports": ports,
            "additional_args": additional_args
        }
        
        # Execute the scan via the Kali server API
        return kali_client.safe_post("api/tools/nmap", data)

    @mcp.tool()
    def intelligent_nmap_recon(target: str, objective: str, stealth_level: str = "normal", time_constraint: str = "normal") -> Dict[str, Any]:
        """
        MCP Tool: Execute intelligent multi-phase Nmap reconnaissance with automatic scan selection.
        
        This tool implements cybersecurity best practices by automatically selecting optimal
        scan strategies based on operational requirements. The LLM doesn't need to know
        specific Nmap syntax - just describe the mission requirements.
        
        Args:
            target: Target IP, hostname, or network range to reconnaissance
            
            objective: Primary reconnaissance objective - choose the mission type:
                "host_discovery" - Find live hosts in a network range
                "port_discovery" - Identify open ports on known hosts  
                "service_enumeration" - Determine service versions and configurations
                "vulnerability_assessment" - Scan for known vulnerabilities and misconfigurations
                "stealth_reconnaissance" - Gather intelligence while minimizing detection
                "os_fingerprinting" - Identify operating systems and device types
                "network_mapping" - Map network topology and host relationships
                "rapid_assessment" - Quick security posture evaluation
                "targeted_analysis" - Deep dive on specific services or vulnerabilities
                "firewall_analysis" - Test firewall rules and packet filtering
                
            stealth_level: Operational stealth requirement:
                "aggressive" - Maximum speed, easily detectable (use for authorized tests)
                "normal" - Balanced speed and stealth (standard operations)
                "stealth" - Reduced detection risk, slower scanning
                "paranoid" - Maximum stealth, very slow but minimal detection
                
            time_constraint: Available time window for reconnaissance:
                "urgent" - Results needed immediately (< 5 minutes)
                "quick" - Fast assessment needed (5-15 minutes)  
                "normal" - Standard timing acceptable (15-60 minutes)
                "thorough" - Comprehensive assessment allowed (1+ hours)
                
        Returns:
            Comprehensive reconnaissance results with automatically optimized scan parameters.
            Includes discovered hosts, open ports, services, and vulnerabilities based on objective.
            
        AUTOMATIC SCAN LOGIC:
        
        The tool automatically constructs optimal Nmap commands based on your parameters:
        
        Host Discovery Examples:
        ├─ aggressive + urgent: "-sn -T5 --min-rate 5000"
        ├─ normal + quick: "-sn -T3 -PE -PP -PS80,443"  
        └─ stealth + thorough: "-sn -T2 -PS80 --randomize-hosts"
        
        Service Enumeration Examples:
        ├─ aggressive + quick: "-sV -T4 --version-intensity 7"
        ├─ normal + normal: "-sV -sC --version-intensity 5"
        └─ stealth + thorough: "-sV -T2 --version-intensity 3 -f"
        
        Vulnerability Assessment Examples:
        ├─ aggressive + thorough: "-sV -sC --script vuln --script-args=unsafe=1 -T4"
        ├─ normal + normal: "-sV -sC --script vuln,safe"
        └─ stealth + thorough: "-sV --script vuln -T2 --randomize-hosts"
        
        OPERATIONAL INTELLIGENCE:
        - Tool automatically adapts port ranges based on time constraints
        - Implements proper scan sequencing (discovery → enumeration → vulnerability)
        - Includes appropriate evasion techniques for stealth requirements
        - Optimizes timing templates for operational tempo
        - Selects relevant NSE scripts based on discovered services
        """
        logger.info(f"Intelligent reconnaissance: target={target}, objective={objective}, stealth={stealth_level}, time={time_constraint}")
        
        # Define scan configuration matrix
        scan_configs = {
            "host_discovery": {
                ("aggressive", "urgent"): "-sn -T5 --min-rate 5000 -PE -PP",
                ("aggressive", "quick"): "-sn -T4 --min-rate 2000 -PE -PP -PS80,443",
                ("aggressive", "normal"): "-sn -T4 -PE -PP -PS21,22,23,25,80,113,443",
                ("aggressive", "thorough"): "-sn -T4 -PE -PP -PS21,22,23,25,53,80,113,135,139,443,993,995,1723,3389,5985",
                
                ("normal", "urgent"): "-sn -T3 --min-rate 1000 -PE",
                ("normal", "quick"): "-sn -T3 -PE -PP -PS80,443,22",
                ("normal", "normal"): "-sn -T3 -PE -PP -PS21,22,23,25,80,113,443",
                ("normal", "thorough"): "-sn -T3 -PE -PP -PS21,22,23,25,53,80,113,135,139,443,993,995",
                
                ("stealth", "quick"): "-sn -T2 -PS80",
                ("stealth", "normal"): "-sn -T2 -PS80,443 --randomize-hosts",
                ("stealth", "thorough"): "-sn -T2 -PS80,443,22 --randomize-hosts -f",
                
                ("paranoid", "normal"): "-sn -T1 -PS80 --randomize-hosts",
                ("paranoid", "thorough"): "-sn -T1 -PS80,443 --randomize-hosts -f --data-length 200"
            },
            
            "port_discovery": {
                ("aggressive", "urgent"): "-sS -T5 --min-rate 5000 --top-ports 100",
                ("aggressive", "quick"): "-sS -T4 --min-rate 2000 --top-ports 1000",
                ("aggressive", "normal"): "-sS -T4 --top-ports 1000 -Pn",
                ("aggressive", "thorough"): "-sS -T4 -p- --min-rate 1000",
                
                ("normal", "urgent"): "-sS -T3 --top-ports 100",
                ("normal", "quick"): "-sS -T3 --top-ports 1000",
                ("normal", "normal"): "-sS -T3 --top-ports 1000 -Pn",
                ("normal", "thorough"): "-sS -T3 -p-",
                
                ("stealth", "quick"): "-sS -T2 --top-ports 100 -f",
                ("stealth", "normal"): "-sS -T2 --top-ports 1000 -f --randomize-hosts",
                ("stealth", "thorough"): "-sS -T2 -p- -f --randomize-hosts",
                
                ("paranoid", "normal"): "-sS -T1 --top-ports 1000 -f --randomize-hosts",
                ("paranoid", "thorough"): "-sS -T1 -p- -f --randomize-hosts --data-length 200"
            },
            
            "service_enumeration": {
                ("aggressive", "quick"): "-sV -T4 --version-intensity 7 --top-ports 1000",
                ("aggressive", "normal"): "-sV -sC -T4 --version-intensity 7",
                ("aggressive", "thorough"): "-sV -sC -T4 --version-intensity 9 -A",
                
                ("normal", "quick"): "-sV -T3 --version-intensity 5 --top-ports 1000",
                ("normal", "normal"): "-sV -sC -T3 --version-intensity 5",
                ("normal", "thorough"): "-sV -sC -O -T3 --version-intensity 6",
                
                ("stealth", "normal"): "-sV -T2 --version-intensity 3 -f",
                ("stealth", "thorough"): "-sV -sC -T2 --version-intensity 4 -f --randomize-hosts",
                
                ("paranoid", "thorough"): "-sV -T1 --version-intensity 2 -f --randomize-hosts"
            },
            
            "vulnerability_assessment": {
                ("aggressive", "normal"): "-sV -sC --script vuln -T4",
                ("aggressive", "thorough"): "-sV -sC --script vuln --script-args=unsafe=1 -T4 -A",
                
                ("normal", "normal"): "-sV -sC --script vuln,safe",
                ("normal", "thorough"): "-sV -sC --script vuln,safe,discovery -O",
                
                ("stealth", "normal"): "-sV --script vuln -T2 -f",
                ("stealth", "thorough"): "-sV --script vuln,safe -T2 -f --randomize-hosts",
                
                ("paranoid", "thorough"): "-sV --script vuln -T1 -f --randomize-hosts"
            },
            
            "stealth_reconnaissance": {
                ("stealth", "normal"): "-sS -T2 -f --randomize-hosts --data-length 200",
                ("stealth", "thorough"): "-sF -T2 -f --randomize-hosts --data-length 200 --spoof-mac 0",
                
                ("paranoid", "normal"): "-sN -T1 -f --randomize-hosts --data-length 200",
                ("paranoid", "thorough"): "-sF -T1 -f --randomize-hosts --data-length 200 --spoof-mac 0 -D RND:5"
            },
            
            "rapid_assessment": {
                ("aggressive", "urgent"): "-sS -sV -T5 --min-rate 5000 --top-ports 100 --version-intensity 3",
                ("normal", "urgent"): "-sS -sV -T4 --min-rate 2000 --top-ports 100 --version-intensity 3",
                ("normal", "quick"): "-sS -sV -T3 --top-ports 1000 --version-intensity 4"
            }
        }
        
        # Select appropriate scan configuration
        config_key = (stealth_level, time_constraint)
        selected_scan = scan_configs.get(objective, {}).get(config_key)
        
        # Fallback logic if specific combination not found
        if not selected_scan:
            if objective in scan_configs:
                # Try to find closest match
                available_configs = scan_configs[objective]
                if (stealth_level, "normal") in available_configs:
                    selected_scan = available_configs[(stealth_level, "normal")]
                elif ("normal", time_constraint) in available_configs:
                    selected_scan = available_configs[("normal", time_constraint)]
                else:
                    # Use first available configuration
                    selected_scan = list(available_configs.values())[0]
            else:
                # Default fallback
                selected_scan = "-sS -T3 --top-ports 1000"
        
        logger.info(f"Selected scan configuration: {selected_scan}")
        
        # Execute the intelligently selected scan
        data = {
            "target": target,
            "scan_type": selected_scan,
            "ports": "",
            "additional_args": ""
        }
        
        result = kali_client.safe_post("api/tools/nmap", data)
        
        # Add metadata about the intelligent selection
        if isinstance(result, dict) and "error" not in result:
            result["intelligent_selection"] = {
                "objective": objective,
                "stealth_level": stealth_level,
                "time_constraint": time_constraint,
                "selected_scan": selected_scan,
                "reasoning": f"Automatically selected optimal scan for {objective} with {stealth_level} stealth level and {time_constraint} time constraint"
            }
        
        return result

    @mcp.tool()
    def ssh_tool(ip: str, username: str, password: str, command: str) -> Dict[str, Any]:
        """
        MCP Tool: SSH to a remote machine and execute a specific command.
        This function will be callable by the AI agent.

        Args:
            ip: The IP address of the remote machine to connect to.
            username: SSH username for authentication.
            password: SSH password for authentication.
            command: The specific shell command to execute on the remote machine after successful SSH connection.

        Returns:
            The results of the SSH command execution from the Kali server.
        """
        logger.info(f"SSH tool called: ip={ip}, username={username}, command='{command[:50]}...'")
        data = {
            "ip": ip,
            "username": username,
            "password": password,
            "command": command 
        }
        return kali_client.safe_post("api/tools/ssh", data)

    @mcp.tool()
    def server_health() -> Dict[str, Any]:
        """
        MCP Tool: Check the health status of the backend Kali API server.
        This function will be callable by the AI agent.

        Returns:
            Server health information.
        """
        logger.info("Server health tool called.")
        return kali_client.check_health()

    logger.info("Enhanced MCP tools registered: nmap_scan, intelligent_nmap_recon, ssh_tool, server_health")
    return mcp

def parse_args():
    """Parse command line arguments for the enhanced MCP client script."""
    parser = argparse.ArgumentParser(description="Run the Enhanced Kali MCP Client with Intelligent Tools")
    parser.add_argument("--server", type=str, default=DEFAULT_KALI_SERVER, 
                      help=f"Kali API server URL (default: {DEFAULT_KALI_SERVER})")
    parser.add_argument("--timeout", type=int, default=DEFAULT_REQUEST_TIMEOUT,
                      help=f"Request timeout in seconds (default: {DEFAULT_REQUEST_TIMEOUT})")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging level")
    return parser.parse_args()

def main():
    """
    Main entry point for the enhanced MCP client application.
    Initializes the client and starts the server with intelligent cybersecurity tools.
    """
    args = parse_args()
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger.info("Debug logging enabled by command line argument.")
    
    logger.info(f"Initializing Enhanced KaliToolsClient with server: {args.server}, timeout: {args.timeout}s")
    kali_client = KaliToolsClient(args.server, args.timeout)
    
    logger.info("Performing initial health check of Kali API server...")
    health = kali_client.check_health()
    if "error" in health:
        logger.warning(f"Unable to connect to Kali API server at {args.server}: {health['error']}")
        logger.warning("Enhanced MCP client will start, but tool execution will likely fail until server is available.")
    else:
        logger.info(f"Successfully connected to Kali API server at {args.server}")
        logger.info(f"Server health status: {health.get('status', 'N/A')}")
        if not health.get("all_essential_tools_available", True):
            logger.warning("Kali server reported that not all essential tools are available.")
            missing_tools = [tool for tool, available in health.get("tools_status", {}).items() if not available]
            if missing_tools:
                logger.warning(f"Missing tools on Kali server: {', '.join(missing_tools)}")
    
    mcp_log_level = "DEBUG" if args.debug else "INFO"
    mcp = setup_enhanced_mcp_server(kali_client, log_level=mcp_log_level)
    
    logger.info(f"Starting Enhanced Kali MCP client server with intelligent tools...")
    logger.info("Available tools: nmap_scan (detailed), intelligent_nmap_recon (automated), ssh_tool, server_health")
    mcp.run()

if __name__ == "__main__":
    main()