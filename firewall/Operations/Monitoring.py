import subprocess
from .Utility import validate_ip

def check_ip_block(ip_address: str) -> str:
    is_valid, error_msg = validate_ip(ip_address)
    if not is_valid:
        return error_msg

    rule_prefix = f"MCP_Block_{ip_address}"
    command = [
        "powershell", "-NoProfile", "-Command",
        f"Get-NetFirewallRule -DisplayName '{rule_prefix}*' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty DisplayName"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if names:
            return "IP is BLOCKED by rule(s):\n" + "\n".join(f"- {n}" for n in names)
        return f"IP {ip_address} is NOT blocked (no MCP rule found)"
    except subprocess.CalledProcessError:
        return f"IP {ip_address} is NOT blocked (no MCP rule found)"

def list_blocked_ips() -> str:
    command = [
        "powershell", "-NoProfile", "-Command",
        "Get-NetFirewallRule -DisplayName 'MCP_Block_*' -ErrorAction SilentlyContinue | "
        "Where-Object {$_.Enabled -eq 'True'} | "
        "Select-Object -ExpandProperty DisplayName"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        rules = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not rules:
            return "No IPs are currently blocked by MCP rules."
        return "Currently blocked (enabled) MCP rules:\n" + "\n".join(f"- {r}" for r in rules)
    except subprocess.CalledProcessError:
        return "No IPs are currently blocked by MCP rules."
    
def get_rule_details(ip_address: str) -> str:
    """Get detailed information about a specific firewall rule"""
    is_valid, error_msg = validate_ip(ip_address)
    if not is_valid:
        return error_msg
    
    rule_name = f"MCP_Block_{ip_address}"
    
    command = [
        "powershell", "-Command",
        f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue | Format-List DisplayName, Enabled, Direction, Action, CreationClassName"
    ]
    
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if result.stdout.strip():
            return f"Rule details for {ip_address}:\n{result.stdout}"
        else:
            return f"No rule found for {ip_address}"
    except subprocess.CalledProcessError:
        return f"No rule found for {ip_address}"