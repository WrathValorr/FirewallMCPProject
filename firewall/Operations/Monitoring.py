import subprocess
from .Utility import validate_ip

def check_ip_block(ip_address: str) -> str:
    # Make sure the IP is valid
    is_valid, error_msg = validate_ip(ip_address)
    if not is_valid:
        return error_msg

    # The star (*) at the end means "match any rule starting with this name".
    rule_prefix = f"MCP_Block_{ip_address}"
    command = [
        "powershell", "-NoProfile", "-Command",
        f"Get-NetFirewallRule -DisplayName '{rule_prefix}*' -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty DisplayName"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        # Split the output into one rule name per line and drop empty lines.
        names = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if names:
            return "IP is BLOCKED by rule(s):\n" + "\n".join(f"- {n}" for n in names)
        return f"IP {ip_address} is NOT blocked (no MCP rule found)"
    except subprocess.CalledProcessError:
        # PowerShell can't find the rule, which just means the IP isn't blocked.
        return f"IP {ip_address} is NOT blocked (no MCP rule found)"

def list_blocked_ips() -> str:
    # Pull every rule we made. The MCP_Block_* pattern keeps us out of other apps' rules.
    # Filtering by Enabled means disabled rules don't get reported as active blocks.
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
        # No matching rules at all. Same outcome as an empty list.
        return "No IPs are currently blocked by MCP rules."
    
def get_rule_details(ip_address: str) -> str:
    """Get detailed information about a specific firewall rule"""
    # Validate the IP first 
    is_valid, error_msg = validate_ip(ip_address)
    if not is_valid:
        return error_msg
    
    rule_name = f"MCP_Block_{ip_address}"

    # Format-List gives us all the useful fields one per line, instead of a cramped table.
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
    
def show_active_connections(protocol: str = "TCP", state: str = "ESTABLISHED") -> str:
    """
    Show active network connections, useful for detecting DDoS attacks.

    Args:
        protocol: TCP or UDP (default: TCP)
        state: Connection state. ESTABLISHED, LISTEN, TIME_WAIT, etc. (default: ESTABLISHED)
    """
    # Normalise the protocol so "tcp", "Tcp" and "TCP" all work.
    proto = protocol.upper()
    if proto not in ("TCP", "UDP"):
        return "ERROR: Protocol must be TCP or UDP"

    # Connection states only apply to TCP. UDP is stateless so the state value gets ignored.
    valid_states = ["ESTABLISHED", "LISTEN", "TIME_WAIT", "CLOSE_WAIT", "SYN_SENT", "SYN_RECEIVED"]
    state_upper = state.upper()

    if proto == "TCP":
        # TCP gets the full picture: local address, remote address, ports and the state.
        command = [
            "powershell", "-NoProfile", "-Command",
            f"Get-NetTCPConnection -State {state_upper} -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | "
            "Format-Table -AutoSize"
        ]
    else:
        # UDP just gives us listening endpoints. There's no remote side until something talks back.
        command = [
            "powershell", "-NoProfile", "-Command",
            "Get-NetUDPEndpoint -ErrorAction SilentlyContinue | "
            "Select-Object LocalAddress, LocalPort | "
            "Format-Table -AutoSize"
        ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        # PowerShell tables always have a header and a separator line.
        # So if we have 2 lines or fewer, there are no real results.
        if not output or len(output.splitlines()) <= 2:
            return f"No active {proto} connections in {state} state."
        return f"Active {proto} connections ({state}):\n\n{output}"
    except subprocess.CalledProcessError as e:
        return f"Failed to retrieve connections: {(e.stderr or '').strip()}"


def detect_connection_flood(threshold: int = 10) -> str:
    """
    Detect potential DDoS by finding IPs with excessive connections.

    Args:
        threshold: Minimum number of connections to flag an IP (default: 10)
    """
    # Group connections by their remote IP, then keep only the IPs over the threshold.
    # Sorting by Count descending puts the worst offenders at the top.
    command = [
        "powershell", "-NoProfile", "-Command",
        "Get-NetTCPConnection -State ESTABLISHED -ErrorAction SilentlyContinue | "
        "Group-Object RemoteAddress | "
        "Where-Object {$_.Count -ge " + str(threshold) + "} | "
        "Sort-Object Count -Descending | "
        "Select-Object @{Name='IP';Expression={$_.Name}}, Count | "
        "Format-Table -AutoSize"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout.strip()

        # Same trick as before. Header + separator = 2 lines, so anything at or below that is empty.
        if not output or len(output.splitlines()) <= 2:
            return f"No IPs found with {threshold}+ connections. System looks normal."

        # Subtract the 2 header lines from the total to get the real count of flagged IPs.
        lines = output.splitlines()
        suspicious_count = len(lines) - 2

        # Only show the warning banner if at least one IP was actually flagged.
        warning = "POTENTIAL DDOS DETECTED\n" if suspicious_count > 0 else ""
        return (f"{warning}IPs with {threshold}+ connections (threshold for concern):\n\n{output}\n\n"
                f"Total suspicious IPs: {suspicious_count}")
    except subprocess.CalledProcessError as e:
        return f"Failed to analyze connections: {(e.stderr or '').strip()}"


def analyze_remote_ips() -> str:
    """List every unique remote IP connected to the system, sorted by connection count."""
    # Same grouping idea as detect_connection_flood, but no threshold.
    # We want to see everything, not just the suspicious stuff.
    command = [
        "powershell", "-NoProfile", "-Command",
        "Get-NetTCPConnection -State ESTABLISHED -ErrorAction SilentlyContinue | "
        "Group-Object RemoteAddress | "
        "Sort-Object Count -Descending | "
        "Select-Object @{Name='IP';Expression={$_.Name}}, Count | "
        "Format-Table -AutoSize"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if not output or len(output.splitlines()) <= 2:
            return "No active remote connections found."
        return f"Remote IPs by connection count:\n\n{output}"
    except subprocess.CalledProcessError as e:
        return f"Failed to analyze remote IPs: {(e.stderr or '').strip()}"


def show_listening_ports() -> str:
    """Show all ports currently in LISTEN state along with the owning process."""
    # Pulls every port in LISTEN state and joins it to the process that owns it.
    # The OwningProcess field is just a PID, so we look up the actual process name with Get-Process.
    # Sorted by port number so the output reads naturally from low to high.
    command = [
        "powershell", "-NoProfile", "-Command",
        "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
        "Select-Object LocalAddress, LocalPort, "
        "@{Name='Process';Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | "
        "Sort-Object LocalPort | "
        "Format-Table -AutoSize"
    ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        output = result.stdout.strip()
        if not output or len(output.splitlines()) <= 2:
            return "No listening ports found."
        return f"Listening ports:\n\n{output}"
    except subprocess.CalledProcessError as e:
        return f"Failed to retrieve listening ports: {(e.stderr or '').strip()}"