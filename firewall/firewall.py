from fastmcp import FastMCP
from Operations.Management import (
    block_ip as block_ip_logic,
    remove_ip_block as remove_ip_block_logic,
    block_ip_port as block_ip_port_logic,
    block_multiple_ips as block_multiple_ips_logic,
    remove_all_blocks as remove_all_blocks_logic,
    block_website_ips as block_website_ips_logic,
)
from Operations.Monitoring import (
    check_ip_block as check_ip_block_logic,
    list_blocked_ips as list_blocked_ips_logic,
    get_rule_details as get_rule_details_logic,
    show_active_connections as show_active_connections_logic,
    detect_connection_flood as detect_connection_flood_logic,
    analyze_remote_ips as analyze_remote_ips_logic,
    show_listening_ports as show_listening_ports_logic,
)
from Operations.Utility import check_admin_privileges
from Operations.Utility import view_audit_log as view_audit_log_logic

mcp = FastMCP("NetworkSecurity")

# Utility Tools
@mcp.tool()
def check_admin() -> str:
    """Check if running with admin privileges."""
    return check_admin_privileges()

# Blocking Tools
@mcp.tool()
def block_ip(ip_address: str, direction: str = "Inbound") -> str:
    """Creates a Windows Defender Firewall rule to block an IP.
    direction: 'Inbound' (default), 'Outbound', or 'Both'."""
    return block_ip_logic(ip_address, direction)

@mcp.tool()
def remove_ip_block(ip_address: str) -> str:
    """Removes a previously created MCP firewall rule."""
    return remove_ip_block_logic(ip_address)

@mcp.tool()
def block_ip_port(ip_address: str, port: int, protocol: str = "TCP") -> str:
    """Block specific IP on a specific port and protocol (TCP/UDP)"""
    return block_ip_port_logic(ip_address, port, protocol)

@mcp.tool()
def block_multiple_ips(ip_list: str, confirmation: str, direction: str = "Inbound") -> str:
    """Block multiple IPs at once (comma-separated). Requires confirmation='CONFIRM_BLOCK_MANY'.
    direction: 'Inbound' (default), 'Outbound', or 'Both'."""
    return block_multiple_ips_logic(ip_list, confirmation, direction)

@mcp.tool()
def block_website_ips(domain: str, direction: str = "Outbound") -> str:
    """Resolve a domain and block its IPv4 addresses.
    direction: 'Outbound' (default - stops you reaching the site),
    'Inbound', or 'Both'."""
    return block_website_ips_logic(domain, direction)

@mcp.tool()
def remove_all_blocks(confirmation: str) -> str:
    """Remove ALL MCP firewall rules. Requires confirmation='CONFIRM_DELETE_ALL'"""
    return remove_all_blocks_logic(confirmation)

# Monitoring Tools
@mcp.tool()
def check_ip_block(ip_address: str) -> str:
    """Checks if an IP address is currently blocked."""
    return check_ip_block_logic(ip_address)

@mcp.tool()
def list_blocked_ips() -> str:
    """Lists all IP addresses currently blocked by MCP firewall rules."""
    return list_blocked_ips_logic()

@mcp.tool()
def get_rule_details(ip_address: str) -> str:
    """Get detailed information about a specific firewall rule"""
    return get_rule_details_logic(ip_address)

@mcp.tool()
def view_audit_log(lines: int = 20) -> str:
    """View the last N lines of the audit log"""
    return view_audit_log_logic(lines)

@mcp.tool()
def show_active_connections(protocol: str = "TCP", state: str = "ESTABLISHED") -> str:
    """Show active network connections. Useful for spotting unusual traffic.
    protocol: 'TCP' (default) or 'UDP'.
    state: 'ESTABLISHED' (default), 'LISTEN', 'TIME_WAIT', etc."""
    return show_active_connections_logic(protocol, state)

@mcp.tool()
def detect_connection_flood(threshold: int = 10) -> str:
    """Detect potential DDoS by finding remote IPs with excessive connections.
    threshold: Minimum connection count to flag an IP (default: 10)."""
    return detect_connection_flood_logic(threshold)

@mcp.tool()
def analyze_remote_ips() -> str:
    """List every unique remote IP connected to the system, sorted by connection count."""
    return analyze_remote_ips_logic()

@mcp.tool()
def show_listening_ports() -> str:
    """Show all ports currently in LISTEN state along with the owning process."""
    return show_listening_ports_logic()

# Main
if __name__ == "__main__":
    mcp.run()