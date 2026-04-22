import subprocess
from .Utility import audit_log, validate_ip, rule_exists, is_admin, ps_quote

def block_ip(ip_address: str) -> str:
    # First check we are running as admin. You can't change the firewall without it.
    if not is_admin():
        audit_log("BLOCK_IP", ip_address, False)
        return "ERROR: Admin privileges required. Run as Administrator."

    # Make sure the user actually gave us a real IP address.
    ok, msg = validate_ip(ip_address)
    if not ok:
        audit_log("BLOCK_IP", ip_address, False)
        return msg

    # Build a rule name. All our rules start with MCP_Block_ so we can find them later.
    rule_name = f"MCP_Block_{ip_address}"
    # If this IP is already blocked, don't make a duplicate rule.
    if rule_exists(rule_name):
        audit_log("BLOCK_IP", ip_address, True)
        return f"Already blocked: {rule_name}"

    # Build the PowerShell command that creates a new firewall rule.
    # Direction Inbound = traffic coming in. Action Block = drop it.
    command = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        f"New-NetFirewallRule -DisplayName '{ps_quote(rule_name)}' -Direction Inbound -Action Block -RemoteAddress {ip_address} -ErrorAction Stop"
    ]


    try:
        # Run the command. check=True means it will error if PowerShell fails.
        subprocess.run(command, capture_output=True, text=True, check=True)
        audit_log("BLOCK_IP", ip_address, True)
        return f"Successfully created Windows Firewall rule: {rule_name}"
    except subprocess.CalledProcessError as e:
        # Something went wrong. Grab the error message from PowerShell.
        stderr = (e.stderr or "").strip()
        audit_log("BLOCK_IP", ip_address, False)
        # Handle the most common problem: not being admin.
        if "Access is denied" in stderr or "UnauthorizedAccessException" in stderr:
            return "ERROR: Access Denied. Please run as Administrator."
        return f"Failed to add rule: {stderr}"

def block_multiple_ips(ip_list: str, confirmation: str) -> str:
    # This can block lots of IPs at once, so we make the user confirm first.
    if confirmation != "CONFIRM_BLOCK_MANY":
        return f"ERROR: Must provide confirmation=CONFIRM_BLOCK_MANY to proceed"

    # Must be admin to change the firewall.
    if not is_admin():
        audit_log("BLOCK_MANY", "BATCH", False)
        return "ERROR: Admin privileges required. Run as Administrator."

    # Split the comma list into a set of IPs. Set removes duplicates. Sorted makes output tidy.
    ips = sorted({ip.strip() for ip in ip_list.split(",") if ip.strip()})
    if not ips:
        return "ERROR: No IPs provided."
    # Cap at 200 so people can't lock up the system with a huge list.
    if len(ips) > 200:
        return "ERROR: Too many IPs (max 200 per request)."

    # Keep score of how many worked and how many failed.
    results, success_count, fail_count = [], 0, 0
    for ip in ips:
        # Re-use the single-IP block function for each one.
        result = block_ip(ip)
        if result.startswith("Successfully") or result.startswith("Already blocked"):
            success_count += 1
        else:
            fail_count += 1
        results.append(f"{ip}: {result}")

    # Build a summary at the top and the full list below it.
    summary = f"\n--- Summary ---\nSuccess: {success_count} | Failed: {fail_count}\n\n"
    return summary + "\n".join(results)

def block_ip_port(ip_address: str, port: int, protocol: str = "TCP") -> str:
    # Admin check first.
    if not is_admin():
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{protocol}", False)
        return "ERROR: Admin privileges required. Run as Administrator."

    # Make sure the IP is valid.
    ok, msg = validate_ip(ip_address)
    if not ok:
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{protocol}", False)
        return msg

    # Ports only go from 1 to 65535. Anything else is not a real port.
    if port < 1 or port > 65535:
        return "ERROR: Invalid port number. Must be 1-65535"

    # Only TCP and UDP are supported. Turn the text upper case so "tcp" and "TCP" both work.
    proto = protocol.upper()
    if proto not in ("TCP", "UDP"):
        return "ERROR: Protocol must be TCP or UDP"

    # Rule name includes IP, port and protocol so we can tell rules apart.
    rule_name = f"MCP_Block_{ip_address}_Port_{port}_{proto}"
    # Skip making the rule again if it is already there.
    if rule_exists(rule_name):
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{proto}", True)
        return f"Already blocked: {ip_address} on port {port} ({proto})"

    # Same as block_ip but we add the Protocol and LocalPort parts to narrow the block.
    command = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        f"New-NetFirewallRule -DisplayName '{ps_quote(rule_name)}' -Direction Inbound -Action Block -Protocol {proto} -RemoteAddress {ip_address} -LocalPort {port} -ErrorAction Stop"
    ]

    try:
        # Run it. If it fails, we fall into the except block below.
        subprocess.run(command, capture_output=True, text=True, check=True)
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{proto}", True)
        return f"Successfully blocked {ip_address} on port {port} ({proto})"
    except subprocess.CalledProcessError as e:
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{proto}", False)
        return f"Failed to block port: {(e.stderr or '').strip()}"

def remove_ip_block(ip_address: str) -> str:
    # Need admin to delete firewall rules too.
    if not is_admin():
        audit_log("UNBLOCK_IP", ip_address, False)
        return "ERROR: Admin privileges required. Run as Administrator."

    # Check the IP is a real one before we touch anything.
    ok, msg = validate_ip(ip_address)
    if not ok:
        audit_log("UNBLOCK_IP", ip_address, False)
        return msg

    # The star (*) at the end means "delete any rule starting with this name".
    # So this removes the full-IP block and any port-specific blocks for that IP.
    rule_prefix = f"MCP_Block_{ip_address}"
    command = [
        "powershell", "-NoProfile", "-Command",
        f"Remove-NetFirewallRule -DisplayName '{ps_quote(rule_prefix)}*' -ErrorAction SilentlyContinue"
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        audit_log("UNBLOCK_IP", ip_address, True)
        return f"Successfully removed firewall rule(s) for {ip_address}."
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        audit_log("UNBLOCK_IP", ip_address, False)
        # Most common fail reason is not being admin. Give a clear message for that.
        if "Access is denied" in stderr or "UnauthorizedAccessException" in stderr:
            return "ERROR: Access Denied. Please run as Administrator."
        return f"Could not remove rule(s) for: {ip_address}"

def remove_all_blocks(confirmation: str) -> str:
    # This wipes every single rule we made, so force the user to confirm.
    if confirmation != "CONFIRM_REMOVE_ALL":
        return f"ERROR: Must provide confirmation=CONFIRM_REMOVE_ALL to proceed"

    # Must be admin.
    if not is_admin():
        audit_log("REMOVE_ALL", "ALL_RULES", False)
        return "ERROR: Admin privileges required. Run as Administrator."

    # The 'MCP_Block_*' pattern only matches rules our tool made.
    # Rules made by other programs are safe.
    command = [
        "powershell", "-NoProfile", "-Command",
        "Remove-NetFirewallRule -DisplayName 'MCP_Block_*' -ErrorAction SilentlyContinue"
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        audit_log("REMOVE_ALL", "ALL_RULES", True)
        return "Successfully removed all MCP firewall rules"
    except subprocess.CalledProcessError as e:
        audit_log("REMOVE_ALL", "ALL_RULES", False)
        return f"Failed to remove all rules: {(e.stderr or '').strip()}"
