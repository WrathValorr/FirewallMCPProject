import subprocess
from .Utility import audit_log, validate_ip, rule_exists, is_admin, ps_quote

def block_ip(ip_address: str) -> str:
    if not is_admin():
        audit_log("BLOCK_IP", ip_address, False)
        return "ERROR: Admin privileges required. Run as Administrator."

    ok, msg = validate_ip(ip_address)
    if not ok:
        audit_log("BLOCK_IP", ip_address, False)
        return msg

    rule_name = f"MCP_Block_{ip_address}"
    if rule_exists(rule_name):
        audit_log("BLOCK_IP", ip_address, True)
        return f"Already blocked: {rule_name}"

    command = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        f"New-NetFirewallRule -DisplayName '{ps_quote(rule_name)}' -Direction Inbound -Action Block -RemoteAddress {ip_address} -ErrorAction Stop"
    ]
    

    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        audit_log("BLOCK_IP", ip_address, True)
        return f"Successfully created Windows Firewall rule: {rule_name}"
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        audit_log("BLOCK_IP", ip_address, False)
        if "Access is denied" in stderr or "UnauthorizedAccessException" in stderr:
            return "ERROR: Access Denied. Please run as Administrator."
        return f"Failed to add rule: {stderr}"

def block_multiple_ips(ip_list: str, confirmation: str) -> str:
    if confirmation != "CONFIRM_BLOCK_MANY":
        return f"ERROR: Must provide confirmation=CONFIRM_BLOCK_MANY to proceed"

    if not is_admin():
        audit_log("BLOCK_MANY", "BATCH", False)
        return "ERROR: Admin privileges required. Run as Administrator."

    ips = sorted({ip.strip() for ip in ip_list.split(",") if ip.strip()})
    if not ips:
        return "ERROR: No IPs provided."
    if len(ips) > 200:
        return "ERROR: Too many IPs (max 200 per request)."

    results, success_count, fail_count = [], 0, 0
    for ip in ips:
        result = block_ip(ip)
        if result.startswith("Successfully") or result.startswith("Already blocked"):
            success_count += 1
        else:
            fail_count += 1
        results.append(f"{ip}: {result}")

    summary = f"\n--- Summary ---\nSuccess: {success_count} | Failed: {fail_count}\n\n"
    return summary + "\n".join(results)

def block_ip_port(ip_address: str, port: int, protocol: str = "TCP") -> str:
    if not is_admin():
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{protocol}", False)
        return "ERROR: Admin privileges required. Run as Administrator."

    ok, msg = validate_ip(ip_address)
    if not ok:
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{protocol}", False)
        return msg

    if port < 1 or port > 65535:
        return "ERROR: Invalid port number. Must be 1-65535"

    proto = protocol.upper()
    if proto not in ("TCP", "UDP"):
        return "ERROR: Protocol must be TCP or UDP"

    rule_name = f"MCP_Block_{ip_address}_Port_{port}_{proto}"
    if rule_exists(rule_name):
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{proto}", True)
        return f"Already blocked: {ip_address} on port {port} ({proto})"

    command = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        f"New-NetFirewallRule -DisplayName '{ps_quote(rule_name)}' -Direction Inbound -Action Block -Protocol {proto} -RemoteAddress {ip_address} -LocalPort {port} -ErrorAction Stop"
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{proto}", True)
        return f"Successfully blocked {ip_address} on port {port} ({proto})"
    except subprocess.CalledProcessError as e:
        audit_log("BLOCK_PORT", f"{ip_address}:{port}/{proto}", False)
        return f"Failed to block port: {(e.stderr or '').strip()}"

def remove_ip_block(ip_address: str) -> str:
    if not is_admin():
        audit_log("UNBLOCK_IP", ip_address, False)
        return "ERROR: Admin privileges required. Run as Administrator."

    ok, msg = validate_ip(ip_address)
    if not ok:
        audit_log("UNBLOCK_IP", ip_address, False)
        return msg

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
        if "Access is denied" in stderr or "UnauthorizedAccessException" in stderr:
            return "ERROR: Access Denied. Please run as Administrator."
        return f"Could not remove rule(s) for: {ip_address}"

def remove_all_blocks(confirmation: str) -> str:
    if confirmation != "CONFIRM_REMOVE_ALL":
        return f"ERROR: Must provide confirmation=CONFIRM_REMOVE_ALL to proceed"

    if not is_admin():
        audit_log("REMOVE_ALL", "ALL_RULES", False)
        return "ERROR: Admin privileges required. Run as Administrator."

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