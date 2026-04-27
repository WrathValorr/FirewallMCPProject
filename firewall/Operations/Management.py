import subprocess
import socket

from .Utility import audit_log, validate_ip, rule_exists, is_admin, ps_quote

def _create_block_rule(rule_name: str, ip_address: str, direction: str) -> tuple[bool, str]:
    # Returns (success, message) so the caller can track each rule separately.
    # Skip if this exact rule name already exists.
    if rule_exists(rule_name):
        return True, f"Already exists: {rule_name}"

    # Build the PowerShell command for a single direction.
    command = [
        "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command",
        f"New-NetFirewallRule -DisplayName '{ps_quote(rule_name)}' -Direction {direction} -Action Block -RemoteAddress {ip_address} -ErrorAction Stop"
    ]

    try:
        subprocess.run(command, capture_output=True, text=True, check=True)
        return True, f"Created: {rule_name}"
    except subprocess.CalledProcessError as e:
        stderr = (e.stderr or "").strip()
        if "Access is denied" in stderr or "UnauthorizedAccessException" in stderr:
            return False, "Access Denied. Please run as Administrator."
        return False, f"Failed: {stderr}"


def block_ip(ip_address: str, direction: str = "Inbound") -> str:
    # First check we are running as admin. You can't change the firewall without it.
    if not is_admin():
        audit_log("BLOCK_IP", ip_address, False)
        return "ERROR: Admin privileges required. Run as Administrator."

    # Make sure the user actually gave us a real IP address.
    ok, msg = validate_ip(ip_address)
    if not ok:
        audit_log("BLOCK_IP", ip_address, False)
        return msg

    # Clean up the direction input. Accept any casing like "inbound", "OUTBOUND".
    direction = direction.strip().capitalize()
    if direction not in ("Inbound", "Outbound", "Both"):
        return "ERROR: direction must be 'Inbound', 'Outbound', or 'Both'."

    # Work out which rules we need to make.
    # Inbound keeps the old name MCP_Block_<ip> so existing tools keep working.
    # Outbound gets an _Out suffix so it doesn't clash with the inbound rule.
    rules_to_make = []
    if direction in ("Inbound", "Both"):
        rules_to_make.append(("Inbound", f"MCP_Block_{ip_address}"))
    if direction in ("Outbound", "Both"):
        rules_to_make.append(("Outbound", f"MCP_Block_{ip_address}_Out"))

    # Try to make each rule and collect results.
    messages, any_fail = [], False
    for dir_name, rule_name in rules_to_make:
        ok_rule, msg_rule = _create_block_rule(rule_name, ip_address, dir_name)
        if not ok_rule:
            any_fail = True
        messages.append(f"[{dir_name}] {msg_rule}")

    # Log once per call, marking success only if every rule succeeded.
    audit_log("BLOCK_IP", f"{ip_address} ({direction})", not any_fail)

    # Give back a combined report. If only one rule was asked for, the report is still clear.
    header = f"Block {ip_address} ({direction}):"
    return header + "\n" + "\n".join(messages)

def block_multiple_ips(ip_list: str, confirmation: str, direction: str = "Inbound") -> str:
    if confirmation != "CONFIRM_BLOCK_MANY":
        return f"ERROR: Must provide confirmation=CONFIRM_BLOCK_MANY to proceed"

    if not is_admin():
        audit_log("BLOCK_MANY", "BATCH", False)
        return "ERROR: Admin privileges required. Run as Administrator."

    ips = sorted({ip.strip() for ip in ip_list.split(",") if ip.strip()})
    if not ips:
        return "ERROR: No IPs provided."
    # Cap at 10 so people can't lock up the system with a huge list.
    if len(ips) > 10:
        return "ERROR: Too many IPs (max 10 per request)."

    results, success_count, fail_count = [], 0, 0
    for ip in ips:
        result = block_ip(ip, direction)
        if "Failed:" in result or "Access Denied" in result or result.startswith("ERROR"):
            fail_count += 1
        else:
            success_count += 1
        results.append(f"{ip}: {result}")

    summary = f"\n--- Summary ---\nSuccess: {success_count} | Failed: {fail_count}\n\n"
    return summary + "\n".join(results)


def block_website_ips(domain: str, direction: str = "Outbound") -> str:
    # Admin check first. No firewall edits without admin.
    if not is_admin():
        audit_log("BLOCK_WEB_IPS", domain, False)
        return "ERROR: Admin privileges required. Run as Administrator."

    # Clean up the input. Strip spaces and any http(s):// prefix the user might paste.
    domain = domain.strip().lower()
    for prefix in ("https://", "http://"):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    # Drop anything after the first slash  so we only have the host.
    domain = domain.split("/")[0]

    if not domain:
        return "ERROR: No domain provided."

    # Ask the OS to resolve the domain to every IP it knows about.
    try:
        results = socket.getaddrinfo(domain, None)
    except socket.gaierror as e:
        audit_log("BLOCK_WEB_IPS", domain, False)
        return f"ERROR: Could not resolve '{domain}': {e}"

    # Pull just the IPv4 addresses. Use a set so duplicates drop out.
    ips = sorted({sockaddr[0] for family, _, _, _, sockaddr in results
                  if family == socket.AF_INET})

    if not ips:
        return f"ERROR: No IPv4 addresses found for {domain}."

    # Block each IP one at a time. 
    results_out, ok, fail = [], 0, 0
    for ip in ips:
        r = block_ip(ip, direction)
        if "Failed:" in r or "Access Denied" in r or r.startswith("ERROR"):
            fail += 1
        else:
            ok += 1
        results_out.append(f"{ip}: {r}")

    audit_log("BLOCK_WEB_IPS", f"{domain} ({len(ips)} IPs)", fail == 0)

    # Build the report.
    summary = (f"\n--- Blocked IPs for {domain} ---\n"
               f"Resolved {len(ips)} IP(s) | Success: {ok} | Failed: {fail}\n\n")
    return summary + "\n".join(results_out)

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
