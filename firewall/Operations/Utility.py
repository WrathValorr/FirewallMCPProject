import logging
import ctypes
import ipaddress
import subprocess

# Setup logging
logging.basicConfig(
    filename="firewall_audit.log",
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

def audit_log(action: str, ip_address: str, success: bool, user: str = "system"):
    """Log all firewall operations for security auditing"""
    logging.info(f"Action: {action} | IP: {ip_address} | Success: {success} | User: {user}")

def view_audit_log(lines: int = 20) -> str:
    """View the last N lines of the audit log"""
    try:
        with open("firewall_audit.log", 'r') as f:
            all_lines = f.readlines()
            last_lines = all_lines[-lines:]
            return ''.join(last_lines)
    except FileNotFoundError:
        return "No audit log found"
    except Exception as e:
        return f"Error reading log: {str(e)}"

def validate_ip(ip_address: str) -> tuple[bool, str]:
    """
    Validate IP address format.
    Returns: (is_valid, error_message)
    """
    try:
        ipaddress.ip_address(ip_address)
        return True, ""
    except ValueError:
        return False, f"ERROR: Invalid IP address format: {ip_address}"

def rule_exists(rule_name: str) -> bool:
    cmd = [
        "powershell", "-NoProfile", "-Command",
        f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue | Select-Object -First 1"
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    return bool(r.stdout.strip())

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def check_admin_privileges() -> str:
    return f"Running as Administrator: {is_admin()}"
    
def ps_quote(s: str) -> str:
    return s.replace("'", "''")