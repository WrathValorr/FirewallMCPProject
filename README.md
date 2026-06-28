# Firewall MCP

An MCP server for automating Windows Defender Firewall rules, monitoring active connections, and spotting unusual traffic — all driven from an MCP client like Claude.

## How it works

1. **MCP Client** — The interface for users. Sends prompts and tool calls to the server.
2. **Python** — The backend for the MCP server. Handles the logic, validates input, and shells out to PowerShell.
3. **PowerShell** — Executes the actual commands against Windows Defender Firewall and returns the results back up the chain.

## Features

- Block and unblock IPs (Inbound, Outbound, or Both)
- Block specific IP + port + protocol combinations
- Block every IPv4 address behind a domain in one call
- Block multiple IPs at once (with confirmation, capped at 10)
- Wipe every rule the server has created (with confirmation)
- Check whether an IP is currently blocked
- List all rules created by this server
- Pull detailed info on a specific rule
- Show active TCP / UDP connections by state
- Detect connection floods with a configurable threshold
- List unique remote IPs sorted by connection count
- Show all listening ports along with the process that owns each one
- Built-in audit log of every action

## Project structure

The project is split across one entry point and three operation modules:

1. **`firewall.py`** — The MCP server entry point. Registers every tool and wires each one to the right logic function.
2. **`Operations/Management.py`** — Rule creation and deletion. This is where the blocking happens.
3. **`Operations/Monitoring.py`** — Reading the state of the firewall and the network: rule details, active connections, flood detection, listening ports.
4. **`Operations/Utility.py`** — Helpers used across the project: IP validation, admin checks, PowerShell quoting, and the audit logger.

## Requirements

- Windows 10 or 11 (the server uses Windows Defender Firewall via PowerShell, so it will not run on macOS or Linux)
- Python 3.10+
- `fastmcp`
- Administrator privileges — every rule change is rejected without them

## Setup

1. Clone the repo.
2. Install dependencies:
   ```
   pip install fastmcp
   ```
3. Add the server to your MCP client config, pointing it at `firewall.py`. Make sure the client (or whatever launches the server) is started **as Administrator**. Without admin rights, every block/remove call fails at the admin check.
4. Restart your MCP client and confirm the tools show up.

## Tools

| Tool | Purpose |
| --- | --- |
| `check_admin` | Confirm the server is running with admin rights. |
| `block_ip` | Block an IP (Inbound / Outbound / Both). |
| `remove_ip_block` | Remove rules for an IP. |
| `block_ip_port` | Block an IP on a specific port + protocol. |
| `block_multiple_ips` | Block up to 10 IPs in one call. Requires `confirmation='CONFIRM_BLOCK_MANY'`. |
| `block_website_ips` | Resolve a domain and block its IPv4 addresses. |
| `remove_all_blocks` | Wipe every rule this server has created. Requires `confirmation='CONFIRM_REMOVE_ALL'`. |
| `check_ip_block` | Check whether a specific IP is currently blocked. |
| `list_blocked_ips` | List all enabled rules created by this server. |
| `get_rule_details` | Show full details for a specific rule. |
| `view_audit_log` | View the last N lines of the audit log. |
| `show_active_connections` | List active TCP / UDP connections by state. |
| `detect_connection_flood` | Flag remote IPs above a connection-count threshold. |
| `analyze_remote_ips` | List unique remote IPs by connection count. |
| `show_listening_ports` | List every port in LISTEN state and the process that owns it. |

## Safety features

- **Admin check** on every operation that touches the firewall.
- **IP validation** before any rule is created.
- **Confirmation strings** for destructive batch operations (`CONFIRM_BLOCK_MANY`, `CONFIRM_REMOVE_ALL`).
- **Batch cap** — `block_multiple_ips` will not accept more than 10 IPs in one call.
- **Namespaced rules** — every rule is prefixed `MCP_Block_`, so the server only ever touches its own rules and leaves the rest of your firewall alone.
- **Audit log** at `firewall_audit.log` records every action with timestamp, IP, result, and user.

## Audit log

Every block, unblock, and bulk operation is appended to `firewall_audit.log` in the working directory. You can tail it directly, or pull the last N lines through the `view_audit_log` tool.
