# Using MCP to configure cybersecurity elements
In this case, using an MCP server to automate firewall rules, view rules and detect connections.

## How it works
1. MCP Client - Interface for users. Allowing them to input their prompts and delievering their requests.
2. Python - The backend for the MCP server. Responsible for handling the logic. Communicating with Powershell via Scripts.
3. Powershell - Executes the commands to interact with the Firewall and returns with results found.
   
## Structure
The project is categorized in three files. Management, Monitoring and Utility.

1. Management - Holds the logic that handles rule creation/deletion. (Blocking ips)
2. Monitoring - Logic for viewing rule details that were created by the MCP server. Has functionality for detecting connection floods too.
3. Utility - Helper functions that are used across the project.

   
