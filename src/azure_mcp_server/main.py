#!/usr/bin/env python
import sys
import dotenv
from azure_mcp_server.server import mcp, config

def setup_environment():
    if dotenv.load_dotenv():
        print("Loaded environment variables from .env file")
    else:
        print("No .env file found or could not load it - using environment variables")

    if not config.subscription_id:
        print("ERROR: AZURE_SUBSCRIPTION_ID environment variable is not set")
        print("Please set it to your Azure subscription ID")
        return False

    print(f"Azure configuration:")
    print(f"  Subscription ID: {config.subscription_id}")
    if config.tenant_id:
        print(f"  Tenant ID: {config.tenant_id}")
    
    # Show authentication method
    if config.client_id and config.client_secret and config.tenant_id:
        print(f"  Authentication: Using client credentials")
    elif config.tenant_id:
        print(f"  Authentication: Using device code authentication")
        print("\nNOTE: When prompted, please authenticate using the device code at https://microsoft.com/devicelogin")
    else:
        print(f"  Authentication: Using DefaultAzureCredential")
    
    return True

def run_server():
    """Main entry point for the Azure Resource MCP Server"""
    # Setup environment
    if not setup_environment():
        sys.exit(1)
    
    print("\nStarting Azure Resource MCP Server...")
    print("Running server in standard mode...")
    
    # Run the server with the stdio transport
    mcp.run(transport="stdio")

if __name__ == "__main__":
    run_server()
