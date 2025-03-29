#!/bin/bash
set -e

# Output environment variables for debugging (excluding secrets)
echo "Starting Azure Resource MCP Server in Docker..."
echo "  Subscription ID: $AZURE_SUBSCRIPTION_ID"

# Run the MCP server
exec /app/.venv/bin/python -m azure_mcp_server.main "$@"
