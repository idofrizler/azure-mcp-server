#!/usr/bin/env python

import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import dotenv
from mcp.server.fastmcp import FastMCP
from azure.identity import DeviceCodeCredential, DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient

dotenv.load_dotenv()
mcp = FastMCP("Azure Resource MCP")

@dataclass
class AzureConfig:
    subscription_id: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None

config = AzureConfig(
    subscription_id=os.environ.get("AZURE_SUBSCRIPTION_ID", ""),
    tenant_id=os.environ.get("AZURE_TENANT_ID", None),
    client_id=os.environ.get("AZURE_CLIENT_ID", None),
    client_secret=os.environ.get("AZURE_CLIENT_SECRET", None)
)

def get_resource_client() -> ResourceManagementClient:
    """Get an Azure Resource Management client using appropriate authentication."""
    if config.client_id and config.client_secret and config.tenant_id:
        # Use client secret authentication if credentials are provided
        credential = ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret
        )
    elif config.tenant_id:
        credential = DeviceCodeCredential(tenant_id=config.tenant_id)
    else:
        # If no tenant ID is provided, try DefaultAzureCredential which includes device code flow
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
    
    return ResourceManagementClient(
        credential=credential,
        subscription_id=config.subscription_id
    )

@mcp.tool(description="Lists all resources in the Azure subscription, optionally filtered by resource group.")
async def list_resources(resource_group: str) -> List[Dict[str, Any]]:
    """List Azure resources, optionally filtered by resource group."""
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")
    
    client = get_resource_client()
    if resource_group:
        resources = client.resources.list_by_resource_group(resource_group)
    else:
        resources = client.resources.list()
    
    return [
        {
            "id": resource.id,
            "name": resource.name,
            "type": resource.type,
            "location": resource.location,
            "tags": resource.tags or {},
            "properties": resource.properties
        }
        for resource in resources
    ]

@mcp.tool(description="Lists all resource groups in the Azure subscription.")
async def list_resource_groups() -> List[Dict[str, Any]]:
    """List all resource groups in the Azure subscription."""
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")
    
    client = get_resource_client()
    resource_groups = client.resource_groups.list()
    
    return [
        {
            "id": group.id,
            "name": group.name,
            "location": group.location,
            "tags": group.tags or {},
            "properties": group.properties
        }
        for group in resource_groups
    ]

if __name__ == "__main__":
    print(f"Starting Azure Resource MCP Server...")
    mcp.run()
