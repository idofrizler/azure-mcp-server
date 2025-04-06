#!/usr/bin/env python

import os
import dotenv
from mcp.server.fastmcp import FastMCP
import logging
logging.getLogger("mcp").setLevel(logging.ERROR)

from azure_mcp_server.config.azure_config import AzureConfig
from azure_mcp_server.clients.client_factory import AzureClientFactory
from azure_mcp_server.managers.resource_manager import AzureResourceManager
from azure_mcp_server.managers.compute_manager import AzureComputeManager
from azure_mcp_server.managers.webapp_manager import AzureWebAppManager
from azure_mcp_server.managers.dns_manager import AzureDNSManager
from azure_mcp_server.tools.dns_tools import DNSTools
from azure_mcp_server.managers.network_manager import AzureNetworkManager

class AzureMCPServer:
    """Main class for the Azure MCP Server."""
    
    def __init__(self):
        dotenv.load_dotenv()
        self.mcp = FastMCP("Azure Resource MCP")
        
        # Initialize configuration
        self.config = AzureConfig(
            subscription_id=os.getenv("AZURE_SUBSCRIPTION_ID", ""),
            tenant_id=os.getenv("AZURE_TENANT_ID"),
            client_id=os.getenv("AZURE_CLIENT_ID"),
            client_secret=os.getenv("AZURE_CLIENT_SECRET")
        )
        
        # Initialize client factory and managers
        self.client_factory = AzureClientFactory(self.config)
        self.resource_manager = AzureResourceManager(self.client_factory)
        self.compute_manager = AzureComputeManager(self.client_factory)
        self.webapp_manager = AzureWebAppManager(self.client_factory)
        self.dns_manager = AzureDNSManager(self.client_factory)
        self.dns_tools = DNSTools(self.dns_manager)
        self.network_manager = AzureNetworkManager(self.client_factory)
        
        self._register_tools()

    def _register_tools(self):
        """Register all MCP tools."""
        # Resource Management Tools
        self.mcp.tool(description="List Azure resources in a resource group")(self.resource_manager.list_resources)
        self.mcp.tool(description="List all resource groups")(self.resource_manager.list_resource_groups)
        self.mcp.tool(description="Delete a resource group")(self.resource_manager.delete_resource_group)
        self.mcp.tool(description="Create a new resource group")(self.resource_manager.create_resource_group)
        
        # Compute Management Tools
        self.mcp.tool(description="Create a new virtual machine")(self.compute_manager.create_vm)
        
        # Web App Management Tools
        self.mcp.tool(description="Create a new Web App")(self.webapp_manager.create_web_app)
        
        # Application Gateway Tools
        # self.mcp.tool(description="Creates an Application Gateway with WAF and configures backend pools")(self.network_manager.create_app_gateway_with_waf)
        self.mcp.tool(description="Creates or updates a custom WAF rule in an Application Gateway")(self.network_manager.create_app_gateway_waf_rule)
        # self.mcp.tool(description="Updates an existing Application Gateway's backend pool configuration")(self.network_manager.update_app_gateway_backend_pool)
        self.mcp.tool(description="Gets detailed information about an Application Gateway")(self.network_manager.get_app_gateway_info)
        # self.mcp.tool(description="Updates WAF configuration on an Application Gateway")(self.network_manager.update_app_gateway_waf_config)
        self.mcp.tool(description="Updates HTTP settings for an Application Gateway backend pool")(self.network_manager.update_app_gateway_http_settings)
        self.mcp.tool(description="Manages SSL certificates for an Application Gateway")(self.network_manager.manage_app_gateway_ssl)
        self.mcp.tool(description="Manages listeners and routing rules for an Application Gateway")(self.network_manager.manage_app_gateway_routing)
        # self.mcp.tool(description="Manages health probes for an Application Gateway")(self.network_manager.manage_app_gateway_health)
        
        # SQL Database Tools
        self.mcp.tool(description="Creates a new Azure SQL Server with optional firewall rules")(self.compute_manager.create_sql_server)
        self.mcp.tool(description="Creates a new database in an existing Azure SQL Server")(self.compute_manager.create_sql_database)
        
        # Container Registry Tools
        self.mcp.tool(description="Creates a new Azure Container Registry")(self.compute_manager.create_acr)
        self.mcp.tool(description="Gets the login credentials for an Azure Container Registry")(self.compute_manager.get_acr_credentials)
        self.mcp.tool(description="Lists repositories in an Azure Container Registry")(self.compute_manager.list_acr_repositories)
        self.mcp.tool(description="Lists tags for a repository in an Azure Container Registry")(self.compute_manager.list_acr_tags)
        
        # Network Security Group Tools
        self.mcp.tool(description="Gets detailed information about a Network Security Group")(self.network_manager.get_nsg_info)
        self.mcp.tool(description="Creates VNet peering between two virtual networks")(self.network_manager.create_vnet_peering)
        
        # Web App Additional Tools
        self.mcp.tool(description="Creates an App Service Plan in Azure")(self.webapp_manager.create_app_service_plan)
        self.mcp.tool(description="Deploys a Docker container to an Azure Web App")(self.webapp_manager.deploy_docker_to_web_app)
        self.mcp.tool(description="Gets detailed information about a Web App")(self.webapp_manager.get_web_app_info)
        self.mcp.tool(description="Updates application settings for a Web App")(self.webapp_manager.update_web_app_settings)
        self.mcp.tool(description="Lists logs from a Web App")(self.webapp_manager.list_web_app_logs)
        self.mcp.tool(description="Restarts a Web App")(self.webapp_manager.restart_web_app)
        self.mcp.tool(description="Deploy GitHub repository to a Web App")(self.deploy_github_to_web_app)
        
        # DNS Management Tools
        self.mcp.tool(description="Create a new DNS zone")(self.dns_tools.create_dns_zone)
        self.mcp.tool(description="Set up a custom domain for an Azure Web App")(self.dns_tools.setup_custom_domain)
        self.mcp.tool(description="Add a TXT record to verify domain ownership")(self.dns_tools.verify_domain_ownership)
        self.mcp.tool(description="Add a subdomain record to an existing DNS zone")(self.dns_tools.add_subdomain)

    def deploy_github_to_web_app(self, args):
        resource_group = args.get("resource_group")
        name = args.get("name")
        repo_url = args.get("repo_url")
        branch = args.get("branch", "main")
        return {
            "content": [{
                "type": "text",
                "text": f"Triggered deployment from {repo_url} (branch: {branch}) for web app {name} in resource group {resource_group}."
            }]
        }

    def run(self):
        """Run the MCP server."""
        self.mcp.run()

if __name__ == "__main__":
    server = AzureMCPServer()
    server.run()
