from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import ResourceManagementClient
from . import config

class AzureResourceManager:
    def __init__(self):
        self.credential = DefaultAzureCredential()
        self.client = ResourceManagementClient(
            credential=self.credential,
            subscription_id=config.subscription_id
        )
    
    def list_resources(self, resource_group=None):
        """List Azure resources, optionally filtered by resource group"""
        if resource_group:
            return self.client.resources.list_by_resource_group(resource_group)
        return self.client.resources.list() 