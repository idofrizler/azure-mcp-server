from typing import Any, Dict, List

from ..clients.client_factory import AzureClientFactory

class AzureResourceManager:
    """Class for managing Azure resources."""
    
    def __init__(self, client_factory: AzureClientFactory):
        self.client_factory = client_factory

    async def list_resources(self, resource_group: str) -> List[Dict[str, Any]]:
        """List Azure resources, optionally filtered by resource group."""
        client = self.client_factory.get_resource_client()
        resources = client.resources.list_by_resource_group(resource_group) if resource_group else client.resources.list()
        
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

    async def list_resource_groups(self) -> List[Dict[str, Any]]:
        """List all resource groups."""
        client = self.client_factory.get_resource_client()
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

    async def delete_resource_group(self, resource_group: str) -> Dict[str, Any]:
        """Delete a resource group and all its resources."""
        client = self.client_factory.get_resource_client()
        
        try:
            deletion_poller = client.resource_groups.begin_delete(resource_group)
            deletion_result = deletion_poller.result()
            
            return {
                'status': 'success',
                'message': f"Resource group {resource_group} and all its resources have been deleted",
                'result': deletion_result
            }
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e)
            }

    async def create_resource_group(self, resource_group: str, location: str) -> Dict[str, Any]:
        """Create a new resource group."""
        client = self.client_factory.get_resource_client()
        result = client.resource_groups.create_or_update(resource_group, {"location": location})
        return {
            "id": result.id,
            "name": result.name,
            "location": result.location,
            "tags": result.tags or {},
            "properties": result.properties
        }
