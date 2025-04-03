from azure.identity import DeviceCodeCredential, DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.dns import DnsManagementClient

from ..config.azure_config import AzureConfig

class AzureClientFactory:
    """Factory class for creating Azure service clients."""
    
    def __init__(self, config: AzureConfig):
        self.config = config
        self._credential = self._get_credential()

    def _get_credential(self):
        """Get appropriate Azure credential based on configuration."""
        if self.config.client_id and self.config.client_secret and self.config.tenant_id:
            return ClientSecretCredential(
                tenant_id=self.config.tenant_id,
                client_id=self.config.client_id,
                client_secret=self.config.client_secret
            )
        elif self.config.tenant_id:
            return DeviceCodeCredential(tenant_id=self.config.tenant_id)
        return DefaultAzureCredential(exclude_shared_token_cache_credential=True)

    def get_resource_client(self) -> ResourceManagementClient:
        return ResourceManagementClient(
            credential=self._credential,
            subscription_id=self.config.subscription_id
        )

    def get_compute_client(self) -> ComputeManagementClient:
        return ComputeManagementClient(
            credential=self._credential,
            subscription_id=self.config.subscription_id
        )

    def get_network_client(self) -> NetworkManagementClient:
        return NetworkManagementClient(
            credential=self._credential,
            subscription_id=self.config.subscription_id
        )

    def get_sql_client(self) -> SqlManagementClient:
        return SqlManagementClient(
            credential=self._credential,
            subscription_id=self.config.subscription_id
        )

    def get_container_registry_client(self) -> ContainerRegistryManagementClient:
        return ContainerRegistryManagementClient(
            credential=self._credential,
            subscription_id=self.config.subscription_id
        )

    def get_web_client(self) -> WebSiteManagementClient:
        return WebSiteManagementClient(
            credential=self._credential,
            subscription_id=self.config.subscription_id
        )

    def get_dns_client(self) -> DnsManagementClient:
        """Get a client for managing DNS zones and records."""
        return DnsManagementClient(
            credential=self._credential,
            subscription_id=self.config.subscription_id
        ) 