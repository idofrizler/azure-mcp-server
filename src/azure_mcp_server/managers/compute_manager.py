from typing import Any, Dict, List, Optional
import base64

from ..clients.client_factory import AzureClientFactory

class AzureComputeManager:
    """Class for managing Azure compute resources."""
    
    def __init__(self, client_factory: AzureClientFactory):
        self.client_factory = client_factory

    async def create_vm(
        self,
        resource_group: str,
        vm_name: str,
        location: str = "westeurope",
        vm_size: str = "Standard_DS1_v2",
        admin_username: str = "azureuser",
        os_disk_size_gb: int = 30,
        image_reference: Dict[str, str] = {
            "publisher": "Canonical",
            "offer": "UbuntuServer",
            "sku": "18.04-LTS",
            "version": "latest"
        }
    ) -> Dict[str, Any]:
        """Create a new virtual machine."""
        compute_client = self.client_factory.get_compute_client()
        network_client = self.client_factory.get_network_client()
        
        import asyncio
        loop = asyncio.get_event_loop()
        
        # Create unique names for networking components
        vnet_name = f"{vm_name}-vnet"
        subnet_name = f"{vm_name}-subnet"
        ip_name = f"{vm_name}-ip"
        nsg_name = f"{vm_name}-nsg"
        nic_name = f"{vm_name}-nic"
        
        try:
            # Create public IP address
            def create_public_ip():
                poller = network_client.public_ip_addresses.begin_create_or_update(
                    resource_group,
                    ip_name,
                    {
                        "location": location,
                        "sku": {"name": "Standard"},
                        "public_ip_allocation_method": "Static",
                    }
                )
                return poller.result()
                
            public_ip = await loop.run_in_executor(None, create_public_ip)
            
            # Create VNet and subnet
            def create_vnet_and_subnet():
                poller = network_client.virtual_networks.begin_create_or_update(
                    resource_group,
                    vnet_name,
                    {
                        "location": location,
                        "address_space": {
                            "address_prefixes": ["10.0.0.0/16"]
                        },
                        "subnets": [
                            {
                                "name": subnet_name,
                                "address_prefix": "10.0.0.0/24"
                            }
                        ]
                    }
                )
                return poller.result()
                
            vnet = await loop.run_in_executor(None, create_vnet_and_subnet)
            
            # Get subnet
            def get_subnet():
                return network_client.subnets.get(
                    resource_group,
                    vnet_name,
                    subnet_name
                )
            
            subnet = await loop.run_in_executor(None, get_subnet)
            
            # Create NSG
            def create_nsg():
                poller = network_client.network_security_groups.begin_create_or_update(
                    resource_group,
                    nsg_name,
                    {
                        "location": location,
                        "security_rules": [
                            {
                                "name": "SSH",
                                "priority": 1000,
                                "protocol": "Tcp",
                                "access": "Allow",
                                "direction": "Inbound",
                                "source_address_prefix": "*",
                                "source_port_range": "*",
                                "destination_address_prefix": "*",
                                "destination_port_range": "22"
                            }
                        ]
                    }
                )
                return poller.result()
                
            nsg = await loop.run_in_executor(None, create_nsg)
            
            # Create NIC
            def create_nic():
                poller = network_client.network_interfaces.begin_create_or_update(
                    resource_group,
                    nic_name,
                    {
                        "location": location,
                        "network_security_group": {"id": nsg.id},
                        "ip_configurations": [
                            {
                                "name": "ipconfig1",
                                "subnet": {"id": subnet.id},
                                "public_ip_address": {"id": public_ip.id}
                            }
                        ]
                    }
                )
                return poller.result()
                
            nic = await loop.run_in_executor(None, create_nic)
            
            # Create VM
            def create_virtual_machine():
                import uuid
                vm_parameters = {
                    "location": location,
                    "hardware_profile": {
                        "vm_size": vm_size
                    },
                    "storage_profile": {
                        "image_reference": image_reference,
                        "os_disk": {
                            "name": f"{vm_name}-os-disk",
                            "caching": "ReadWrite",
                            "create_option": "FromImage",
                            "disk_size_gb": os_disk_size_gb,
                            "managed_disk": {
                                "storage_account_type": "Premium_LRS"
                            }
                        }
                    },
                    "os_profile": {
                        "computer_name": vm_name,
                        "admin_username": admin_username,
                        "linux_configuration": {
                            "disable_password_authentication": True,
                            "ssh": {
                                "public_keys": [
                                    {
                                        "path": f"/home/{admin_username}/.ssh/authorized_keys",
                                        "key_data": "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC+wWK73dCr+jgQOAxNsHAnNNNMEMWOHYEccp6wJm2gotpr9katuF/ZAdou5AaW1C61slRkHRkpRRX9FA9CYBiitZgvCCz+3nWNN7l/Up54Zps/pHWGZLHNJZRYyAB6j5yVLMVHIHriY49d/GZTZVNB8GoJv9Gakwc/fuEZYYl4YDFiGMBP///TzlI4jhiJzjKnEvqPFki5p2ZRJqcbCiF4pJrxUQR/RXqVFQdbRLZgYfJ8xGB878RENq3yQ39d8dVOkq4edbkzwcUmwwwkYVPIoDGsYLaRHnG+To7FvMeyO7xDVQkMKzopTQV8AuKpyvpqu0a9pWOMaiCyDytO7GGN example@example.com"
                                    }
                                ]
                            }
                        }
                    },
                    "network_profile": {
                        "network_interfaces": [
                            {
                                "id": nic.id
                            }
                        ]
                    }
                }
                
                poller = compute_client.virtual_machines.begin_create_or_update(
                    resource_group,
                    vm_name,
                    vm_parameters
                )
                return poller.result()
            
            vm = await loop.run_in_executor(None, create_virtual_machine)
            
            return {
                "id": vm.id,
                "name": vm.name,
                "resource_group": resource_group,
                "location": location,
                "vm_size": vm_size,
                "public_ip": public_ip.ip_address,
                "status": "provisioning"
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "vm_name": vm_name
            }

    async def create_app_gateway_with_waf(
        self,
        resource_group: str,
        app_gateway_name: str,
        backend_pool_name: str,
        backend_fqdns: List[str] = None,
        backend_ips: List[str] = None,
        location: str = "westeurope",
        sku_name: str = "WAF_v2",
        capacity: int = 2,
        waf_enabled: bool = True,
        waf_mode: str = "Prevention",
        frontend_port: int = 80,
        backend_port: int = 80,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create an Application Gateway with WAF and configure backend pools."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        # Create unique names for networking components
        vnet_name = f"{app_gateway_name}-vnet"
        subnet_name = f"{app_gateway_name}-subnet"
        pip_name = f"{app_gateway_name}-pip"
        frontend_ip_config_name = "frontend-ip-config"
        frontend_port_name = "frontend-port"
        http_listener_name = "http-listener"
        backend_http_settings_name = "backend-http-settings"
        http_routing_rule_name = "http-routing-rule"
        
        try:
            # Create public IP
            def create_public_ip():
                return network_client.public_ip_addresses.begin_create_or_update(
                    resource_group,
                    pip_name,
                    {
                        "location": location,
                        "sku": {"name": "Standard"},
                        "public_ip_allocation_method": "Static",
                        "tags": tags
                    }
                ).result()
                
            public_ip = await loop.run_in_executor(None, create_public_ip)
            
            # Create VNet and subnet
            def create_vnet_and_subnet():
                # Create VNet
                vnet_poller = network_client.virtual_networks.begin_create_or_update(
                    resource_group,
                    vnet_name,
                    {
                        "location": location,
                        "address_space": {
                            "address_prefixes": ["10.0.0.0/16"]
                        },
                        "tags": tags
                    }
                )
                vnet = vnet_poller.result()
                
                # Create subnet
                subnet_poller = network_client.subnets.begin_create_or_update(
                    resource_group,
                    vnet_name,
                    subnet_name,
                    {
                        "address_prefix": "10.0.0.0/24"
                    }
                )
                return subnet_poller.result()
                
            subnet = await loop.run_in_executor(None, create_vnet_and_subnet)
            
            # Prepare backend address pool configuration
            backend_addresses = []
            if backend_fqdns:
                for fqdn in backend_fqdns:
                    backend_addresses.append({"fqdn": fqdn})
            if backend_ips:
                for ip in backend_ips:
                    backend_addresses.append({"ip_address": ip})
            
            # Create the Application Gateway
            def create_app_gateway():
                app_gateway_params = {
                    "location": location,
                    "tags": tags,
                    "sku": {
                        "name": sku_name,
                        "tier": sku_name.split('_')[0],
                        "capacity": capacity
                    },
                    "gateway_ip_configurations": [
                        {
                            "name": "gateway-ip-configuration",
                            "subnet": {"id": subnet.id}
                        }
                    ],
                    "frontend_ip_configurations": [
                        {
                            "name": frontend_ip_config_name,
                            "public_ip_address": {"id": public_ip.id}
                        }
                    ],
                    "frontend_ports": [
                        {
                            "name": frontend_port_name,
                            "port": frontend_port
                        }
                    ],
                    "backend_address_pools": [
                        {
                            "name": backend_pool_name,
                            "backend_addresses": backend_addresses
                        }
                    ],
                    "backend_http_settings_collection": [
                        {
                            "name": backend_http_settings_name,
                            "port": backend_port,
                            "protocol": "Http",
                            "cookie_based_affinity": "Disabled",
                            "request_timeout": 30
                        }
                    ],
                    "http_listeners": [
                        {
                            "name": http_listener_name,
                            "frontend_ip_configuration": {"id": f"[resourceId('Microsoft.Network/applicationGateways/frontendIPConfigurations', '{app_gateway_name}', '{frontend_ip_config_name}')]"},
                            "frontend_port": {"id": f"[resourceId('Microsoft.Network/applicationGateways/frontendPorts', '{app_gateway_name}', '{frontend_port_name}')]"},
                            "protocol": "Http"
                        }
                    ],
                    "request_routing_rules": [
                        {
                            "name": http_routing_rule_name,
                            "rule_type": "Basic",
                            "http_listener": {"id": f"[resourceId('Microsoft.Network/applicationGateways/httpListeners', '{app_gateway_name}', '{http_listener_name}')]"},
                            "backend_address_pool": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"},
                            "backend_http_settings": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}

                        }
                    ]
                }
                
                # Add WAF configuration if WAF is enabled
                if waf_enabled and "WAF" in sku_name:
                    app_gateway_params["web_application_firewall_configuration"] = {
                        "enabled": True,
                        "firewall_mode": waf_mode,
                        "rule_set_type": "OWASP",
                        "rule_set_version": "3.2"
                    }
                
                poller = network_client.application_gateways.begin_create_or_update(
                    resource_group,
                    app_gateway_name,
                    app_gateway_params
                )
                return poller.result()
            
            app_gateway = await loop.run_in_executor(None, create_app_gateway)
            
            return {
                "id": app_gateway.id,
                "name": app_gateway.name,
                "resource_group": resource_group,
                "location": location,
                "public_ip": public_ip.ip_address,
                "backend_pool": backend_pool_name,
                "sku": sku_name,
                "waf_enabled": waf_enabled,
                "waf_mode": waf_mode if waf_enabled else None,
                "status": "provisioning"
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name
            }

    async def create_vnet_peering(
        self,
        resource_group: str,
        vnet_name: str,
        remote_vnet_name: str,
        remote_vnet_resource_group: str,
        peering_name: str = None
    ) -> Dict[str, Any]:
        """Create VNet peering between two virtual networks."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # Generate a default peering name if not provided
            if not peering_name:
                peering_name = f"{vnet_name}-{remote_vnet_name}-peering"

            # Get the remote VNet ID
            def get_remote_vnet():
                return network_client.virtual_networks.get(
                    resource_group_name=remote_vnet_resource_group,
                    virtual_network_name=remote_vnet_name
                )

            remote_vnet = await loop.run_in_executor(None, get_remote_vnet)

            # Create the VNet peering
            def create_peering():
                poller = network_client.virtual_network_peerings.begin_create_or_update(
                    resource_group_name=resource_group,
                    virtual_network_name=vnet_name,
                    virtual_network_peering_name=peering_name,
                    parameters={
                        "allow_virtual_network_access": True,
                        "allow_forwarded_traffic": True,
                        "allow_gateway_transit": False,
                        "use_remote_gateways": False,
                        "remote_virtual_network": {"id": remote_vnet.id}
                    }
                )
                return poller.result()

            peering = await loop.run_in_executor(None, create_peering)

            return {
                "result": f"VNet peering '{peering_name}' created successfully",
                "peering_name": peering_name,
                "vnet_name": vnet_name,
                "remote_vnet_name": remote_vnet_name,
                "resource_group": resource_group,
                "remote_vnet_resource_group": remote_vnet_resource_group
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "vnet_name": vnet_name,
                "remote_vnet_name": remote_vnet_name,
                "remote_vnet_resource_group": remote_vnet_resource_group
            }

    async def create_sql_server(
        self,
        resource_group: str,
        server_name: str,
        location: str = "westeurope",
        admin_username: str = "sqladmin",
        admin_password: str = "P@ssw0rd1234",
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new Azure SQL Server with optional firewall rules."""
        sql_client = self.client_factory.get_sql_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # Create the SQL Server
            def create_server():
                poller = sql_client.servers.begin_create_or_update(
                    resource_group_name=resource_group,
                    server_name=server_name,
                    parameters={
                        "location": location,
                        "administrator_login": admin_username,
                        "administrator_login_password": admin_password,
                        "tags": tags
                    }
                )
                return poller.result()

            server = await loop.run_in_executor(None, create_server)

            return {
                "result": f"SQL Server '{server_name}' created successfully",
                "server_name": server_name,
                "resource_group": resource_group,
                "location": location
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "server_name": server_name
            }

    async def create_sql_database(
        self,
        resource_group: str,
        server_name: str,
        database_name: str,
        collation: str = "SQL_Latin1_General_CP1_CI_AS",
        max_size_bytes: int = 2147483648,
        edition: str = "Basic",
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new database in an existing Azure SQL Server."""
        sql_client = self.client_factory.get_sql_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # Create the SQL Database
            def create_database():
                poller = sql_client.databases.begin_create_or_update(
                    resource_group_name=resource_group,
                    server_name=server_name,
                    database_name=database_name,
                    parameters={
                        "location": sql_client.servers.get(resource_group, server_name).location,
                        "collation": collation,
                        "max_size_bytes": max_size_bytes,
                        "sku": {
                            "name": edition
                        },
                        "tags": tags
                    }
                )
                return poller.result()

            database = await loop.run_in_executor(None, create_database)

            return {
                "result": f"SQL Database '{database_name}' created successfully",
                "database_name": database_name,
                "server_name": server_name,
                "resource_group": resource_group
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "server_name": server_name,
                "database_name": database_name
            }

    async def create_acr(
        self,
        resource_group: str,
        registry_name: str,
        location: str = "westeurope",
        sku: str = "Basic",
        admin_user_enabled: bool = True,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new Azure Container Registry."""
        container_registry_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # Create the Container Registry
            def create_registry():
                poller = container_registry_client.registries.begin_create(
                    resource_group_name=resource_group,
                    registry_name=registry_name,
                    registry={
                        "location": location,
                        "sku": {"name": sku},
                        "admin_user_enabled": admin_user_enabled,
                        "tags": tags
                    }
                )
                return poller.result()

            registry = await loop.run_in_executor(None, create_registry)

            return {
                "result": f"Azure Container Registry '{registry_name}' created successfully",
                "registry_name": registry_name,
                "resource_group": resource_group,
                "location": location,
                "sku": sku,
                "admin_user_enabled": admin_user_enabled
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "registry_name": registry_name
            }

    async def get_acr_credentials(
        self,
        resource_group: str,
        registry_name: str
    ) -> Dict[str, Any]:
        """Get the login credentials for an Azure Container Registry."""
        container_registry_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # Get the registry credentials
            def list_credentials():
                return container_registry_client.registries.list_credentials(
                    resource_group_name=resource_group,
                    registry_name=registry_name
                )

            credentials = await loop.run_in_executor(None, list_credentials)

            return {
                "result": "Credentials retrieved successfully",
                "registry_name": registry_name,
                "resource_group": resource_group,
                "username": credentials.username,
                "passwords": [password.value for password in credentials.passwords]
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "registry_name": registry_name
            }

    async def list_acr_repositories(
        self,
        resource_group: str,
        registry_name: str
    ) -> Dict[str, Any]:
        """List repositories in an Azure Container Registry."""
        container_registry_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # List repositories
            def list_repositories():
                return container_registry_client.registries.list_repositories(
                    resource_group_name=resource_group,
                    registry_name=registry_name
                )

            repositories = await loop.run_in_executor(None, list_repositories)

            return {
                "result": "Repositories listed successfully",
                "registry_name": registry_name,
                "resource_group": resource_group,
                "repositories": repositories
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "registry_name": registry_name
            }

    async def list_acr_tags(
        self,
        resource_group: str,
        registry_name: str,
        repository_name: str
    ) -> Dict[str, Any]:
        """List tags for a repository in an Azure Container Registry."""
        container_registry_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # List tags for the repository
            def list_tags():
                return container_registry_client.registries.get_repository_tags(
                    resource_group_name=resource_group,
                    registry_name=registry_name,
                    repository_name=repository_name
                )

            tags = await loop.run_in_executor(None, list_tags)

            return {
                "result": "Tags listed successfully",
                "registry_name": registry_name,
                "repository_name": repository_name,
                "resource_group": resource_group,
                "tags": tags
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "registry_name": registry_name,
                "repository_name": repository_name
            }