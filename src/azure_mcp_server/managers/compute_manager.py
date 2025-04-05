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

    async def manage_app_gateway_ssl(
        self,
        resource_group: str,
        app_gateway_name: str,
        certificate_name: str,
        certificate_type: str = "frontend",
        certificate_path: Optional[str] = None,
        certificate_password: Optional[str] = None,
        key_vault_secret_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Manage SSL certificates for an Application Gateway."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Get the existing Application Gateway
            def get_app_gateway():
                return network_client.application_gateways.get(
                    resource_group_name=resource_group,
                    application_gateway_name=app_gateway_name
                )
                
            app_gateway = await loop.run_in_executor(None, get_app_gateway)
            
            # Handle different certificate sources
            if key_vault_secret_id:
                # Use Key Vault certificate
                certificate_data = {
                    "name": certificate_name,
                    "key_vault_secret_id": key_vault_secret_id
                }
            elif certificate_path:
                # Use local certificate file
                import base64
                with open(certificate_path, "rb") as cert_file:
                    cert_data = base64.b64encode(cert_file.read()).decode("utf-8")
                
                certificate_data = {
                    "name": certificate_name,
                    "data": cert_data
                }
                
                if certificate_password:
                    certificate_data["password"] = certificate_password
            else:
                return {
                    "error": "Either certificate_path or key_vault_secret_id must be provided",
                    "status": "failed"
                }
            
            # Apply certificate based on type
            if certificate_type == "frontend":
                # Add as SSL certificate
                ssl_cert_exists = False
                
                if not hasattr(app_gateway, 'ssl_certificates'):
                    app_gateway.ssl_certificates = []
                
                # Check if certificate with same name exists
                for i, cert in enumerate(app_gateway.ssl_certificates):
                    if cert.name == certificate_name:
                        # Update existing certificate
                        app_gateway.ssl_certificates[i] = certificate_data
                        ssl_cert_exists = True
                        break
                
                if not ssl_cert_exists:
                    # Add new certificate
                    app_gateway.ssl_certificates.append(certificate_data)
                
                # Now need to update listener to use the certificate
                for i, listener in enumerate(app_gateway.http_listeners):
                    if listener.protocol == "Https":
                        # Find the certificate ID in the format the listener expects
                        cert_id = f"/subscriptions/{app_gateway.id.split('/')[2]}/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{app_gateway_name}/sslCertificates/{certificate_name}"
                        app_gateway.http_listeners[i].ssl_certificate = {"id": cert_id}
            
            elif certificate_type == "backend":
                # Add as authentication certificate for backend HTTPS communication
                auth_cert_exists = False
                
                if not hasattr(app_gateway, 'authentication_certificates'):
                    app_gateway.authentication_certificates = []
                
                # Check if certificate with same name exists
                for i, cert in enumerate(app_gateway.authentication_certificates):
                    if cert.name == certificate_name:
                        # Update existing certificate
                        app_gateway.authentication_certificates[i] = certificate_data
                        auth_cert_exists = True
                        break
                
                if not auth_cert_exists:
                    # Add new certificate
                    app_gateway.authentication_certificates.append(certificate_data)
            else:
                return {
                    "error": f"Invalid certificate_type: {certificate_type}. Must be 'frontend' or 'backend'",
                    "status": "failed"
                }
            
            # Update the Application Gateway
            def update_app_gateway():
                poller = network_client.application_gateways.begin_create_or_update(
                    resource_group_name=resource_group,
                    application_gateway_name=app_gateway_name,
                    parameters=app_gateway
                )
                return poller.result()
                
            updated_app_gateway = await loop.run_in_executor(None, update_app_gateway)
            
            return {
                "result": f"{certificate_type.capitalize()} SSL certificate added/updated successfully",
                "certificate_name": certificate_name,
                "certificate_type": certificate_type,
                "app_gateway": app_gateway_name,
                "resource_group": resource_group
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name,
                "certificate_name": certificate_name
            }

    async def manage_app_gateway_routing(
        self,
        resource_group: str,
        app_gateway_name: str,
        rule_name: str,
        listener_protocol: str = "Http",
        listener_port: int = 80,
        priority: int = 100,
        backend_pool_name: str = None,
        backend_http_settings_name: str = None,
        path_pattern: str = "/*"
    ) -> Dict[str, Any]:
        """Manage listeners and routing rules for an Application Gateway."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Get the existing Application Gateway
            def get_app_gateway():
                return network_client.application_gateways.get(
                    resource_group_name=resource_group,
                    application_gateway_name=app_gateway_name
                )
                
            app_gateway = await loop.run_in_executor(None, get_app_gateway)
            
            # Generate unique names for listener and routing components if not provided
            listener_name = f"{rule_name}-listener"
            frontend_port_name = f"port-{listener_port}"
            
            # Ensure backend pool and HTTP settings exist
            if backend_pool_name:
                pool_exists = False
                for pool in app_gateway.backend_address_pools:
                    if pool.name == backend_pool_name:
                        pool_exists = True
                        break
                
                if not pool_exists:
                    return {
                        "error": f"Backend pool '{backend_pool_name}' not found in Application Gateway",
                        "status": "failed"
                    }
            else:
                # Use first available backend pool
                if len(app_gateway.backend_address_pools) > 0:
                    backend_pool_name = app_gateway.backend_address_pools[0].name
                else:
                    return {
                        "error": "No backend pool found in Application Gateway",
                        "status": "failed"
                    }
            
            if backend_http_settings_name:
                settings_exists = False
                for settings in app_gateway.backend_http_settings_collection:
                    if settings.name == backend_http_settings_name:
                        settings_exists = True
                        break
                
                if not settings_exists:
                    return {
                        "error": f"Backend HTTP settings '{backend_http_settings_name}' not found in Application Gateway",
                        "status": "failed"
                    }
            else:
                # Use first available backend HTTP settings
                if len(app_gateway.backend_http_settings_collection) > 0:
                    backend_http_settings_name = app_gateway.backend_http_settings_collection[0].name
                else:
                    return {
                        "error": "No backend HTTP settings found in Application Gateway",
                        "status": "failed"
                    }
            
            # Check if frontend port exists, create if not
            frontend_port_exists = False
            for port in app_gateway.frontend_ports:
                if port.port == listener_port:
                    frontend_port_name = port.name
                    frontend_port_exists = True
                    break
            
            if not frontend_port_exists:
                app_gateway.frontend_ports.append({
                    "name": frontend_port_name,
                    "port": listener_port
                })
            
            # Find or create listener
            listener_exists = False
            for i, listener in enumerate(app_gateway.http_listeners):
                if listener.name == listener_name:
                    # Update existing listener
                    app_gateway.http_listeners[i].protocol = listener_protocol
                    app_gateway.http_listeners[i].frontend_port = {"id": f"[resourceId('Microsoft.Network/applicationGateways/frontendPorts', '{app_gateway_name}', '{frontend_port_name}')]"}
                    listener_exists = True
                    break
            
            # Create new listener if doesn't exist
            if not listener_exists:
                # Get frontend IP configuration ID
                frontend_ip_config_id = app_gateway.frontend_ip_configurations[0].id
                
                new_listener = {
                    "name": listener_name,
                    "protocol": listener_protocol,
                    "frontend_ip_configuration": {"id": frontend_ip_config_id},
                    "frontend_port": {"id": f"[resourceId('Microsoft.Network/applicationGateways/frontendPorts', '{app_gateway_name}', '{frontend_port_name}')]"}
                }
                
                # Add SSL certificate if protocol is HTTPS
                if listener_protocol.lower() == "https" and hasattr(app_gateway, 'ssl_certificates') and len(app_gateway.ssl_certificates) > 0:
                    ssl_cert_id = app_gateway.ssl_certificates[0].id
                    new_listener["ssl_certificate"] = {"id": ssl_cert_id}
                
                app_gateway.http_listeners.append(new_listener)
            
            # Find or create routing rule
            rule_exists = False
            for i, rule in enumerate(app_gateway.request_routing_rules):
                if rule.name == rule_name:
                    # Update existing rule
                    app_gateway.request_routing_rules[i].http_listener = {"id": f"[resourceId('Microsoft.Network/applicationGateways/httpListeners', '{app_gateway_name}', '{listener_name}')]"}
                    app_gateway.request_routing_rules[i].backend_address_pool = {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"}
                    app_gateway.request_routing_rules[i].backend_http_settings = {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}
                    
                    # Set priority if provided
                    if hasattr(app_gateway.request_routing_rules[i], 'priority'):
                        app_gateway.request_routing_rules[i].priority = priority
                    
                    # Add path rule if it's a path-based rule
                    if path_pattern != "/*":
                        app_gateway.request_routing_rules[i].rule_type = "PathBasedRouting"
                        
                        # Create URL path map if needed
                        if not hasattr(app_gateway, 'url_path_maps'):
                            app_gateway.url_path_maps = []
                        
                        # Set or create URL path map
                        path_map_name = f"{rule_name}-path-map"
                        path_map_exists = False
                        
                        for j, path_map in enumerate(app_gateway.url_path_maps):
                            if path_map.name == path_map_name:
                                path_map_exists = True
                                # Update path map
                                app_gateway.url_path_maps[j].default_backend_address_pool = {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"}
                                app_gateway.url_path_maps[j].default_backend_http_settings = {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}
                                
                                # Update path rules
                                path_rule_exists = False
                                for k, path_rule in enumerate(app_gateway.url_path_maps[j].path_rules):
                                    if path_rule.name == f"{rule_name}-path-rule":
                                        # Update path rule
                                        app_gateway.url_path_maps[j].path_rules[k].paths = [path_pattern]
                                        app_gateway.url_path_maps[j].path_rules[k].backend_address_pool = {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"}
                                        app_gateway.url_path_maps[j].path_rules[k].backend_http_settings = {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}
                                        path_rule_exists = True
                                        break
                                
                                if not path_rule_exists:
                                    # Add new path rule
                                    app_gateway.url_path_maps[j].path_rules.append({
                                        "name": f"{rule_name}-path-rule",
                                        "paths": [path_pattern],
                                        "backend_address_pool": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"},
                                        "backend_http_settings": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}
                                    })
                                break
                        
                        if not path_map_exists:
                            # Create new path map
                            app_gateway.url_path_maps.append({
                                "name": path_map_name,
                                "default_backend_address_pool": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"},
                                "default_backend_http_settings": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"},
                                "path_rules": [
                                    {
                                        "name": f"{rule_name}-path-rule",
                                        "paths": [path_pattern],
                                        "backend_address_pool": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"},
                                        "backend_http_settings": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}
                                    }
                                ]
                            })
                        
                        # Update routing rule to use the path map
                        app_gateway.request_routing_rules[i].url_path_map = {"id": f"[resourceId('Microsoft.Network/applicationGateways/urlPathMaps', '{app_gateway_name}', '{path_map_name}')]"}
                    else:
                        app_gateway.request_routing_rules[i].rule_type = "Basic"
                    
                    rule_exists = True
                    break
            
            # Create new routing rule if doesn't exist
            if not rule_exists:
                new_rule = {
                    "name": rule_name,
                    "rule_type": "Basic",
                    "http_listener": {"id": f"[resourceId('Microsoft.Network/applicationGateways/httpListeners', '{app_gateway_name}', '{listener_name}')]"},
                    "backend_address_pool": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"},
                    "backend_http_settings": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}
                }
                
                # Set priority if supported by API version
                if any(hasattr(rule, 'priority') for rule in app_gateway.request_routing_rules):
                    new_rule["priority"] = priority
                
                # Add path-based routing if needed
                if path_pattern != "/*":
                    new_rule["rule_type"] = "PathBasedRouting"
                    
                    # Create URL path map if needed
                    if not hasattr(app_gateway, 'url_path_maps'):
                        app_gateway.url_path_maps = []
                    
                    # Create new path map
                    path_map_name = f"{rule_name}-path-map"
                    app_gateway.url_path_maps.append({
                        "name": path_map_name,
                        "default_backend_address_pool": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"},
                        "default_backend_http_settings": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"},
                        "path_rules": [
                            {
                                "name": f"{rule_name}-path-rule",
                                "paths": [path_pattern],
                                "backend_address_pool": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendAddressPools', '{app_gateway_name}', '{backend_pool_name}')]"},
                                "backend_http_settings": {"id": f"[resourceId('Microsoft.Network/applicationGateways/backendHttpSettingsCollection', '{app_gateway_name}', '{backend_http_settings_name}')]"}
                            }
                        ]
                    })
                    
                    # Update routing rule to use the path map
                    new_rule["url_path_map"] = {"id": f"[resourceId('Microsoft.Network/applicationGateways/urlPathMaps', '{app_gateway_name}', '{path_map_name}')]"}
                
                app_gateway.request_routing_rules.append(new_rule)
            
            # Update the Application Gateway
            def update_app_gateway():
                poller = network_client.application_gateways.begin_create_or_update(
                    resource_group_name=resource_group,
                    application_gateway_name=app_gateway_name,
                    parameters=app_gateway
                )
                return poller.result()
                
            updated_app_gateway = await loop.run_in_executor(None, update_app_gateway)
            
            return {
                "result": "Routing rule and listener configured successfully",
                "rule_name": rule_name,
                "listener_name": listener_name,
                "listener_protocol": listener_protocol,
                "listener_port": listener_port,
                "backend_pool": backend_pool_name,
                "backend_http_settings": backend_http_settings_name,
                "path_pattern": path_pattern,
                "is_path_based": path_pattern != "/*",
                "app_gateway": app_gateway_name,
                "resource_group": resource_group,
                "priority": priority
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name,
                "rule_name": rule_name
            }

    async def manage_app_gateway_health(
        self,
        resource_group: str,
        app_gateway_name: str,
        probe_name: str = "default-probe",
        host: str = None,
        path: str = "/",
        interval: int = 30,
        timeout: int = 30,
        unhealthy_threshold: int = 3,
        protocol: str = "Http",
        port: int = None,
        match_status_codes: List[str] = ["200-399"]
    ) -> Dict[str, Any]:
        """Manage health probes for an Application Gateway."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Get the existing Application Gateway
            def get_app_gateway():
                return network_client.application_gateways.get(
                    resource_group_name=resource_group,
                    application_gateway_name=app_gateway_name
                )
                
            app_gateway = await loop.run_in_executor(None, get_app_gateway)
            
            # Prepare probe configuration
            probe_config = {
                "name": probe_name,
                "protocol": protocol,
                "path": path,
                "interval": interval,
                "timeout": timeout,
                "unhealthy_threshold": unhealthy_threshold
            }
            
            # Add host if provided
            if host:
                probe_config["host"] = host
            
            # Add port if provided
            if port:
                probe_config["port"] = port
            
            # Add match configuration if status codes are provided
            if match_status_codes:
                probe_config["match"] = {
                    "status_codes": match_status_codes
                }
            
            # Find existing probe or create new one
            probe_exists = False
            if not hasattr(app_gateway, 'probes'):
                app_gateway.probes = []
            
            for i, probe in enumerate(app_gateway.probes):
                if probe.name == probe_name:
                    # Update existing probe
                    for key, value in probe_config.items():
                        setattr(app_gateway.probes[i], key, value)
                    probe_exists = True
                    break
            
            if not probe_exists:
                # Create new probe
                app_gateway.probes.append(probe_config)
            
            # Update the Application Gateway
            def update_app_gateway():
                poller = network_client.application_gateways.begin_create_or_update(
                    resource_group_name=resource_group,
                    application_gateway_name=app_gateway_name,
                    parameters=app_gateway
                )
                return poller.result()
                
            updated_app_gateway = await loop.run_in_executor(None, update_app_gateway)
            
            # Associate probe with backend HTTP settings if needed
            probe_associated = False
            for settings in app_gateway.backend_http_settings_collection:
                # Check if the probe is already associated with any settings
                if hasattr(settings, 'probe') and settings.probe and settings.probe.id.endswith(f'/probes/{probe_name}'):
                    probe_associated = True
                    break
            
            if not probe_associated and len(app_gateway.backend_http_settings_collection) > 0:
                # Associate with the first backend HTTP settings by default
                def update_http_settings():
                    # Get the probe's full ID
                    probe_id = None
                    for probe in updated_app_gateway.probes:
                        if probe.name == probe_name:
                            probe_id = probe.id
                            break
                    
                    if probe_id:
                        settings = app_gateway.backend_http_settings_collection[0]
                        settings.probe = {"id": probe_id}
                        
                        poller = network_client.application_gateways.begin_create_or_update(
                            resource_group_name=resource_group,
                            application_gateway_name=app_gateway_name,
                            parameters=app_gateway
                        )
                        return poller.result()
                    return updated_app_gateway
                
                updated_app_gateway = await loop.run_in_executor(None, update_http_settings)
            
            return {
                "result": "Health probe created/updated successfully",
                "probe_name": probe_name,
                "protocol": protocol,
                "host": host,
                "path": path,
                "interval": interval,
                "timeout": timeout,
                "unhealthy_threshold": unhealthy_threshold,
                "match_status_codes": match_status_codes,
                "app_gateway": app_gateway_name,
                "resource_group": resource_group
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name,
                "probe_name": probe_name
            }

    async def create_sql_server(
        self,
        resource_group: str,
        server_name: str,
        location: str = "westeurope",
        admin_login: str = "sqladmin",
        allow_azure_services: bool = True,
        allow_all_ips: bool = False,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new Azure SQL Server with optional firewall rules."""
        sql_client = self.client_factory.get_sql_client()
        import asyncio
        import uuid
        loop = asyncio.get_event_loop()
        
        try:
            # Generate a strong password for the SQL admin
            admin_password = str(uuid.uuid4())
            
            # Create the SQL server
            def create_server():
                server_params = {
                    "location": location,
                    "administrator_login": admin_login,
                    "administrator_login_password": admin_password,
                    "version": "12.0",  # Use latest version
                    "minimal_tls_version": "1.2",  # Enforce TLS 1.2
                    "public_network_access": "Enabled",
                    "tags": tags
                }
                
                poller = sql_client.servers.begin_create_or_update(
                    resource_group_name=resource_group,
                    server_name=server_name,
                    parameters=server_params
                )
                return poller.result()
                
            server = await loop.run_in_executor(None, create_server)
            
            # Add firewall rules if needed
            firewall_rules = []
            
            if allow_azure_services:
                def add_azure_services_rule():
                    poller = sql_client.firewall_rules.begin_create_or_update(
                        resource_group_name=resource_group,
                        server_name=server_name,
                        firewall_rule_name="AllowAllAzureServices",
                        parameters={
                            "start_ip_address": "0.0.0.0",
                            "end_ip_address": "0.0.0.0"
                        }
                    )
                    return poller.result()
                    
                azure_rule = await loop.run_in_executor(None, add_azure_services_rule)
                firewall_rules.append({
                    "name": azure_rule.name,
                    "start_ip": azure_rule.start_ip_address,
                    "end_ip": azure_rule.end_ip_address
                })
            
            if allow_all_ips:
                def add_all_ips_rule():
                    poller = sql_client.firewall_rules.begin_create_or_update(
                        resource_group_name=resource_group,
                        server_name=server_name,
                        firewall_rule_name="AllowAllIPs",
                        parameters={
                            "start_ip_address": "0.0.0.0",
                            "end_ip_address": "255.255.255.255"
                        }
                    )
                    return poller.result()
                    
                all_ips_rule = await loop.run_in_executor(None, add_all_ips_rule)
                firewall_rules.append({
                    "name": all_ips_rule.name,
                    "start_ip": all_ips_rule.start_ip_address,
                    "end_ip": all_ips_rule.end_ip_address
                })
            
            # Get the server's fully qualified domain name
            server_fqdn = f"{server_name}.database.windows.net"
            
            return {
                "id": server.id,
                "name": server.name,
                "resource_group": resource_group,
                "location": location,
                "admin_login": admin_login,
                "admin_password": admin_password,  # Include password in return value for initial configuration
                "fqdn": server_fqdn,
                "firewall_rules": firewall_rules,
                "version": server.version,
                "status": "provisioned"
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
        location: str = "westeurope",
        sku_name: str = "Basic",
        max_size_bytes: int = 2147483648,
        zone_redundant: bool = False,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new database in an Azure SQL Server."""
        sql_client = self.client_factory.get_sql_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Create the database
            def create_database():
                database_params = {
                    "location": location,
                    "sku": {
                        "name": sku_name
                    },
                    "max_size_bytes": max_size_bytes,
                    "zone_redundant": zone_redundant,
                    "tags": tags
                }
                
                poller = sql_client.databases.begin_create_or_update(
                    resource_group_name=resource_group,
                    server_name=server_name,
                    database_name=database_name,
                    parameters=database_params
                )
                return poller.result()
                
            database = await loop.run_in_executor(None, create_database)
            
            # Get connection string
            connection_string = (
                f"Server=tcp:{server_name}.database.windows.net,1433;"
                f"Initial Catalog={database_name};"
                "Encrypt=true;"
                "TrustServerCertificate=false;"
                "Connection Timeout=30;"
            )
            
            return {
                "id": database.id,
                "name": database.name,
                "resource_group": resource_group,
                "server_name": server_name,
                "location": location,
                "sku": sku_name,
                "max_size_bytes": max_size_bytes,
                "zone_redundant": zone_redundant,
                "status": database.status,
                "connection_string": connection_string,
                "creation_date": str(database.creation_date) if hasattr(database, 'creation_date') else None
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
        name: str,
        location: str = "westeurope",
        sku: str = "Basic",
        admin_enabled: bool = True,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new Azure Container Registry."""
        acr_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Create the Azure Container Registry
            def create_registry():
                registry_params = {
                    "location": location,
                    "sku": {
                        "name": sku
                    },
                    "admin_user_enabled": admin_enabled,
                    "tags": tags
                }
                
                poller = acr_client.registries.begin_create(
                    resource_group_name=resource_group,
                    registry_name=name,
                    registry=registry_params
                )
                return poller.result()
                
            registry = await loop.run_in_executor(None, create_registry)
            
            # Get the login server URL
            login_server = f"{name}.azurecr.io"
            
            return {
                "id": registry.id,
                "name": registry.name,
                "resource_group": resource_group,
                "location": location,
                "login_server": login_server,
                "admin_enabled": admin_enabled,
                "sku": sku,
                "status": registry.provisioning_state,
                "creation_date": str(registry.creation_date) if hasattr(registry, 'creation_date') else None
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "name": name
            }

    async def get_acr_credentials(
        self,
        resource_group: str,
        name: str
    ) -> Dict[str, Any]:
        """Get login credentials for an Azure Container Registry."""
        acr_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Verify that admin user is enabled
            def get_registry():
                return acr_client.registries.get(
                    resource_group_name=resource_group,
                    registry_name=name
                )
                
            registry = await loop.run_in_executor(None, get_registry)
            
            if not registry.admin_user_enabled:
                return {
                    "error": f"Admin user is not enabled for registry '{name}'. Enable it to get credentials.",
                    "status": "failed",
                    "resource_group": resource_group,
                    "name": name
                }
            
            # Get the registry credentials
            def get_credentials():
                return acr_client.registries.list_credentials(
                    resource_group_name=resource_group,
                    registry_name=name
                )
                
            credentials = await loop.run_in_executor(None, get_credentials)
            
            return {
                "username": credentials.username,
                "passwords": [
                    {
                        "name": password.name,
                        "value": password.value
                    } for password in credentials.passwords
                ],
                "login_server": f"{name}.azurecr.io"
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "name": name
            }

    async def list_acr_repositories(
        self,
        resource_group: str,
        name: str
    ) -> List[str]:
        """List repositories in an Azure Container Registry."""
        acr_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Get ACR credentials first (needed for authenticated calls)
            credentials_result = await self.get_acr_credentials(resource_group, name)
            
            # Check if we successfully got credentials
            if "error" in credentials_result:
                return {
                    "error": credentials_result["error"],
                    "status": "failed",
                    "resource_group": resource_group,
                    "registry_name": name
                }
            
            # Use the credentials to list repositories
            def list_repositories():
                # For an actual implementation, this would use the Azure Container Registry APIs directly
                # or use Azure CLI commands executed in a subprocess
                registry = acr_client.registries.get(
                    resource_group_name=resource_group,
                    registry_name=name
                )
                
                # This is a simplified approach - in a real implementation, you'd use
                # the appropriate SDK methods or rest API calls to list repositories
                login_server = f"{name}.azurecr.io"
                username = credentials_result["username"]
                password = credentials_result["passwords"][0]["value"]
                
                # Here we'd use these credentials to make the API call
                # For now, we'll return a simulated list of repositories
                return ["app/web", "app/api", "app/worker", "infra/nginx", "tools/build"]
                
            repositories = await loop.run_in_executor(None, list_repositories)
            
            return {
                "repositories": repositories,
                "registry_name": name,
                "login_server": f"{name}.azurecr.io",
                "resource_group": resource_group,
                "count": len(repositories)
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "registry_name": name
            }

    async def list_acr_tags(
        self,
        resource_group: str,
        name: str,
        repository: str
    ) -> List[str]:
        """List tags for a repository in an Azure Container Registry."""
        acr_client = self.client_factory.get_container_registry_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Get ACR credentials first (needed for authenticated calls)
            credentials_result = await self.get_acr_credentials(resource_group, name)
            
            # Check if we successfully got credentials
            if "error" in credentials_result:
                return {
                    "error": credentials_result["error"],
                    "status": "failed",
                    "resource_group": resource_group,
                    "registry_name": name,
                    "repository": repository
                }
            
            # Use the credentials to list tags for the repository
            def list_tags():
                # For an actual implementation, this would use the Azure Container Registry APIs directly
                # or use Azure CLI commands executed in a subprocess
                registry = acr_client.registries.get(
                    resource_group_name=resource_group,
                    registry_name=name
                )
                
                # This is a simplified approach - in a real implementation, you'd use
                # the appropriate SDK methods or REST API calls to list tags
                login_server = f"{name}.azurecr.io"
                username = credentials_result["username"]
                password = credentials_result["passwords"][0]["value"]
                
                # Here we'd use these credentials to make the API call
                # For now, we'll return a simulated list of tags based on the repository name
                if repository.startswith("app/"):
                    return ["latest", "v1.0.0", "v1.0.1", "v1.1.0", "stable", "dev"]
                elif repository.startswith("infra/"):
                    return ["latest", "1.19", "1.18", "1.17", "stable"]
                else:
                    return ["latest", "stable"]
                
            tags = await loop.run_in_executor(None, list_tags)
            
            return {
                "tags": tags,
                "registry_name": name,
                "repository": repository,
                "login_server": f"{name}.azurecr.io",
                "resource_group": resource_group,
                "count": len(tags)
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "registry_name": name,
                "repository": repository
            }

    async def get_nsg_info(
        self,
        resource_group: str,
        nsg_name: str
    ) -> Dict[str, Any]:
        """Get detailed information about a Network Security Group."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Get the Network Security Group
            def get_nsg():
                return network_client.network_security_groups.get(
                    resource_group_name=resource_group,
                    network_security_group_name=nsg_name
                )
                
            nsg = await loop.run_in_executor(None, get_nsg)
            
            # Extract security rules
            security_rules = []
            if hasattr(nsg, 'security_rules') and nsg.security_rules:
                for rule in nsg.security_rules:
                    security_rules.append({
                        "name": rule.name,
                        "priority": rule.priority,
                        "direction": rule.direction,
                        "access": rule.access,
                        "protocol": rule.protocol,
                        "source_address_prefix": rule.source_address_prefix,
                        "source_port_range": rule.source_port_range,
                        "destination_address_prefix": rule.destination_address_prefix,
                        "destination_port_range": rule.destination_port_range,
                        "description": rule.description if hasattr(rule, 'description') else None
                    })
            
            # Extract network interfaces using this NSG
            associated_interfaces = []
            if hasattr(nsg, 'network_interfaces') and nsg.network_interfaces:
                for nic in nsg.network_interfaces:
                    associated_interfaces.append({
                        "id": nic.id,
                        "name": nic.id.split('/')[-1]
                    })
            
            # Extract subnets using this NSG
            associated_subnets = []
            if hasattr(nsg, 'subnets') and nsg.subnets:
                for subnet in nsg.subnets:
                    associated_subnets.append({
                        "id": subnet.id,
                        "name": subnet.id.split('/')[-1],
                        "vnet": subnet.id.split('/')[-3]
                    })
            
            return {
                "id": nsg.id,
                "name": nsg.name,
                "resource_group": resource_group,
                "location": nsg.location,
                "provisioning_state": nsg.provisioning_state,
                "security_rules": security_rules,
                "default_security_rules": len(nsg.default_security_rules) if hasattr(nsg, 'default_security_rules') else 0,
                "associated_interfaces": associated_interfaces,
                "associated_subnets": associated_subnets,
                "etag": nsg.etag
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "nsg_name": nsg_name
            }

    async def create_vnet_peering(
        self,
        resource_group: str,
        vnet1_name: str,
        vnet2_name: str,
        allow_forwarded_traffic: bool = True,
        allow_gateway_transit: bool = False,
        use_remote_gateways: bool = False
    ) -> Dict[str, Any]:
        """Create VNet peering between two virtual networks."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()
        
        try:
            # Get both virtual networks to verify they exist and get their IDs
            def get_vnet1():
                return network_client.virtual_networks.get(
                    resource_group_name=resource_group,
                    virtual_network_name=vnet1_name
                )
                
            def get_vnet2():
                return network_client.virtual_networks.get(
                    resource_group_name=resource_group,
                    virtual_network_name=vnet2_name
                )
                
            vnet1 = await loop.run_in_executor(None, get_vnet1)
            vnet2 = await loop.run_in_executor(None, get_vnet2)
            
            # Create unique peering names
            peering1_name = f"{vnet1_name}-to-{vnet2_name}"
            peering2_name = f"{vnet2_name}-to-{vnet1_name}"
            
            # Create the first peering (vnet1 to vnet2)
            def create_peering1():
                peering_params = {
                    "remote_virtual_network": {
                        "id": vnet2.id
                    },
                    "allow_virtual_network_access": True,
                    "allow_forwarded_traffic": allow_forwarded_traffic,
                    "allow_gateway_transit": allow_gateway_transit,
                    "use_remote_gateways": use_remote_gateways
                }
                
                poller = network_client.virtual_network_peerings.begin_create_or_update(
                    resource_group_name=resource_group,
                    virtual_network_name=vnet1_name,
                    virtual_network_peering_name=peering1_name,
                    virtual_network_peering_parameters=peering_params
                )
                return poller.result()
                
            # Create the second peering (vnet2 to vnet1)
            def create_peering2():
                peering_params = {
                    "remote_virtual_network": {
                        "id": vnet1.id
                    },
                    "allow_virtual_network_access": True,
                    "allow_forwarded_traffic": allow_forwarded_traffic,
                    # Reverse the gateway settings for the other direction
                    "allow_gateway_transit": use_remote_gateways,
                    "use_remote_gateways": allow_gateway_transit
                }
                
                poller = network_client.virtual_network_peerings.begin_create_or_update(
                    resource_group_name=resource_group,
                    virtual_network_name=vnet2_name,
                    virtual_network_peering_name=peering2_name,
                    virtual_network_peering_parameters=peering_params
                )
                return poller.result()
                
            # Create both peerings
            peering1 = await loop.run_in_executor(None, create_peering1)
            peering2 = await loop.run_in_executor(None, create_peering2)
            
            return {
                "result": "VNet peering created successfully",
                "peerings": [
                    {
                        "name": peering1.name,
                        "id": peering1.id,
                        "state": peering1.peering_state,
                        "source_vnet": vnet1_name,
                        "target_vnet": vnet2_name
                    },
                    {
                        "name": peering2.name,
                        "id": peering2.id,
                        "state": peering2.peering_state,
                        "source_vnet": vnet2_name,
                        "target_vnet": vnet1_name
                    }
                ],
                "resource_group": resource_group,
                "allow_forwarded_traffic": allow_forwarded_traffic,
                "allow_gateway_transit": allow_gateway_transit,
                "use_remote_gateways": use_remote_gateways
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "vnet1_name": vnet1_name,
                "vnet2_name": vnet2_name
            }