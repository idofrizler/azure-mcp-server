from typing import Dict, Any, Optional

class AzureNetworkManager:
    def __init__(self, client_factory):
        self.client_factory = client_factory

    async def update_app_gateway_http_settings(
        self,
        resource_group: str,
        app_gateway_name: str,
        http_settings_name: str,
        port: int = 80,
        protocol: str = "Http",
        cookie_based_affinity: str = "Disabled",
        request_timeout: int = 30
    ) -> Dict[str, Any]:
        """Update HTTP settings for an Application Gateway backend pool."""
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

            # Find the HTTP settings to update
            settings_found = False
            for i, settings in enumerate(app_gateway.backend_http_settings_collection):
                if settings.name == http_settings_name:
                    settings_found = True
                    # Update the HTTP settings
                    app_gateway.backend_http_settings_collection[i].port = port
                    app_gateway.backend_http_settings_collection[i].protocol = protocol
                    app_gateway.backend_http_settings_collection[i].cookie_based_affinity = cookie_based_affinity
                    app_gateway.backend_http_settings_collection[i].request_timeout = request_timeout
                    break

            if not settings_found:
                return {
                    "error": f"HTTP settings '{http_settings_name}' not found in Application Gateway '{app_gateway_name}'",
                    "status": "failed",
                    "resource_group": resource_group,
                    "app_gateway_name": app_gateway_name
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
                "result": f"HTTP settings '{http_settings_name}' updated successfully",
                "app_gateway": app_gateway_name,
                "http_settings": http_settings_name,
                "resource_group": resource_group
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name,
                "http_settings_name": http_settings_name
            }

    async def manage_app_gateway_ssl(
        self,
        resource_group: str,
        app_gateway_name: str,
        ssl_certificate_name: str,
        certificate_data: str,
        certificate_password: str
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

            # Check if the SSL certificate already exists
            certificate_found = False
            for i, cert in enumerate(app_gateway.ssl_certificates):
                if cert.name == ssl_certificate_name:
                    certificate_found = True
                    # Update the existing certificate
                    app_gateway.ssl_certificates[i].data = certificate_data
                    app_gateway.ssl_certificates[i].password = certificate_password
                    break

            if not certificate_found:
                # Add a new SSL certificate
                app_gateway.ssl_certificates.append({
                    "name": ssl_certificate_name,
                    "data": certificate_data,
                    "password": certificate_password
                })

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
                "result": f"SSL certificate '{ssl_certificate_name}' managed successfully",
                "app_gateway": app_gateway_name,
                "ssl_certificate": ssl_certificate_name,
                "resource_group": resource_group
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name,
                "ssl_certificate_name": ssl_certificate_name
            }

    async def manage_app_gateway_routing(
        self,
        resource_group: str,
        app_gateway_name: str,
        routing_rule_name: str,
        listener_name: str,
        backend_pool_name: str,
        backend_http_settings_name: str,
        rule_type: str = "Basic"
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

            # Check if the listener exists
            listener_found = False
            for listener in app_gateway.http_listeners:
                if listener.name == listener_name:
                    listener_found = True
                    break

            if not listener_found:
                return {
                    "error": f"Listener '{listener_name}' not found in Application Gateway '{app_gateway_name}'",
                    "status": "failed",
                    "resource_group": resource_group,
                    "app_gateway_name": app_gateway_name
                }

            # Check if the backend pool exists
            backend_pool_found = False
            for pool in app_gateway.backend_address_pools:
                if pool.name == backend_pool_name:
                    backend_pool_found = True
                    break

            if not backend_pool_found:
                return {
                    "error": f"Backend pool '{backend_pool_name}' not found in Application Gateway '{app_gateway_name}'",
                    "status": "failed",
                    "resource_group": resource_group,
                    "app_gateway_name": app_gateway_name
                }

            # Check if the backend HTTP settings exist
            http_settings_found = False
            for settings in app_gateway.backend_http_settings_collection:
                if settings.name == backend_http_settings_name:
                    http_settings_found = True
                    break

            if not http_settings_found:
                return {
                    "error": f"Backend HTTP settings '{backend_http_settings_name}' not found in Application Gateway '{app_gateway_name}'",
                    "status": "failed",
                    "resource_group": resource_group,
                    "app_gateway_name": app_gateway_name
                }

            # Check if the routing rule exists
            rule_found = False
            for rule in app_gateway.request_routing_rules:
                if rule.name == routing_rule_name:
                    rule_found = True
                    # Update the existing rule
                    rule.rule_type = rule_type
                    rule.http_listener = {"id": listener.id}
                    rule.backend_address_pool = {"id": pool.id}
                    rule.backend_http_settings = {"id": settings.id}
                    break

            if not rule_found:
                # Add a new routing rule
                app_gateway.request_routing_rules.append({
                    "name": routing_rule_name,
                    "rule_type": rule_type,
                    "http_listener": {"id": listener.id},
                    "backend_address_pool": {"id": pool.id},
                    "backend_http_settings": {"id": settings.id}
                })

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
                "result": f"Routing rule '{routing_rule_name}' managed successfully",
                "app_gateway": app_gateway_name,
                "routing_rule": routing_rule_name,
                "resource_group": resource_group
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name,
                "routing_rule_name": routing_rule_name
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
            # Get the NSG details
            def get_nsg():
                return network_client.network_security_groups.get(
                    resource_group_name=resource_group,
                    network_security_group_name=nsg_name
                )

            nsg = await loop.run_in_executor(None, get_nsg)

            return {
                "result": "NSG information retrieved successfully",
                "nsg_name": nsg_name,
                "resource_group": resource_group,
                "location": nsg.location,
                "security_rules": [rule.as_dict() for rule in nsg.security_rules]
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

    async def create_app_gateway_waf_rule(
        self,
        resource_group: str,
        app_gateway_name: str,
        rule_name: str,
        priority: int,
        match_conditions: list,
        action: str = "Allow"
    ) -> Dict[str, Any]:
        """Create or update a custom WAF rule in an Application Gateway."""
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

            # Check if WAF configuration exists
            if not app_gateway.web_application_firewall_configuration:
                return {
                    "error": f"Application Gateway '{app_gateway_name}' does not have WAF configuration enabled.",
                    "status": "failed",
                    "resource_group": resource_group,
                    "app_gateway_name": app_gateway_name
                }

            # Check if the rule already exists
            rule_found = False
            for rule in app_gateway.web_application_firewall_configuration.custom_rules:
                if rule.name == rule_name:
                    rule_found = True
                    # Update the existing rule
                    rule.priority = priority
                    rule.match_conditions = match_conditions
                    rule.action = action
                    break

            if not rule_found:
                # Add a new custom rule
                app_gateway.web_application_firewall_configuration.custom_rules.append({
                    "name": rule_name,
                    "priority": priority,
                    "match_conditions": match_conditions,
                    "action": action
                })

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
                "result": f"WAF rule '{rule_name}' created or updated successfully",
                "app_gateway": app_gateway_name,
                "rule_name": rule_name,
                "resource_group": resource_group
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name,
                "rule_name": rule_name
            }

    # async def create_app_gateway_with_waf(
    #     self,
    #     resource_group: str,
    #     app_gateway_name: str,
    #     location: str,
    #     backend_pools: list,
    #     waf_configuration: dict
    # ) -> Dict[str, Any]:
    #     """Create an Application Gateway with WAF and configure backend pools."""
    #     network_client = self.client_factory.get_network_client()
    #     import asyncio
    #     loop = asyncio.get_event_loop()

    #     try:
    #         # Create the Application Gateway
    #         def create_app_gateway():
    #             poller = network_client.application_gateways.begin_create_or_update(
    #                 resource_group_name=resource_group,
    #                 application_gateway_name=app_gateway_name,
    #                 parameters={
    #                     "location": location,
    #                     "sku": {"name": "WAF_v2"},
    #                     "web_application_firewall_configuration": waf_configuration,
    #                     "backend_address_pools": backend_pools
    #                 }
    #             )
    #             return poller.result()

    #         app_gateway = await loop.run_in_executor(None, create_app_gateway)

    #         return {
    #             "result": f"Application Gateway '{app_gateway_name}' created successfully with WAF.",
    #             "app_gateway_name": app_gateway_name,
    #             "resource_group": resource_group
    #         }

    #     except Exception as e:
    #         return {
    #             "error": str(e),
    #             "status": "failed",
    #             "resource_group": resource_group,
    #             "app_gateway_name": app_gateway_name
    #         }

    # async def update_app_gateway_backend_pool(
    #     self,
    #     resource_group: str,
    #     app_gateway_name: str,
    #     backend_pool_name: str,
    #     backend_addresses: list
    # ) -> Dict[str, Any]:
    #     """Update an existing Application Gateway's backend pool configuration."""
    #     network_client = self.client_factory.get_network_client()
    #     import asyncio
    #     loop = asyncio.get_event_loop()

    #     try:
    #         # Get the existing Application Gateway
    #         def get_app_gateway():
    #             return network_client.application_gateways.get(
    #                 resource_group_name=resource_group,
    #                 application_gateway_name=app_gateway_name
    #             )

    #         app_gateway = await loop.run_in_executor(None, get_app_gateway)

    #         # Find the backend pool to update
    #         pool_found = False
    #         for pool in app_gateway.backend_address_pools:
    #             if pool.name == backend_pool_name:
    #                 pool_found = True
    #                 pool.backend_addresses = backend_addresses
    #                 break

    #         if not pool_found:
    #             return {
    #                 "error": f"Backend pool '{backend_pool_name}' not found in Application Gateway '{app_gateway_name}'",
    #                 "status": "failed",
    #                 "resource_group": resource_group,
    #                 "app_gateway_name": app_gateway_name
    #             }

    #         # Update the Application Gateway
    #         def update_app_gateway():
    #             poller = network_client.application_gateways.begin_create_or_update(
    #                 resource_group_name=resource_group,
    #                 application_gateway_name=app_gateway_name,
    #                 parameters=app_gateway
    #             )
    #             return poller.result()

    #         updated_app_gateway = await loop.run_in_executor(None, update_app_gateway)

    #         return {
    #             "result": f"Backend pool '{backend_pool_name}' updated successfully.",
    #             "app_gateway_name": app_gateway_name,
    #             "backend_pool_name": backend_pool_name,
    #             "resource_group": resource_group
    #         }

    #     except Exception as e:
    #         return {
    #             "error": str(e),
    #             "status": "failed",
    #             "resource_group": resource_group,
    #             "app_gateway_name": app_gateway_name,
    #             "backend_pool_name": backend_pool_name
    #         }

    async def get_app_gateway_info(
        self,
        resource_group: str,
        app_gateway_name: str
    ) -> Dict[str, Any]:
        """Get detailed information about an Application Gateway."""
        network_client = self.client_factory.get_network_client()
        import asyncio
        loop = asyncio.get_event_loop()

        try:
            # Get the Application Gateway details
            def get_app_gateway():
                return network_client.application_gateways.get(
                    resource_group_name=resource_group,
                    application_gateway_name=app_gateway_name
                )

            app_gateway = await loop.run_in_executor(None, get_app_gateway)

            return {
                "result": "Application Gateway information retrieved successfully.",
                "app_gateway_name": app_gateway_name,
                "resource_group": resource_group,
                "details": app_gateway.as_dict()
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name
            }

    async def update_app_gateway_waf_config(
        self,
        resource_group: str,
        app_gateway_name: str,
        waf_configuration: dict
    ) -> Dict[str, Any]:
        """Update WAF configuration on an Application Gateway."""
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

            # Update the WAF configuration
            app_gateway.web_application_firewall_configuration = waf_configuration

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
                "result": "WAF configuration updated successfully.",
                "app_gateway_name": app_gateway_name,
                "resource_group": resource_group
            }

        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "app_gateway_name": app_gateway_name
            }

    # async def manage_app_gateway_health(
    #     self,
    #     resource_group: str,
    #     app_gateway_name: str,
    #     health_probe_name: str,
    #     probe_configuration: dict
    # ) -> Dict[str, Any]:
    #     """Manage health probes for an Application Gateway."""
    #     network_client = self.client_factory.get_network_client()
    #     import asyncio
    #     loop = asyncio.get_event_loop()

    #     try:
    #         # Get the existing Application Gateway
    #         def get_app_gateway():
    #             return network_client.application_gateways.get(
    #                 resource_group_name=resource_group,
    #                 application_gateway_name=app_gateway_name
    #             )

    #         app_gateway = await loop.run_in_executor(None, get_app_gateway)

    #         # Check if the health probe exists
    #         probe_found = False
    #         for probe in app_gateway.probes:
    #             if probe.name == health_probe_name:
    #                 probe_found = True
    #                 probe.probe_configuration = probe_configuration
    #                 break

    #         if not probe_found:
    #             # Add a new health probe
    #             app_gateway.probes.append({
    #                 "name": health_probe_name,
    #                 "probe_configuration": probe_configuration
    #             })

    #         # Update the Application Gateway
    #         def update_app_gateway():
    #             poller = network_client.application_gateways.begin_create_or_update(
    #                 resource_group_name=resource_group,
    #                 application_gateway_name=app_gateway_name,
    #                 parameters=app_gateway
    #             )
    #             return poller.result()

    #         updated_app_gateway = await loop.run_in_executor(None, update_app_gateway)

    #         return {
    #             "result": f"Health probe '{health_probe_name}' managed successfully.",
    #             "app_gateway_name": app_gateway_name,
    #             "health_probe_name": health_probe_name,
    #             "resource_group": resource_group
    #         }

    #     except Exception as e:
    #         return {
    #             "error": str(e),
    #             "status": "failed",
    #             "resource_group": resource_group,
    #             "app_gateway_name": app_gateway_name,
    #             "health_probe_name": health_probe_name
    #         }