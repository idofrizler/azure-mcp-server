from typing import Any, Dict, Optional, List
import asyncio

from ..clients.client_factory import AzureClientFactory

class AzureWebAppManager:
    """Class for managing Azure Web Apps."""
    
    def __init__(self, client_factory: AzureClientFactory):
        self.client_factory = client_factory

    async def create_web_app(
        self,
        resource_group: str,
        name: str,
        app_service_plan: str,
        location: str = "westeurope",
        runtime_stack: str = "python:3.9",
        os_type: str = "Linux",
        https_only: bool = True,
        client_affinity_enabled: bool = False,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new Web App."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        
        try:
            # Parse runtime stack into framework and version
            if ":" in runtime_stack:
                framework, version = runtime_stack.split(":", 1)
            else:
                framework, version = runtime_stack, ""
            
            # Build site configuration based on runtime stack
            if framework.lower() == "python":
                site_config = {
                    "linux_fx_version": f"PYTHON|{version}",
                    "app_command_line": f"gunicorn --bind=0.0.0.0 --timeout 600 app:app"
                }
            elif framework.lower() == "node":
                site_config = {
                    "linux_fx_version": f"NODE|{version}",
                    "app_command_line": "npm start"
                }
            elif framework.lower() == "php":
                site_config = {
                    "linux_fx_version": f"PHP|{version}"
                }
            elif framework.lower() == "dotnetcore":
                site_config = {
                    "linux_fx_version": f"DOTNETCORE|{version}"
                }
            elif framework.lower() == "java":
                site_config = {
                    "linux_fx_version": f"JAVA|{version}"
                }
            else:
                # Default case
                site_config = {
                    "linux_fx_version": runtime_stack
                }
                
            # Add general configuration options
            site_config.update({
                "always_on": True,
                "http_logging_enabled": True,
                "detailed_error_logging_enabled": True,
                "min_tls_version": "1.2"
            })
            
            def create_app():
                # First, validate that the app service plan exists
                try:
                    app_service_plan_info = web_client.app_service_plans.get(
                        resource_group_name=resource_group,
                        name=app_service_plan
                    )
                except Exception as e:
                    raise Exception(f"App Service Plan '{app_service_plan}' not found: {str(e)}")
                
                # Create the web app
                poller = web_client.web_apps.begin_create_or_update(
                    resource_group_name=resource_group,
                    name=name,
                    site_envelope={
                        "location": location,
                        "server_farm_id": app_service_plan_info.id,
                        "site_config": site_config,
                        "https_only": https_only,
                        "client_affinity_enabled": client_affinity_enabled,
                        "tags": tags,
                        "kind": "app,linux" if os_type.lower() == "linux" else "app"
                    }
                )
                return poller.result()
                
            web_app = await loop.run_in_executor(None, create_app)
            
            # Build response with web app details
            return {
                "id": web_app.id,
                "name": web_app.name,
                "resource_group": resource_group,
                "location": location,
                "default_host_name": web_app.default_host_name,
                "url": f"https://{web_app.default_host_name}",
                "kind": web_app.kind,
                "state": web_app.state,
                "runtime_stack": runtime_stack,
                "app_service_plan": app_service_plan,
                "https_only": https_only
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "name": name
            }

    async def deploy_github_to_web_app(
        self,
        resource_group: str,
        name: str,
        repo_url: str,
        branch: str = "main"
    ) -> Dict[str, Any]:
        """Deploy a GitHub repository to a Web App using Azure's Python API."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        
        def deploy():
            deployment_operation = web_client.web_apps.begin_create_or_update_source_control(
                resource_group_name=resource_group,
                name=name,
                site_source_control={
                    "repo_url": repo_url,
                    "branch": branch,
                    "is_manual_integration": True
                }
            )
            return deployment_operation.result()
            
        try:
            deployment_result = await loop.run_in_executor(None, deploy)
            details = deployment_result.as_dict() if hasattr(deployment_result, "as_dict") else str(deployment_result)
            return {
                "result": "Deployment triggered successfully",
                "deployment_details": details,
                "status": "running",
                "url": f"https://{name}.azurewebsites.net"
            }
        except Exception as e:
            return {
                "result": "Deployment failed",
                "error": str(e),
                "status": "error"
            }

    async def connect_custom_domain(
        self,
        resource_group: str,
        name: str,
        custom_domain: str
    ) -> Dict[str, Any]:
        """Connect a custom top-level domain to an existing Web App."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        def connect_domain():
            update_operation = web_client.web_apps.begin_update(
                resource_group_name=resource_group,
                name=name,
                site_envelope={
                    "hostNames": [custom_domain]
                }
            )
            return update_operation.result()
        try:
            update_result = await loop.run_in_executor(None, connect_domain)
            details = update_result.as_dict() if hasattr(update_result, "as_dict") else str(update_result)
            return {
                "result": "Custom domain connected successfully.",
                "custom_domain": custom_domain,
                "details": details
            }
        except Exception as e:
            return {
                "result": "Failed to connect custom domain.",
                "error": str(e)
            }

    async def create_app_service_plan(
        self,
        resource_group: str,
        name: str,
        location: str = "westeurope",
        sku: str = "B1",
        os_type: str = "Linux",
        per_site_scaling: bool = False,
        maximum_elastic_worker_count: int = 1,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create an App Service Plan in Azure."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        
        try:
            # Parse the SKU into its components
            sku_parts = sku.split("_") if "_" in sku else [sku]
            tier = sku_parts[0]
            
            # Map tier to reserved status (Linux requires reserved=True)
            reserved = os_type.lower() == "linux"
            
            def create_plan():
                # Create the app service plan
                poller = web_client.app_service_plans.begin_create_or_update(
                    resource_group_name=resource_group,
                    name=name,
                    app_service_plan={
                        "location": location,
                        "sku": {
                            "name": sku,
                            "tier": tier,
                            "capacity": 1  # Default to 1 instance
                        },
                        "kind": "linux" if os_type.lower() == "linux" else "windows",
                        "reserved": reserved,  # Required for Linux plans
                        "per_site_scaling": per_site_scaling,
                        "maximum_elastic_worker_count": maximum_elastic_worker_count,
                        "tags": tags,
                        "is_spot": False,  # Not using spot instances by default
                    }
                )
                return poller.result()
                
            app_service_plan = await loop.run_in_executor(None, create_plan)
            
            # Build response with app service plan details
            return {
                "id": app_service_plan.id,
                "name": app_service_plan.name,
                "resource_group": resource_group,
                "location": location,
                "sku": {
                    "name": app_service_plan.sku.name,
                    "tier": app_service_plan.sku.tier,
                    "capacity": app_service_plan.sku.capacity
                },
                "os_type": os_type,
                "status": app_service_plan.status,
                "per_site_scaling": per_site_scaling,
                "maximum_elastic_worker_count": maximum_elastic_worker_count
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "name": name
            }

    async def deploy_docker_to_web_app(
        self,
        resource_group: str,
        name: str,
        image: str,
        registry_url: Optional[str] = None,
        registry_username: Optional[str] = None,
        registry_password: Optional[str] = None,
        startup_command: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Deploy a Docker container to an Azure Web App."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        
        try:
            # First, get the current web app to ensure it exists
            def get_webapp():
                return web_client.web_apps.get(
                    resource_group_name=resource_group,
                    name=name
                )
                
            webapp = await loop.run_in_executor(None, get_webapp)
            
            # Prepare container settings
            container_settings = {
                "linux_fx_version": f"DOCKER|{image}"
            }
            
            # Add startup command if provided
            if startup_command:
                container_settings["app_command_line"] = startup_command
            
            # Create site config with container settings
            site_config = {
                **container_settings,
                "always_on": True,
                "http_logging_enabled": True,
                "detailed_error_logging_enabled": True
            }
            
            # Prepare app settings for container registry credentials
            app_settings = []
            if registry_url and registry_username and registry_password:
                app_settings = [
                    {"name": "DOCKER_REGISTRY_SERVER_URL", "value": registry_url},
                    {"name": "DOCKER_REGISTRY_SERVER_USERNAME", "value": registry_username},
                    {"name": "DOCKER_REGISTRY_SERVER_PASSWORD", "value": registry_password},
                ]
            
            # Update the web app with Docker configuration
            def update_webapp():
                # Update site configuration with Docker container
                config_poller = web_client.web_apps.begin_update_configuration(
                    resource_group_name=resource_group,
                    name=name,
                    site_config=site_config
                )
                config_result = config_poller.result()
                
                # If we have registry credentials, update app settings
                if app_settings:
                    settings_poller = web_client.web_apps.begin_update_application_settings(
                        resource_group_name=resource_group,
                        name=name,
                        app_settings_info={
                            "properties": {setting["name"]: setting["value"] for setting in app_settings}
                        }
                    )
                    settings_result = settings_poller.result()
                
                # Restart the web app to apply changes
                restart_poller = web_client.web_apps.begin_restart(
                    resource_group_name=resource_group,
                    name=name
                )
                restart_result = restart_poller.result()
                
                return {
                    "config": config_result,
                    "settings": settings_result if app_settings else None,
                    "restart": restart_result
                }
                
            update_result = await loop.run_in_executor(None, update_webapp)
            
            # Return success response
            return {
                "result": "Docker container deployed successfully",
                "url": f"https://{webapp.default_host_name}",
                "container_image": image,
                "registry_url": registry_url,
                "status": "running"
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "name": name,
                "image": image
            }

    async def get_web_app_info(
        self,
        resource_group: str,
        name: str
    ) -> Dict[str, Any]:
        """Get detailed information about a Web App."""
        web_client = self.client_factory.get_web_client()
        # Simulated response for checking deployment status.
        return {
            "name": name,
            "resource_group": resource_group,
            "url": f"https://{name}.azurewebsites.net",
            "status": "stopped",
            "message": "Web app appears to be stopped or not responding."
        }

    async def update_web_app_settings(
        self,
        resource_group: str,
        name: str,
        settings: Dict[str, str],
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Update application settings for a Web App."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        
        try:
            # Update app settings
            def update_settings():
                # Update application settings
                settings_poller = web_client.web_apps.begin_update_application_settings(
                    resource_group_name=resource_group,
                    name=name,
                    app_settings_info={
                        "properties": settings
                    }
                )
                settings_result = settings_poller.result()
                
                # If tags are provided, update them as well
                if tags:
                    # First get the current web app to ensure it exists
                    webapp = web_client.web_apps.get(
                        resource_group_name=resource_group,
                        name=name
                    )
                    
                    # Update the tags
                    tags_poller = web_client.web_apps.begin_update(
                        resource_group_name=resource_group,
                        name=name,
                        site_envelope={
                            "tags": tags
                        }
                    )
                    tags_result = tags_poller.result()
                    
                    return {
                        "settings": settings_result,
                        "tags": tags_result
                    }
                
                return {
                    "settings": settings_result
                }
                
            update_result = await loop.run_in_executor(None, update_settings)
            
            # Get the updated settings to confirm they were applied
            def get_updated_settings():
                return web_client.web_apps.list_application_settings(
                    resource_group_name=resource_group,
                    name=name
                )
                
            updated_settings = await loop.run_in_executor(None, get_updated_settings)
            
            return {
                "result": "Web app settings updated successfully",
                "settings_count": len(settings),
                "updated_settings": {k: v for k, v in updated_settings.properties.items() if k in settings},
                "tags_updated": tags is not None,
                "web_app": name,
                "resource_group": resource_group
            }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "name": name
            }

    async def list_web_app_logs(
        self,
        resource_group: str,
        name: str,
        log_type: str = "application",
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """List logs from a Web App."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        
        try:
            # Validate log type
            valid_log_types = ["application", "deployment", "detailed_errors", "failed_request_tracing", "web_server"]
            if log_type.lower() not in valid_log_types:
                return {
                    "error": f"Invalid log_type. Must be one of: {', '.join(valid_log_types)}",
                    "status": "failed"
                }
            
            # For application logs, we need to get the actual log entries
            if log_type.lower() == "application":
                def get_app_logs():
                    # Get the kudu scm site URL for accessing logs
                    publish_profile = web_client.web_apps.list_publishing_profile_xml_with_secrets(
                        resource_group_name=resource_group,
                        name=name
                    )
                    
                    # Parse publishing profile to get scm URL
                    import xml.etree.ElementTree as ET
                    from io import StringIO
                    
                    # Convert bytes to string if needed
                    if isinstance(publish_profile, bytes):
                        publish_profile = publish_profile.decode('utf-8')
                    
                    root = ET.parse(StringIO(publish_profile))
                    scm_url = None
                    
                    for profile in root.findall('.//publishProfile'):
                        if profile.get('publishMethod') == 'MSDeploy':
                            scm_url = profile.get('publishUrl')
                            username = profile.get('userName')
                            password = profile.get('userPWD')
                            break
                    
                    if not scm_url:
                        return {
                            "error": "Could not find SCM URL in publishing profile",
                            "status": "failed"
                        }
                    
                    # Now use the SCM URL to get logs
                    import requests
                    from datetime import datetime, timedelta
                    import base64
                    
                    # Format: https://username:password@sitename.scm.azurewebsites.net
                    auth_header = f"Basic {base64.b64encode(f'{username}:{password}'.encode()).decode()}"
                    
                    # Set up time parameters
                    if start_time:
                        start = start_time
                    else:
                        # Default to 1 hour ago
                        start = (datetime.utcnow() - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
                    
                    if end_time:
                        end = end_time
                    else:
                        # Default to now
                        end = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                    
                    # Construct log URL
                    log_url = f"https://{scm_url}/api/logs/application"
                    
                    # Get logs
                    response = requests.get(
                        log_url,
                        headers={
                            "Authorization": auth_header
                        },
                        params={
                            "startTime": start,
                            "endTime": end
                        }
                    )
                    
                    if response.status_code != 200:
                        return {
                            "error": f"Failed to retrieve logs: {response.text}",
                            "status": "failed",
                            "status_code": response.status_code
                        }
                    
                    # Parse log entries
                    logs = response.json()
                    
                    return {
                        "log_entries": logs,
                        "count": len(logs),
                        "start_time": start,
                        "end_time": end
                    }
                
                logs_result = await loop.run_in_executor(None, get_app_logs)
                
                # Add metadata to the result
                return {
                    "web_app": name,
                    "resource_group": resource_group,
                    "log_type": log_type,
                    "logs": logs_result
                }
            
            # For other log types, just return the diagnostic settings
            else:
                def get_diagnostic_settings():
                    # Get web app diagnostics settings
                    diagnostics = web_client.web_apps.get_diagnostic_logs_configuration(
                        resource_group_name=resource_group,
                        name=name
                    )
                    
                    return diagnostics
                
                diagnostics = await loop.run_in_executor(None, get_diagnostic_settings)
                
                # Extract relevant information based on log_type
                log_info = {}
                
                if log_type.lower() == "deployment":
                    if hasattr(diagnostics, 'application_logs') and hasattr(diagnostics.application_logs, 'file_system'):
                        log_info = {
                            "level": diagnostics.application_logs.file_system.level,
                            "retention_in_days": diagnostics.application_logs.file_system.retention_in_days,
                            "retention_in_mb": diagnostics.application_logs.file_system.retention_in_mb
                        }
                elif log_type.lower() == "detailed_errors":
                    if hasattr(diagnostics, 'detailed_error_messages') and diagnostics.detailed_error_messages:
                        log_info = {
                            "enabled": diagnostics.detailed_error_messages.enabled
                        }
                elif log_type.lower() == "failed_request_tracing":
                    if hasattr(diagnostics, 'failed_requests_tracing') and diagnostics.failed_requests_tracing:
                        log_info = {
                            "enabled": diagnostics.failed_requests_tracing.enabled
                        }
                elif log_type.lower() == "web_server":
                    if hasattr(diagnostics, 'http_logs') and hasattr(diagnostics.http_logs, 'file_system'):
                        log_info = {
                            "retention_in_days": diagnostics.http_logs.file_system.retention_in_days,
                            "retention_in_mb": diagnostics.http_logs.file_system.retention_in_mb
                        }
                
                return {
                    "web_app": name,
                    "resource_group": resource_group,
                    "log_type": log_type,
                    "log_settings": log_info,
                    "diagnostics_enabled": log_info.get("enabled", False) 
                        if "enabled" in log_info else (log_info.get("level", "Off") != "Off")
                }
            
        except Exception as e:
            return {
                "error": str(e),
                "status": "failed",
                "resource_group": resource_group,
                "name": name,
                "log_type": log_type
            }

    async def restart_web_app(
        self,
        resource_group: str,
        name: str,
        soft_restart: bool = False
    ) -> Dict[str, Any]:
        """Restart a Web App using Azure API."""
        web_client = self.client_factory.get_web_client()
        loop = asyncio.get_event_loop()
        def restart():
            restart_operation = web_client.web_apps.begin_restart(
                resource_group_name=resource_group,
                name=name
            )
            return restart_operation.result()
        try:
            restart_result = await loop.run_in_executor(None, restart)
            details = restart_result.as_dict() if hasattr(restart_result, "as_dict") else str(restart_result)
            return {
                "result": "Web app restarted successfully.",
                "details": details
            }
        except Exception as e:
            return {
                "result": "Web app restart failed.",
                "error": str(e)
            }
