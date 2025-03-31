#!/usr/bin/env python

import os
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

import dotenv
from mcp.server.fastmcp import FastMCP
from azure.identity import DeviceCodeCredential, DefaultAzureCredential, ClientSecretCredential
from azure.mgmt.resource import ResourceManagementClient
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.containerregistry import ContainerRegistryManagementClient
from azure.mgmt.web import WebSiteManagementClient
from azure.mgmt.web.models import SiteConfig
import base64

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

def get_compute_client() -> ComputeManagementClient:
    """Get an Azure Compute Management client using appropriate authentication."""
    if config.client_id and config.client_secret and config.tenant_id:
        credential = ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret
        )
    elif config.tenant_id:
        credential = DeviceCodeCredential(tenant_id=config.tenant_id)
    else:
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
    
    return ComputeManagementClient(
        credential=credential,
        subscription_id=config.subscription_id
    )

def get_network_client() -> NetworkManagementClient:
    """Get an Azure Network Management client using appropriate authentication."""
    if config.client_id and config.client_secret and config.tenant_id:
        credential = ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret
        )
    elif config.tenant_id:
        credential = DeviceCodeCredential(tenant_id=config.tenant_id)
    else:
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
    
    return NetworkManagementClient(
        credential=credential,
        subscription_id=config.subscription_id
    )

def get_sql_client() -> SqlManagementClient:
    """Get an Azure SQL Management client using appropriate authentication."""
    if config.client_id and config.client_secret and config.tenant_id:
        credential = ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret
        )
    elif config.tenant_id:
        credential = DeviceCodeCredential(tenant_id=config.tenant_id)
    else:
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
    
    return SqlManagementClient(
        credential=credential,
        subscription_id=config.subscription_id
    )

def get_container_registry_client() -> ContainerRegistryManagementClient:
    """Get an Azure Container Registry Management client using appropriate authentication."""
    if config.client_id and config.client_secret and config.tenant_id:
        credential = ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret
        )
    elif config.tenant_id:
        credential = DeviceCodeCredential(tenant_id=config.tenant_id)
    else:
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
    
    return ContainerRegistryManagementClient(
        credential=credential,
        subscription_id=config.subscription_id
    )

def get_web_client() -> WebSiteManagementClient:
    """Get an Azure Web App Management client using appropriate authentication."""
    if config.client_id and config.client_secret and config.tenant_id:
        credential = ClientSecretCredential(
            tenant_id=config.tenant_id,
            client_id=config.client_id,
            client_secret=config.client_secret
        )
    elif config.tenant_id:
        credential = DeviceCodeCredential(tenant_id=config.tenant_id)
    else:
        credential = DefaultAzureCredential(exclude_shared_token_cache_credential=True)
    
    return WebSiteManagementClient(
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

@mcp.tool(description="Creates a new virtual machine in the specified resource group.")
async def create_vm(
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
    """Create a new virtual machine in Azure.
    
    Args:
        resource_group: Name of the resource group
        vm_name: Name for the new virtual machine
        location: Azure region for the VM
        vm_size: Size of the VM (e.g., Standard_DS1_v2)
        admin_username: Administrator username for the VM
        os_disk_size_gb: Size of the OS disk in GB
        image_reference: Dictionary specifying the OS image to use
    
    Returns:
        Dictionary containing the created VM's details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    compute_client = get_compute_client()
    network_client = get_network_client()

    # Create a NIC for the VM
    nic_name = f"{vm_name}-nic"
    vnet_name = f"{vm_name}-vnet"
    subnet_name = f"{vm_name}-subnet"
    ip_config_name = f"{vm_name}-ip-config"
    public_ip_name = f"{vm_name}-public-ip"

    # Create Virtual Network
    vnet_params = {
        'location': location,
        'address_space': {
            'address_prefixes': ['10.0.0.0/16']
        }
    }
    vnet = network_client.virtual_networks.begin_create_or_update(
        resource_group,
        vnet_name,
        vnet_params
    ).result()

    # Create Subnet
    subnet_params = {
        'address_prefix': '10.0.0.0/24'
    }
    subnet = network_client.subnets.begin_create_or_update(
        resource_group,
        vnet_name,
        subnet_name,
        subnet_params
    ).result()

    # Create Public IP
    public_ip_params = {
        'location': location,
        'sku': {
            'name': 'Standard'
        },
        'public_ip_allocation_method': 'Static',
        'public_ip_address_version': 'IPV4'
    }
    public_ip = network_client.public_ip_addresses.begin_create_or_update(
        resource_group,
        public_ip_name,
        public_ip_params
    ).result()

    # Create Network Interface
    nic_params = {
        'location': location,
        'ip_configurations': [{
            'name': ip_config_name,
            'subnet': {
                'id': subnet.id
            },
            'public_ip_address': {
                'id': public_ip.id
            }
        }]
    }
    nic = network_client.network_interfaces.begin_create_or_update(
        resource_group,
        nic_name,
        nic_params
    ).result()

    # Generate a random password for the VM
    import secrets
    import string
    password_chars = string.ascii_letters + string.digits + "!@#$%^&*"
    admin_password = ''.join(secrets.choice(password_chars) for _ in range(16))

    # Create VM
    vm_parameters = {
        'location': location,
        'os_profile': {
            'computer_name': vm_name,
            'admin_username': admin_username,
            'admin_password': admin_password,
        },
        'hardware_profile': {
            'vm_size': vm_size
        },
        'storage_profile': {
            'image_reference': image_reference,
            'os_disk': {
                'name': f'{vm_name}-os-disk',
                'disk_size_gb': os_disk_size_gb,
                'create_option': 'FromImage',
                'managed_disk': {
                    'storage_account_type': 'Premium_LRS'
                }
            }
        },
        'network_profile': {
            'network_interfaces': [{
                'id': nic.id
            }]
        }
    }

    vm_creation = compute_client.virtual_machines.begin_create_or_update(
        resource_group,
        vm_name,
        vm_parameters
    )
    vm = vm_creation.result()

    return {
        'id': vm.id,
        'name': vm.name,
        'location': vm.location,
        'vm_size': vm.hardware_profile.vm_size,
        'provisioning_state': vm.provisioning_state,
        'public_ip': public_ip.ip_address,
        'admin_username': admin_username,
        'admin_password': admin_password  # Return the generated password
    }

@mcp.tool(description="Creates a new resource group in the Azure subscription.")
async def create_resource_group(
    name: str,
    location: str = "westeurope",
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Create a new resource group in Azure.
    
    Args:
        name: Name of the resource group to create
        location: Azure region where the resource group will be created
        tags: Optional dictionary of tags to apply to the resource group
    
    Returns:
        Dictionary containing the created resource group's details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")
    
    client = get_resource_client()
    
    parameters = {
        'location': location,
        'tags': tags or {}
    }
    
    resource_group = client.resource_groups.create_or_update(
        name,
        parameters
    )
    
    return {
        'id': resource_group.id,
        'name': resource_group.name,
        'location': resource_group.location,
        'tags': resource_group.tags or {},
        'properties': resource_group.properties,
        'provisioning_state': resource_group.properties.provisioning_state
    }

@mcp.tool(description="Gets detailed information about a virtual machine including its status, network interfaces, and diagnostics.")
async def get_vm_info(
    resource_group: str,
    vm_name: str
) -> Dict[str, Any]:
    """Get detailed information about a virtual machine.
    
    Args:
        resource_group: Name of the resource group containing the VM
        vm_name: Name of the virtual machine
    
    Returns:
        Dictionary containing detailed VM information including status, network, and diagnostics
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    compute_client = get_compute_client()
    network_client = get_network_client()

    # Get VM details
    vm = compute_client.virtual_machines.get(
        resource_group,
        vm_name,
        expand='instanceView'
    )

    # Get VM status
    statuses = {
        status.code.replace('PowerState/', ''): status.display_status
        for status in vm.instance_view.statuses
        if status.code.startswith('PowerState/')
    }

    # Get network interfaces
    network_interfaces = []
    for nic_ref in vm.network_profile.network_interfaces:
        nic_id = nic_ref.id
        nic_name = nic_id.split('/')[-1]
        nic = network_client.network_interfaces.get(resource_group, nic_name)
        
        # Get public IP if any
        public_ip = None
        if nic.ip_configurations[0].public_ip_address:
            public_ip_id = nic.ip_configurations[0].public_ip_address.id
            public_ip_name = public_ip_id.split('/')[-1]
            public_ip = network_client.public_ip_addresses.get(
                resource_group,
                public_ip_name
            )

        network_interfaces.append({
            'name': nic_name,
            'private_ip': nic.ip_configurations[0].private_ip_address,
            'public_ip': public_ip.ip_address if public_ip else None,
            'mac_address': nic.mac_address,
            'dns_servers': nic.dns_settings.dns_servers if nic.dns_settings else [],
            'enable_ip_forwarding': nic.enable_ip_forwarding
        })

    # Get disk information
    os_disk = {
        'name': vm.storage_profile.os_disk.name,
        'size_gb': vm.storage_profile.os_disk.disk_size_gb,
        'storage_type': vm.storage_profile.os_disk.managed_disk.storage_account_type,
        'state': 'Attached'
    }

    data_disks = [
        {
            'name': disk.name,
            'size_gb': disk.disk_size_gb,
            'storage_type': disk.managed_disk.storage_account_type,
            'lun': disk.lun,
            'state': 'Attached'
        }
        for disk in vm.storage_profile.data_disks
    ]

    # Get VM metrics/diagnostics
    vm_size = compute_client.virtual_machine_sizes.list(vm.location)
    size_details = next(
        (size for size in vm_size if size.name == vm.hardware_profile.vm_size),
        None
    )

    return {
        'id': vm.id,
        'name': vm.name,
        'resource_group': resource_group,
        'location': vm.location,
        'vm_size': vm.hardware_profile.vm_size,
        'size_details': {
            'cores': size_details.number_of_cores if size_details else None,
            'memory_gb': size_details.memory_in_mb / 1024 if size_details else None,
            'max_data_disks': size_details.max_data_disk_count if size_details else None
        },
        'os_type': vm.storage_profile.os_disk.os_type,
        'provisioning_state': vm.provisioning_state,
        'power_state': statuses,
        'network_interfaces': network_interfaces,
        'storage': {
            'os_disk': os_disk,
            'data_disks': data_disks
        },
        'boot_diagnostics_enabled': vm.diagnostics_profile.boot_diagnostics.enabled if vm.diagnostics_profile and vm.diagnostics_profile.boot_diagnostics else False,
        'vm_agent_status': {
            status.code: status.message
            for status in vm.instance_view.vm_agent.statuses
        } if vm.instance_view.vm_agent else None,
        'maintenance_state': vm.instance_view.maintenance_redeploy_status.is_customer_initiated_maintenance_allowed if vm.instance_view.maintenance_redeploy_status else None,
        'ultra_ssd_enabled': vm.additional_capabilities.ultra_ssd_enabled if vm.additional_capabilities else False
    }

@mcp.tool(description="Creates or updates a Network Security Group with specified security rules.")
async def create_or_update_nsg(
    resource_group: str,
    nsg_name: str,
    name: str,
    protocol: str,
    source_address_prefix: str,
    source_port_range: str,
    destination_address_prefix: str,
    destination_port_range: str,
    access: str,
    priority: int,
    direction: str,
    location: str = "westeurope",
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Create or update a Network Security Group with a single security rule.
    
    Args:
        resource_group: Name of the resource group
        nsg_name: Name for the NSG
        name: Rule name
        protocol: Protocol (Tcp, Udp, *)
        source_address_prefix: Source address or CIDR
        source_port_range: Source port or range
        destination_address_prefix: Destination address or CIDR
        destination_port_range: Destination port or range
        access: Allow or Deny
        priority: Rule priority (100-4096)
        direction: Inbound or Outbound
        location: Azure region for the NSG (default to place it in same region as the resource group)
        tags: Optional tags for the NSG
    
    Returns:
        Dictionary containing the NSG details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get existing NSG if it exists
    try:
        existing_nsg = network_client.network_security_groups.get(resource_group, nsg_name)
        existing_rules = list(existing_nsg.security_rules) if existing_nsg.security_rules else []
        location = existing_nsg.location
    except Exception:
        existing_rules = []

    # Create the new security rule
    security_rule = {
        'name': name,
        'protocol': protocol,
        'source_address_prefix': source_address_prefix,
        'source_port_range': source_port_range,
        'destination_address_prefix': destination_address_prefix,
        'destination_port_range': destination_port_range,
        'access': access,
        'priority': priority,
        'direction': direction
    }

    # Update existing rules or add new one
    final_rules = []
    rule_updated = False
    
    # First, copy over existing rules, updating if we find a matching name
    for rule in existing_rules:
        if rule.name == name:
            final_rules.append(security_rule)
            rule_updated = True
        else:
            final_rules.append({
                'name': rule.name,
                'protocol': rule.protocol,
                'source_address_prefix': rule.source_address_prefix,
                'source_port_range': rule.source_port_range,
                'destination_address_prefix': rule.destination_address_prefix,
                'destination_port_range': rule.destination_port_range,
                'access': rule.access,
                'priority': rule.priority,
                'direction': rule.direction
            })
    
    # If we didn't update an existing rule, add the new one
    if not rule_updated:
        final_rules.append(security_rule)

    # Create NSG parameters
    parameters = {
        'location': location,
        'tags': tags or {},
        'security_rules': final_rules
    }

    # Create or update the NSG
    nsg = network_client.network_security_groups.begin_create_or_update(
        resource_group,
        nsg_name,
        parameters
    ).result()

    return {
        'id': nsg.id,
        'name': nsg.name,
        'location': nsg.location,
        'security_rules': [
            {
                'name': rule.name,
                'protocol': rule.protocol,
                'source_address_prefix': rule.source_address_prefix,
                'source_port_range': rule.source_port_range,
                'destination_address_prefix': rule.destination_address_prefix,
                'destination_port_range': rule.destination_port_range,
                'access': rule.access,
                'priority': rule.priority,
                'direction': rule.direction
            }
            for rule in nsg.security_rules or []
        ]
    }

@mcp.tool(description="Associates a Network Security Group with a network interface.")
async def associate_nsg_with_nic(
    resource_group: str,
    nsg_name: str,
    nic_name: str
) -> Dict[str, Any]:
    """Associate an NSG with a network interface.
    
    Args:
        resource_group: Name of the resource group
        nsg_name: Name of the NSG to associate
        nic_name: Name of the network interface
    
    Returns:
        Dictionary containing the updated network interface details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get the NSG
    nsg = network_client.network_security_groups.get(resource_group, nsg_name)

    # Get the network interface
    nic = network_client.network_interfaces.get(resource_group, nic_name)

    # Update the network interface with the NSG reference
    nic_params = {
        'location': nic.location,
        'network_security_group': {
            'id': nsg.id
        },
        'ip_configurations': nic.ip_configurations
    }

    # Update the network interface
    updated_nic = network_client.network_interfaces.begin_create_or_update(
        resource_group,
        nic_name,
        nic_params
    ).result()

    return {
        'id': updated_nic.id,
        'name': updated_nic.name,
        'network_security_group': {
            'id': updated_nic.network_security_group.id if updated_nic.network_security_group else None
        },
        'ip_configurations': [
            {
                'name': ip_config.name,
                'private_ip_address': ip_config.private_ip_address,
                'public_ip_address': {
                    'id': ip_config.public_ip_address.id if ip_config.public_ip_address else None
                }
            }
            for ip_config in updated_nic.ip_configurations
        ]
    }

@mcp.tool(description="Executes commands on an Azure VM over SSH with session management")
async def run_vm_commands(
    resource_group: str,
    vm_name: str,
    commands: List[str],
    username: str,
    password: str = "",
    timeout: int = 30,
    use_existing_session: bool = True
) -> Dict[str, Any]:
    """Execute commands on an Azure VM using a managed SSH session.
    
    Args:
        resource_group: Name of the resource group
        vm_name: Name of the VM
        commands: List of commands to execute
        username: SSH username
        password: SSH password (empty string if not provided)
        timeout: Command timeout in seconds
        use_existing_session: Whether to reuse an existing SSH session if available
    
    Returns:
        Dictionary containing results for each command
    """
    try:
        from paramiko import SSHClient, AutoAddPolicy
        from contextlib import contextmanager
    except ImportError:
        raise ImportError("paramiko package is required. Please install it with: pip install paramiko")
    
    # Store SSH sessions in a class-level dict
    if not hasattr(run_vm_commands, '_sessions'):
        run_vm_commands._sessions = {}
    
    @contextmanager
    def get_ssh_session(hostname: str, username: str, password: str = ""):
        session_key = f"{username}@{hostname}"
        
        # Try to reuse existing session
        if use_existing_session and session_key in run_vm_commands._sessions:
            client = run_vm_commands._sessions[session_key]
            try:
                # Test if session is still alive
                client.get_transport().check_channel_window()
                yield client
                return
            except Exception:
                # Session died, clean it up
                client.close()
                del run_vm_commands._sessions[session_key]
        
        # Create new session
        client = SSHClient()
        client.set_missing_host_key_policy(AutoAddPolicy())
        
        # Connect with password if provided
        connect_kwargs = {
            'username': username,
            'timeout': timeout
        }
        if password:  # Only add password if it's not empty
            connect_kwargs['password'] = password
            
        client.connect(hostname, **connect_kwargs)
        
        if use_existing_session:
            run_vm_commands._sessions[session_key] = client
        
        try:
            yield client
        finally:
            if not use_existing_session:
                client.close()
    
    # Get VM info to find its public IP
    compute_client = get_compute_client()
    vm_info = compute_client.virtual_machines.get(resource_group, vm_name)
    network_client = get_network_client()
    
    # Get the VM's public IP
    nic = network_client.network_interfaces.get(
        resource_group,
        vm_info.network_profile.network_interfaces[0].id.split('/')[-1]
    )
    public_ip_id = nic.ip_configurations[0].public_ip_address.id
    public_ip = network_client.public_ip_addresses.get(
        resource_group,
        public_ip_id.split('/')[-1]
    )
    
    results = []
    try:
        with get_ssh_session(public_ip.ip_address, username, password) as ssh:
            for cmd in commands:
                stdin, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
                exit_code = stdout.channel.recv_exit_status()
                results.append({
                    'command': cmd,
                    'stdout': stdout.read().decode('utf-8'),
                    'stderr': stderr.read().decode('utf-8'),
                    'exit_code': exit_code,
                    'success': exit_code == 0
                })
    except Exception as e:
        return {
            'error': str(e),
            'results': results,
            'session_maintained': False
        }
    
    return {
        'results': results,
        'session_maintained': use_existing_session,
        'hostname': public_ip.ip_address
    }

@mcp.tool(description="Creates an Application Gateway with WAF and configures backend pools.")
async def create_app_gateway_with_waf(
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
    """Create an Application Gateway with WAF and configure backend pools.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name for the Application Gateway
        backend_pool_name: Name for the backend pool
        backend_fqdns: List of backend FQDNs (optional)
        backend_ips: List of backend IP addresses (optional)
        location: Azure region for the Application Gateway
        sku_name: SKU name (WAF_v2 recommended for WAF)
        capacity: Number of Application Gateway instances
        waf_enabled: Whether to enable WAF
        waf_mode: WAF mode (Detection or Prevention)
        frontend_port: Frontend port number
        backend_port: Backend port number
        tags: Optional tags for the Application Gateway
    
    Returns:
        Dictionary containing the Application Gateway details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    if not backend_fqdns and not backend_ips:
        raise ValueError("Either backend_fqdns or backend_ips must be provided")

    network_client = get_network_client()

    # Create public IP for the Application Gateway
    public_ip_name = f"{app_gateway_name}-pip"
    public_ip_params = {
        'location': location,
        'sku': {
            'name': 'Standard'
        },
        'public_ip_allocation_method': 'Static',
        'public_ip_address_version': 'IPV4'
    }
    
    public_ip = network_client.public_ip_addresses.begin_create_or_update(
        resource_group,
        public_ip_name,
        public_ip_params
    ).result()

    # Create VNet and subnet for the Application Gateway
    vnet_name = f"{app_gateway_name}-vnet"
    subnet_name = "appgw-subnet"
    
    vnet_params = {
        'location': location,
        'address_space': {
            'address_prefixes': ['10.0.0.0/16']
        },
        'subnets': [{
            'name': subnet_name,
            'address_prefix': '10.0.0.0/24'
        }]
    }
    
    vnet = network_client.virtual_networks.begin_create_or_update(
        resource_group,
        vnet_name,
        vnet_params
    ).result()

    subnet = vnet.subnets[0]

    # Prepare backend pool configuration
    backend_addresses = []
    if backend_fqdns:
        backend_addresses.extend([{'fqdn': fqdn} for fqdn in backend_fqdns])
    if backend_ips:
        backend_addresses.extend([{'ip_address': ip} for ip in backend_ips])

    # Create Application Gateway parameters
    app_gateway_params = {
        'location': location,
        'tags': tags or {},
        'sku': {
            'name': sku_name,
            'tier': 'WAF_v2',
            'capacity': capacity
        },
        'gateway_ip_configurations': [{
            'name': 'appGatewayIpConfig',
            'subnet': {
                'id': subnet.id
            }
        }],
        'frontend_ip_configurations': [{
            'name': 'appGwPublicFrontendIp',
            'public_ip_address': {
                'id': public_ip.id
            }
        }],
        'frontend_ports': [{
            'name': 'appGwFrontendPort',
            'port': frontend_port
        }],
        'backend_address_pools': [{
            'name': backend_pool_name,
            'backend_addresses': backend_addresses
        }],
        'backend_http_settings_collection': [{
            'name': 'appGwBackendHttpSettings',
            'port': backend_port,
            'protocol': 'Http',
            'cookie_based_affinity': 'Disabled',
            'request_timeout': 30,
            'probe': None  # Remove the probe for now to simplify configuration
        }],
        'http_listeners': [{
            'name': 'appGwHttpListener',
            'frontend_ip_configuration': {
                'id': f"/subscriptions/{config.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{app_gateway_name}/frontendIPConfigurations/appGwPublicFrontendIp"
            },
            'frontend_port': {
                'id': f"/subscriptions/{config.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{app_gateway_name}/frontendPorts/appGwFrontendPort"
            },
            'protocol': 'Http'
        }],
        'request_routing_rules': [{
            'name': 'rule1',
            'rule_type': 'Basic',
            'priority': 100,
            'http_listener': {
                'id': f"/subscriptions/{config.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{app_gateway_name}/httpListeners/appGwHttpListener"
            },
            'backend_address_pool': {
                'id': f"/subscriptions/{config.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{app_gateway_name}/backendAddressPools/{backend_pool_name}"
            },
            'backend_http_settings': {
                'id': f"/subscriptions/{config.subscription_id}/resourceGroups/{resource_group}/providers/Microsoft.Network/applicationGateways/{app_gateway_name}/backendHttpSettingsCollection/appGwBackendHttpSettings"
            }
        }],
        'web_application_firewall_configuration': {
            'enabled': waf_enabled,
            'firewall_mode': waf_mode,
            'rule_set_type': 'OWASP',
            'rule_set_version': '3.2',
            'file_upload_limit_mb': 100,
            'request_body_check': True,
            'max_request_body_size_kb': 128
        } if waf_enabled else None
    }

    # Create the Application Gateway
    app_gateway = network_client.application_gateways.begin_create_or_update(
        resource_group,
        app_gateway_name,
        app_gateway_params
    ).result()

    return {
        'id': app_gateway.id,
        'name': app_gateway.name,
        'public_ip': public_ip.ip_address,
        'backend_pool': {
            'name': backend_pool_name,
            'addresses': backend_addresses
        },
        'waf_enabled': waf_enabled,
        'waf_mode': waf_mode if waf_enabled else None,
        'provisioning_state': app_gateway.provisioning_state
    }

@mcp.tool(description="Creates or updates a custom WAF rule in an Application Gateway.")
async def create_app_gateway_waf_rule(
    resource_group: str,
    app_gateway_name: str,
    rule_name: str,
    priority: int,
    rule_type: str = "MatchRule",
    action: str = "Block",
    match_conditions: List[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Create or update a custom WAF rule in an Application Gateway.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
        rule_name: Name for the custom rule
        priority: Rule priority (1-100)
        rule_type: Rule type (default: MatchRule)
        action: Action to take (Allow/Block/Log)
        match_conditions: List of match conditions, each containing:
            - match_variables: List of variables to match (Headers, QueryString, etc.)
            - operator: Operator for matching (Contains, Equals, etc.)
            - match_values: Values to match against
            - transforms: Optional transformations to apply
    
    Returns:
        Dictionary containing the updated WAF policy details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get the existing Application Gateway
    app_gateway = network_client.application_gateways.get(
        resource_group,
        app_gateway_name
    )

    # Prepare the custom rules
    custom_rules = []
    if app_gateway.web_application_firewall_configuration and hasattr(app_gateway.web_application_firewall_configuration, 'custom_rules'):
        custom_rules.extend(app_gateway.web_application_firewall_configuration.custom_rules or [])

    # Create or update the new rule
    new_rule = {
        'name': rule_name,
        'priority': priority,
        'rule_type': rule_type,
        'match_conditions': match_conditions or [],
        'action': action
    }

    # Update existing rule or add new one
    rule_updated = False
    for i, rule in enumerate(custom_rules):
        if rule.name == rule_name:
            custom_rules[i] = new_rule
            rule_updated = True
            break
    
    if not rule_updated:
        custom_rules.append(new_rule)

    # Update the WAF configuration
    waf_config = app_gateway.web_application_firewall_configuration
    waf_config['custom_rules'] = custom_rules

    # Update the Application Gateway
    app_gateway_params = {
        'location': app_gateway.location,
        'sku': app_gateway.sku,
        'gateway_ip_configurations': app_gateway.gateway_ip_configurations,
        'frontend_ip_configurations': app_gateway.frontend_ip_configurations,
        'frontend_ports': app_gateway.frontend_ports,
        'backend_address_pools': app_gateway.backend_address_pools,
        'backend_http_settings_collection': app_gateway.backend_http_settings_collection,
        'http_listeners': app_gateway.http_listeners,
        'request_routing_rules': app_gateway.request_routing_rules,
        'web_application_firewall_configuration': waf_config
    }

    # Apply the update
    updated_gateway = network_client.application_gateways.begin_create_or_update(
        resource_group,
        app_gateway_name,
        app_gateway_params
    ).result()

    return {
        'id': updated_gateway.id,
        'name': updated_gateway.name,
        'custom_rules': [
            {
                'name': rule.name,
                'priority': rule.priority,
                'rule_type': rule.rule_type,
                'action': rule.action,
                'match_conditions': rule.match_conditions
            }
            for rule in updated_gateway.web_application_firewall_configuration.custom_rules or []
        ] if updated_gateway.web_application_firewall_configuration else []
    }

@mcp.tool(description="Deletes a resource group and all resources contained within it. This is a destructive operation and cannot be undone.")
async def delete_resource_group(
    resource_group: str
) -> Dict[str, Any]:
    """Delete a resource group and all its resources.
    
    Args:
        resource_group: Name of the resource group to delete
    
    Returns:
        Dictionary containing the deletion operation status
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")
    
    client = get_resource_client()
    
    try:
        # Begin the deletion operation
        deletion_poller = client.resource_groups.begin_delete(resource_group)
        # Wait for the deletion to complete
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

@mcp.tool(description="Creates a new Azure SQL Server with optional firewall rules.")
async def create_sql_server(
    resource_group: str,
    server_name: str,
    location: str = "westeurope",
    admin_login: str = "sqladmin",
    allow_azure_services: bool = True,
    allow_all_ips: bool = False,
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Create a new Azure SQL Server.
    
    Args:
        resource_group: Name of the resource group
        server_name: Name for the SQL server (must be globally unique)
        location: Azure region for the server
        admin_login: Administrator login name
        allow_azure_services: Whether to allow Azure services to access the server
        allow_all_ips: Whether to allow access from any IP (0.0.0.0-255.255.255.255)
        tags: Optional tags for the server
    
    Returns:
        Dictionary containing the created SQL server's details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    sql_client = get_sql_client()

    # Generate a strong random password
    import secrets
    import string
    password_chars = string.ascii_letters + string.digits + "!@#$%^&*"
    admin_password = ''.join(secrets.choice(password_chars) for _ in range(16))

    # Create server parameters
    parameters = {
        'location': location,
        'properties': {
            'administrator_login': admin_login,
            'administrator_login_password': admin_password,
            'version': '12.0',  # Latest version
            'minimal_tls_version': '1.2',  # Enforce TLS 1.2
            'public_network_access': 'Enabled'
        },
        'tags': tags or {}
    }

    # Create the server
    server = sql_client.servers.begin_create_or_update(
        resource_group,
        server_name,
        parameters
    ).result()

    # Add firewall rules if requested
    firewall_rules = []
    
    if allow_azure_services:
        # Allow Azure services rule
        azure_services_rule = sql_client.firewall_rules.create_or_update(
            resource_group,
            server_name,
            "AllowAllWindowsAzureIps",
            {
                'start_ip_address': '0.0.0.0',
                'end_ip_address': '0.0.0.0'
            }
        )
        firewall_rules.append(azure_services_rule)

    if allow_all_ips:
        # Allow all IPs rule
        all_ips_rule = sql_client.firewall_rules.create_or_update(
            resource_group,
            server_name,
            "AllowAllIPs",
            {
                'start_ip_address': '0.0.0.0',
                'end_ip_address': '255.255.255.255'
            }
        )
        firewall_rules.append(all_ips_rule)

    return {
        'id': server.id,
        'name': server.name,
        'location': server.location,
        'fully_qualified_domain_name': server.fully_qualified_domain_name,
        'admin_login': admin_login,
        'admin_password': admin_password,  # Return the generated password
        'firewall_rules': [
            {
                'name': rule.name,
                'start_ip_address': rule.start_ip_address,
                'end_ip_address': rule.end_ip_address
            }
            for rule in firewall_rules
        ]
    }

@mcp.tool(description="Creates a new database in an existing Azure SQL Server.")
async def create_sql_database(
    resource_group: str,
    server_name: str,
    database_name: str,
    location: str = "westeurope",
    sku_name: str = "Basic",
    max_size_bytes: int = 2147483648,  # 2GB
    zone_redundant: bool = False,
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Create a new database in an Azure SQL Server.
    
    Args:
        resource_group: Name of the resource group
        server_name: Name of the existing SQL server
        database_name: Name for the new database
        location: Azure region for the database
        sku_name: Performance tier (Basic, Standard, Premium)
        max_size_bytes: Maximum size of the database in bytes
        zone_redundant: Whether to enable zone redundancy
        tags: Optional tags for the database
    
    Returns:
        Dictionary containing the created database's details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    sql_client = get_sql_client()

    # Create database parameters
    parameters = {
        'location': location,
        'sku': {
            'name': sku_name
        },
        'max_size_bytes': max_size_bytes,
        'zone_redundant': zone_redundant,
        'tags': tags or {}
    }

    # Create the database
    database = sql_client.databases.begin_create_or_update(
        resource_group,
        server_name,
        database_name,
        parameters
    ).result()

    return {
        'id': database.id,
        'name': database.name,
        'location': database.location,
        'status': database.status,
        'max_size_bytes': database.max_size_bytes,
        'sku': {
            'name': database.sku.name,
            'tier': database.sku.tier,
            'capacity': database.sku.capacity
        } if database.sku else None
    }

@mcp.tool(description="Creates a new Azure Container Registry.")
async def create_acr(
    resource_group: str,
    name: str,
    location: str = "westeurope",
    sku: str = "Basic",
    admin_enabled: bool = True,
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Create a new Azure Container Registry.
    
    Args:
        resource_group: Name of the resource group
        name: Name for the new registry (must be globally unique)
        location: Azure region for the registry
        sku: SKU name ('Basic', 'Standard', or 'Premium')
        admin_enabled: Whether to enable admin user
        tags: Optional tags for the registry
    
    Returns:
        Dictionary containing the created registry's details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    client = get_container_registry_client()
    
    registry_parameters = {
        'location': location,
        'sku': {'name': sku},
        'admin_user_enabled': admin_enabled,
        'tags': tags or {}
    }
    
    poller = client.registries.begin_create(
        resource_group,
        name,
        registry_parameters
    )
    registry = poller.result()
    
    return {
        'id': registry.id,
        'name': registry.name,
        'location': registry.location,
        'login_server': registry.login_server,
        'admin_enabled': registry.admin_user_enabled,
        'sku': registry.sku.name
    }

@mcp.tool(description="Gets the login credentials for an Azure Container Registry.")
async def get_acr_credentials(
    resource_group: str,
    name: str
) -> Dict[str, Any]:
    """Get login credentials for an Azure Container Registry.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the registry
    
    Returns:
        Dictionary containing the registry credentials
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    client = get_container_registry_client()
    credentials = client.registries.list_credentials(resource_group, name)
    
    return {
        'username': credentials.username,
        'passwords': [
            {'name': pwd.name, 'value': pwd.value}
            for pwd in credentials.passwords
        ] if credentials.passwords else []
    }

@mcp.tool(description="Lists repositories in an Azure Container Registry.")
async def list_acr_repositories(
    resource_group: str,
    name: str
) -> List[str]:
    """List repositories in an Azure Container Registry.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the registry
    
    Returns:
        List of repository names
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    client = get_container_registry_client()
    result = client.registries.list_repositories(resource_group, name)
    
    return result.repositories if result.repositories else []

@mcp.tool(description="Lists tags for a repository in an Azure Container Registry.")
async def list_acr_tags(
    resource_group: str,
    name: str,
    repository: str
) -> List[str]:
    """List tags for a repository in an Azure Container Registry.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the registry
        repository: Name of the repository
    
    Returns:
        List of tag names
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    client = get_container_registry_client()
    result = client.registries.list_tags(resource_group, name, repository)
    
    return [tag.name for tag in result.tags] if result.tags else []

@mcp.tool(description="Updates an existing Application Gateway's backend pool configuration.")
async def update_app_gateway_backend_pool(
    resource_group: str,
    app_gateway_name: str,
    backend_pool_name: str,
    backend_fqdns: List[str] = None,
    backend_ips: List[str] = None,
    backend_port: int = 80
) -> Dict[str, Any]:
    """Update an existing Application Gateway's backend pool configuration.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
        backend_pool_name: Name of the backend pool to update or create
        backend_fqdns: List of backend FQDNs (optional)
        backend_ips: List of backend IP addresses (optional)
        backend_port: Backend port number
    
    Returns:
        Dictionary containing the updated Application Gateway details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    if not backend_fqdns and not backend_ips:
        raise ValueError("Either backend_fqdns or backend_ips must be provided")

    network_client = get_network_client()

    # Get the existing Application Gateway
    app_gateway = network_client.application_gateways.get(
        resource_group,
        app_gateway_name
    )

    # Convert the app gateway to a dict for modification
    app_gateway_dict = app_gateway.as_dict()

    # Prepare backend addresses
    backend_addresses = []
    if backend_fqdns:
        backend_addresses.extend([{'fqdn': fqdn} for fqdn in backend_fqdns])
    if backend_ips:
        backend_addresses.extend([{'ip_address': ip} for ip in backend_ips])

    # Find or create backend pool
    backend_pool_found = False
    for pool in app_gateway_dict['backend_address_pools']:
        if pool['name'] == backend_pool_name:
            pool['backend_addresses'] = backend_addresses
            backend_pool_found = True
            break
    
    if not backend_pool_found:
        if 'backend_address_pools' not in app_gateway_dict:
            app_gateway_dict['backend_address_pools'] = []
        app_gateway_dict['backend_address_pools'].append({
            'name': backend_pool_name,
            'backend_addresses': backend_addresses
        })

    # Update backend HTTP settings if needed
    settings_name = f"{backend_pool_name}-http-settings"
    settings_found = False
    for setting in app_gateway_dict['backend_http_settings_collection']:
        if setting['name'] == settings_name:
            setting['port'] = backend_port
            settings_found = True
            break
    
    if not settings_found:
        if 'backend_http_settings_collection' not in app_gateway_dict:
            app_gateway_dict['backend_http_settings_collection'] = []
        app_gateway_dict['backend_http_settings_collection'].append({
            'name': settings_name,
            'port': backend_port,
            'protocol': 'Http',
            'cookie_based_affinity': 'Disabled',
            'request_timeout': 30,
            'probe': None
        })

    # Update the first routing rule to use our backend pool
    if app_gateway_dict['request_routing_rules']:
        rule = app_gateway_dict['request_routing_rules'][0]
        rule['backend_address_pool'] = {
            'id': f"{app_gateway_dict['id']}/backendAddressPools/{backend_pool_name}"
        }
        rule['backend_http_settings'] = {
            'id': f"{app_gateway_dict['id']}/backendHttpSettingsCollection/{settings_name}"
        }
    else:
        # Create a new rule if none exist
        app_gateway_dict['request_routing_rules'] = [{
            'name': 'rule1',
            'rule_type': 'Basic',
            'priority': 100,
            'http_listener': {
                'id': app_gateway_dict['http_listeners'][0]['id']
            },
            'backend_address_pool': {
                'id': f"{app_gateway_dict['id']}/backendAddressPools/{backend_pool_name}"
            },
            'backend_http_settings': {
                'id': f"{app_gateway_dict['id']}/backendHttpSettingsCollection/{settings_name}"
            }
        }]

    # Update the Application Gateway
    updated_gateway = network_client.application_gateways.begin_create_or_update(
        resource_group,
        app_gateway_name,
        app_gateway_dict
    ).result()

    return {
        'id': updated_gateway.id,
        'name': updated_gateway.name,
        'backend_pools': [
            {
                'name': pool.name,
                'addresses': [
                    {'fqdn': addr.fqdn} if addr.fqdn else {'ip_address': addr.ip_address}
                    for addr in pool.backend_addresses
                ] if pool.backend_addresses else []
            }
            for pool in updated_gateway.backend_address_pools
        ],
        'provisioning_state': updated_gateway.provisioning_state
    }

@mcp.tool(description="Gets detailed information about an Application Gateway including its public IP, listeners, rules, and backend configuration.")
async def get_app_gateway_info(
    resource_group: str,
    app_gateway_name: str
) -> Dict[str, Any]:
    """Get detailed information about an Application Gateway.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
    
    Returns:
        Dictionary containing detailed Application Gateway information
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get the Application Gateway
    app_gateway = network_client.application_gateways.get(
        resource_group,
        app_gateway_name
    )

    # Get the public IP
    public_ip = None
    if app_gateway.frontend_ip_configurations:
        for frontend_ip in app_gateway.frontend_ip_configurations:
            if frontend_ip.public_ip_address:
                public_ip_id = frontend_ip.public_ip_address.id
                public_ip_name = public_ip_id.split('/')[-1]
                public_ip = network_client.public_ip_addresses.get(
                    resource_group,
                    public_ip_name
                )
                break

    # Build the response
    return {
        'id': app_gateway.id,
        'name': app_gateway.name,
        'location': app_gateway.location,
        'public_ip': public_ip.ip_address if public_ip else None,
        'operational_state': app_gateway.operational_state,
        'sku': {
            'name': app_gateway.sku.name,
            'tier': app_gateway.sku.tier,
            'capacity': app_gateway.sku.capacity
        },
        'frontend_ports': [
            {
                'name': port.name,
                'port': port.port
            }
            for port in app_gateway.frontend_ports
        ],
        'backend_pools': [
            {
                'name': pool.name,
                'addresses': [
                    {
                        'fqdn': addr.fqdn,
                        'ip_address': addr.ip_address
                    }
                    for addr in pool.backend_addresses
                ] if pool.backend_addresses else []
            }
            for pool in app_gateway.backend_address_pools
        ],
        'http_settings': [
            {
                'name': setting.name,
                'port': setting.port,
                'protocol': setting.protocol,
                'cookie_based_affinity': setting.cookie_based_affinity,
                'request_timeout': setting.request_timeout
            }
            for setting in app_gateway.backend_http_settings_collection
        ],
        'routing_rules': [
            {
                'name': rule.name,
                'rule_type': rule.rule_type,
                'priority': rule.priority,
                'backend_pool': rule.backend_address_pool.id.split('/')[-1] if rule.backend_address_pool else None,
                'backend_http_settings': rule.backend_http_settings.id.split('/')[-1] if rule.backend_http_settings else None,
                'http_listener': rule.http_listener.id.split('/')[-1] if rule.http_listener else None
            }
            for rule in app_gateway.request_routing_rules
        ],
        'waf_configuration': {
            'enabled': app_gateway.web_application_firewall_configuration.enabled,
            'firewall_mode': app_gateway.web_application_firewall_configuration.firewall_mode,
            'rule_set_type': app_gateway.web_application_firewall_configuration.rule_set_type,
            'rule_set_version': app_gateway.web_application_firewall_configuration.rule_set_version
        } if app_gateway.web_application_firewall_configuration else None,
        'ssl_certificates': [
            {
                'name': cert.name,
                'public_cert_data': cert.public_cert_data
            }
            for cert in app_gateway.ssl_certificates
        ] if app_gateway.ssl_certificates else [],
        'provisioning_state': app_gateway.provisioning_state
    }

@mcp.tool(description="Updates WAF configuration on an Application Gateway.")
async def update_app_gateway_waf_config(
    resource_group: str,
    app_gateway_name: str,
    enabled: bool = True,
    firewall_mode: str = "Detection",
    rule_set_type: str = "OWASP",
    rule_set_version: str = "3.2"
) -> Dict[str, Any]:
    """Update WAF configuration on an Application Gateway.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
        enabled: Whether WAF is enabled
        firewall_mode: WAF mode (Detection or Prevention)
        rule_set_type: Rule set type (OWASP)
        rule_set_version: Rule set version
    
    Returns:
        Dictionary containing the updated Application Gateway details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get the Application Gateway
    app_gateway = network_client.application_gateways.get(
        resource_group,
        app_gateway_name
    )

    # Convert to dict for modification
    app_gateway_dict = app_gateway.as_dict()

    # Update WAF configuration
    app_gateway_dict['web_application_firewall_configuration'] = {
        'enabled': enabled,
        'firewall_mode': firewall_mode,
        'rule_set_type': rule_set_type,
        'rule_set_version': rule_set_version,
        'file_upload_limit_mb': 100,
        'request_body_check': True,
        'max_request_body_size_kb': 128
    }

    # Update the Application Gateway
    updated_gateway = network_client.application_gateways.begin_create_or_update(
        resource_group,
        app_gateway_name,
        app_gateway_dict
    ).result()

    return {
        'id': updated_gateway.id,
        'name': updated_gateway.name,
        'waf_configuration': {
            'enabled': updated_gateway.web_application_firewall_configuration.enabled,
            'firewall_mode': updated_gateway.web_application_firewall_configuration.firewall_mode,
            'rule_set_type': updated_gateway.web_application_firewall_configuration.rule_set_type,
            'rule_set_version': updated_gateway.web_application_firewall_configuration.rule_set_version
        } if updated_gateway.web_application_firewall_configuration else None,
        'provisioning_state': updated_gateway.provisioning_state
    }

@mcp.tool(description="Gets detailed information about a Network Security Group including all its rules.")
async def get_nsg_info(
    resource_group: str,
    nsg_name: str
) -> Dict[str, Any]:
    """Get detailed information about a Network Security Group.
    
    Args:
        resource_group: Name of the resource group
        nsg_name: Name of the NSG
    
    Returns:
        Dictionary containing detailed NSG information including all rules
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get the NSG
    nsg = network_client.network_security_groups.get(
        resource_group,
        nsg_name
    )

    # Build the response
    return {
        'id': nsg.id,
        'name': nsg.name,
        'location': nsg.location,
        'security_rules': [
            {
                'name': rule.name,
                'protocol': rule.protocol,
                'source_address_prefix': rule.source_address_prefix,
                'source_port_range': rule.source_port_range,
                'destination_address_prefix': rule.destination_address_prefix,
                'destination_port_range': rule.destination_port_range,
                'access': rule.access,
                'priority': rule.priority,
                'direction': rule.direction,
                'provisioning_state': rule.provisioning_state
            }
            for rule in nsg.security_rules or []
        ],
        'default_security_rules': [
            {
                'name': rule.name,
                'protocol': rule.protocol,
                'source_address_prefix': rule.source_address_prefix,
                'source_port_range': rule.source_port_range,
                'destination_address_prefix': rule.destination_address_prefix,
                'destination_port_range': rule.destination_port_range,
                'access': rule.access,
                'priority': rule.priority,
                'direction': rule.direction,
                'provisioning_state': rule.provisioning_state
            }
            for rule in nsg.default_security_rules or []
        ],
        'network_interfaces': [
            {
                'id': nic.id,
                'name': nic.id.split('/')[-1]
            }
            for nic in nsg.network_interfaces or []
        ] if nsg.network_interfaces else [],
        'provisioning_state': nsg.provisioning_state
    }

@mcp.tool(description="Creates VNet peering between two virtual networks.")
async def create_vnet_peering(
    resource_group: str,
    vnet1_name: str,
    vnet2_name: str,
    allow_forwarded_traffic: bool = True,
    allow_gateway_transit: bool = False,
    use_remote_gateways: bool = False
) -> Dict[str, Any]:
    """Create VNet peering between two virtual networks.
    
    Args:
        resource_group: Name of the resource group
        vnet1_name: Name of the first VNet
        vnet2_name: Name of the second VNet
        allow_forwarded_traffic: Whether to allow forwarded traffic
        allow_gateway_transit: Whether to allow gateway transit
        use_remote_gateways: Whether to use remote gateways
    
    Returns:
        Dictionary containing the peering details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get both VNets
    vnet1 = network_client.virtual_networks.get(resource_group, vnet1_name)
    vnet2 = network_client.virtual_networks.get(resource_group, vnet2_name)

    # Create peering from vnet1 to vnet2
    peering1_name = f"{vnet1_name}-to-{vnet2_name}"
    peering1_params = {
        'remote_virtual_network': {
            'id': vnet2.id
        },
        'allow_virtual_network_access': True,
        'allow_forwarded_traffic': allow_forwarded_traffic,
        'allow_gateway_transit': allow_gateway_transit,
        'use_remote_gateways': use_remote_gateways
    }
    
    peering1 = network_client.virtual_network_peerings.begin_create_or_update(
        resource_group,
        vnet1_name,
        peering1_name,
        peering1_params
    ).result()

    # Create peering from vnet2 to vnet1
    peering2_name = f"{vnet2_name}-to-{vnet1_name}"
    peering2_params = {
        'remote_virtual_network': {
            'id': vnet1.id
        },
        'allow_virtual_network_access': True,
        'allow_forwarded_traffic': allow_forwarded_traffic,
        'allow_gateway_transit': allow_gateway_transit,
        'use_remote_gateways': use_remote_gateways
    }
    
    peering2 = network_client.virtual_network_peerings.begin_create_or_update(
        resource_group,
        vnet2_name,
        peering2_name,
        peering2_params
    ).result()

    return {
        'peering1': {
            'name': peering1.name,
            'state': peering1.peering_state,
            'remote_vnet': vnet2.name
        },
        'peering2': {
            'name': peering2.name,
            'state': peering2.peering_state,
            'remote_vnet': vnet1.name
        }
    }

@mcp.tool(description="Deletes a specific Azure resource by its type and name.")
async def delete_resource(
    resource_group: str,
    resource_type: str,
    resource_name: str
) -> Dict[str, Any]:
    """Delete a specific Azure resource.
    
    Args:
        resource_group: Name of the resource group
        resource_type: Type of the resource (e.g., 'Microsoft.Web/sites')
        resource_name: Name of the resource
    
    Returns:
        Dictionary containing the deletion status
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    resource_client = get_resource_client()
    
    try:
        # Get the latest API version for the resource type
        provider = resource_type.split('/')[0]
        resource_type_path = '/'.join(resource_type.split('/')[1:])
        
        provider_obj = resource_client.providers.get(provider)
        resource_type_info = next(
            (rt for rt in provider_obj.resource_types 
             if rt.resource_type.lower() == resource_type_path.lower()),
            None
        )
        
        if not resource_type_info:
            raise ValueError(f"Resource type {resource_type} not found")
            
        api_version = resource_type_info.api_versions[0]  # Use latest API version
        
        # Delete the resource
        poller = resource_client.resources.begin_delete_by_id(
            resource_id=f"/subscriptions/{config.subscription_id}/resourceGroups/{resource_group}/providers/{resource_type}/{resource_name}",
            api_version=api_version
        )
        
        result = poller.result()  # Wait for completion
        
        return {
            'status': 'success',
            'message': f"Resource {resource_name} of type {resource_type} deleted successfully"
        }
        
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

@mcp.tool(description="Manages health probes for an Application Gateway and retrieves backend health status.")
async def manage_app_gateway_health(
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
    """Manages health probes for an Application Gateway and retrieves backend health.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
        probe_name: Name for the health probe
        host: Host header to be used for the probe
        path: Path to probe on the backend
        interval: Probe interval in seconds
        timeout: Probe timeout in seconds
        unhealthy_threshold: Number of failed probes before marking as unhealthy
        protocol: Protocol to use for the probe (Http/Https)
        port: Port to probe (if different from backend http settings)
        match_status_codes: List of status codes or ranges considered healthy
    
    Returns:
        Dictionary containing probe configuration and backend health status
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()

    # Get the Application Gateway
    app_gateway = network_client.application_gateways.get(
        resource_group,
        app_gateway_name
    )

    # Convert to dict for modification
    app_gateway_dict = app_gateway.as_dict()

    # Create or update probe configuration
    probe_config = {
        'name': probe_name,
        'protocol': protocol,
        'host': host,
        'path': path,
        'interval': interval,
        'timeout': timeout,
        'unhealthy_threshold': unhealthy_threshold,
        'match': {
            'status_codes': match_status_codes
        }
    }
    if port:
        probe_config['port'] = port

    # Update or add probe
    probe_found = False
    if 'probes' in app_gateway_dict:
        for i, probe in enumerate(app_gateway_dict['probes']):
            if probe['name'] == probe_name:
                app_gateway_dict['probes'][i] = probe_config
                probe_found = True
                break
    else:
        app_gateway_dict['probes'] = []
    
    if not probe_found:
        app_gateway_dict['probes'].append(probe_config)

    # Update backend http settings to use the probe
    for setting in app_gateway_dict['backend_http_settings_collection']:
        setting['probe'] = {
            'id': f"{app_gateway_dict['id']}/probes/{probe_name}"
        }

    # Update the Application Gateway
    updated_gateway = network_client.application_gateways.begin_create_or_update(
        resource_group,
        app_gateway_name,
        app_gateway_dict
    ).result()

    # Get backend health after update
    backend_health = network_client.application_gateways.begin_backend_health(
        resource_group,
        app_gateway_name
    ).result()

    # Process backend health information
    health_info = []
    for pool in backend_health.backend_address_pools:
        for backend in pool.backends:
            health_info.append({
                'address': backend.address,
                'health_probe_log': backend.health_probe_log,
                'health': backend.health,
                'backend_pool': pool.backend_address_pool.name
            })

    return {
        'probe_configuration': {
            'name': probe_name,
            'protocol': protocol,
            'host': host,
            'path': path,
            'interval': interval,
            'timeout': timeout,
            'unhealthy_threshold': unhealthy_threshold,
            'match_status_codes': match_status_codes,
            'port': port
        },
        'backend_health': health_info,
        'provisioning_state': updated_gateway.provisioning_state
    }

@mcp.tool(description="Creates an App Service Plan in Azure.")
async def create_app_service_plan(
    resource_group: str,
    name: str,
    location: str = "westeurope",
    sku: str = "B1",
    os_type: str = "Linux",
    per_site_scaling: bool = False,
    maximum_elastic_worker_count: int = 1,
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Create an App Service Plan in Azure.
    
    Args:
        resource_group: Name of the resource group
        name: Name for the App Service Plan
        location: Azure region for the plan
        sku: SKU name (e.g., B1, S1, P1v2)
        os_type: Operating system type (Linux or Windows)
        per_site_scaling: Whether to enable per-site scaling
        maximum_elastic_worker_count: Maximum number of workers for elastic scaling
        tags: Optional tags for the plan
    
    Returns:
        Dictionary containing the created App Service Plan details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    web_client = get_web_client()

    # Create App Service Plan parameters
    plan_parameters = {
        'location': location,
        'sku': {
            'name': sku,
            'tier': sku[:1],  # First letter indicates tier (B, S, P)
            'size': sku[1:]  # Rest is the size
        },
        'per_site_scaling': per_site_scaling,
        'maximum_elastic_worker_count': maximum_elastic_worker_count,
        'reserved': os_type.lower() == 'linux',
        'tags': tags or {}
    }

    # Create the App Service Plan
    plan = web_client.app_service_plans.begin_create_or_update(
        resource_group,
        name,
        plan_parameters
    ).result()

    return {
        'id': plan.id,
        'name': plan.name,
        'location': plan.location,
        'sku': {
            'name': plan.sku.name,
            'tier': plan.sku.tier,
            'size': plan.sku.size
        },
        'os_type': 'Linux' if plan.reserved else 'Windows',
        'per_site_scaling': plan.per_site_scaling,
        'maximum_elastic_worker_count': plan.maximum_elastic_worker_count,
        'provisioning_state': plan.provisioning_state
    }

@mcp.tool(description="Creates a new Web App in Azure.")
async def create_web_app(
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
    """Create a new Web App in Azure.
    
    Args:
        resource_group: Name of the resource group
        name: Name for the Web App (must be globally unique)
        app_service_plan: Name of the App Service Plan
        location: Azure region for the Web App
        runtime_stack: Runtime stack (e.g., 'python:3.9', 'node:14-lts', 'dotnet:6.0')
        os_type: Operating system type (Linux or Windows)
        https_only: Whether to enable HTTPS only
        client_affinity_enabled: Whether to enable client affinity
        tags: Optional tags for the Web App
    
    Returns:
        Dictionary containing the created Web App details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    web_client = get_web_client()

    # Get the App Service Plan
    plan = web_client.app_service_plans.get(resource_group, app_service_plan)

    # Create Web App parameters
    site_config = {
        'linux_fx_version': runtime_stack if os_type.lower() == 'linux' else None,
        'windows_fx_version': runtime_stack if os_type.lower() == 'windows' else None,
        'http20_enabled': True,
        'min_tls_version': '1.2',
        'ftps_state': 'FtpsOnly',
        'reserved': os_type.lower() == 'linux'
    }

    site_parameters = {
        'location': location,
        'server_farm_id': plan.id,
        'site_config': site_config,
        'https_only': https_only,
        'client_affinity_enabled': client_affinity_enabled,
        'tags': tags or {}
    }

    # Create the Web App
    web_app = web_client.web_apps.begin_create_or_update(
        resource_group,
        name,
        site_parameters
    ).result()

    return {
        'id': web_app.id,
        'name': web_app.name,
        'location': web_app.location,
        'default_host_name': web_app.default_host_name,
        'enabled_host_names': web_app.enabled_host_names,
        'state': web_app.state,
        'server_farm_id': web_app.server_farm_id,
        'site_config': {
            'linux_fx_version': web_app.site_config.linux_fx_version,
            'windows_fx_version': web_app.site_config.windows_fx_version,
            'http20_enabled': web_app.site_config.http20_enabled,
            'min_tls_version': web_app.site_config.min_tls_version,
            'ftps_state': web_app.site_config.ftps_state
        },
        'provisioning_state': web_app.provisioning_state
    }

@mcp.tool(description="Deploys a Docker container to an Azure Web App.")
async def deploy_docker_to_web_app(
    resource_group: str,
    name: str,
    image: str,
    registry_url: Optional[str] = None,
    registry_username: Optional[str] = None,
    registry_password: Optional[str] = None,
    startup_command: Optional[str] = None,
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Deploy a Docker container to an Azure Web App.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the Web App
        image: Docker image name and tag (e.g., 'nginx:latest')
        registry_url: Private registry URL (if using private registry)
        registry_username: Registry username (if using private registry)
        registry_password: Registry password (if using private registry)
        startup_command: Optional startup command for the container
        tags: Optional tags for the Web App
    
    Returns:
        Dictionary containing the updated Web App details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    web_client = get_web_client()

    try:
        # Get the existing Web App
        web_app = web_client.web_apps.get(resource_group, name)
        
        # Prepare site config
        site_config = web_app.site_config or SiteConfig()
        site_config.linux_fx_version = f"DOCKER|{image}"
        if startup_command:
            site_config.app_command_line = startup_command

        # Prepare container settings
        container_settings = {}
        if registry_url and registry_username and registry_password:
            container_settings = {
                'DOCKER_REGISTRY_SERVER_URL': f"https://{registry_url}",
                'DOCKER_REGISTRY_SERVER_USERNAME': registry_username,
                'DOCKER_REGISTRY_SERVER_PASSWORD': registry_password
            }

        # Update Web App parameters
        site_parameters = {
            'location': web_app.location,
            'site_config': site_config,
            'tags': tags or web_app.tags
        }

        if web_app.server_farm_id:
            site_parameters['server_farm_id'] = web_app.server_farm_id
        
        if hasattr(web_app, 'https_only'):
            site_parameters['https_only'] = web_app.https_only
            
        if hasattr(web_app, 'client_affinity_enabled'):
            site_parameters['client_affinity_enabled'] = web_app.client_affinity_enabled

        # Update the Web App
        poller = web_client.web_apps.begin_create_or_update(
            resource_group,
            name,
            site_parameters
        )
        
        # Wait for the operation to complete
        updated_app = poller.result()

        # Update container settings if needed
        if container_settings:
            current_settings = web_client.web_apps.list_application_settings(resource_group, name)
            updated_settings = current_settings.properties.copy()
            updated_settings.update(container_settings)
            
            web_client.web_apps.update_application_settings(
                resource_group,
                name,
                {
                    'name': name,
                    'properties': updated_settings
                }
            )

        # Get the final state of the web app
        final_app = web_client.web_apps.get(resource_group, name)

        return {
            'id': final_app.id,
            'name': final_app.name,
            'default_host_name': final_app.default_host_name,
            'state': final_app.state,
            'site_config': {
                'linux_fx_version': final_app.site_config.linux_fx_version,
                'app_command_line': final_app.site_config.app_command_line if final_app.site_config.app_command_line else None
            },
            'enabled': final_app.enabled,
            'host_names': final_app.host_names,
            'host_name_ssl_states': [
                {
                    'name': ssl_state.name,
                    'ssl_state': ssl_state.ssl_state,
                    'virtual_ip': ssl_state.virtual_ip
                } for ssl_state in (final_app.host_name_ssl_states or [])
            ] if final_app.host_name_ssl_states else []
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'status': 'failed'
        }

@mcp.tool(description="Gets detailed information about a Web App including its configuration and settings.")
async def get_web_app_info(
    resource_group: str,
    name: str
) -> Dict[str, Any]:
    """Get detailed information about a Web App.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the Web App
    
    Returns:
        Dictionary containing detailed Web App information
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    web_client = get_web_client()

    # Get the Web App
    web_app = web_client.web_apps.get(resource_group, name)

    # Get application settings
    app_settings = web_client.web_apps.list_application_settings(resource_group, name)

    # Get publishing profile
    publishing_profile = web_client.web_apps.list_publishing_profiles(resource_group, name)

    return {
        'id': web_app.id,
        'name': web_app.name,
        'location': web_app.location,
        'default_host_name': web_app.default_host_name,
        'enabled_host_names': web_app.enabled_host_names,
        'state': web_app.state,
        'server_farm_id': web_app.server_farm_id,
        'site_config': {
            'linux_fx_version': web_app.site_config.linux_fx_version,
            'windows_fx_version': web_app.site_config.windows_fx_version,
            'http20_enabled': web_app.site_config.http20_enabled,
            'min_tls_version': web_app.site_config.min_tls_version,
            'ftps_state': web_app.site_config.ftps_state
        },
        'application_settings': app_settings.properties,
        'publishing_profile': publishing_profile,
        'provisioning_state': web_app.provisioning_state
    }

@mcp.tool(description="Updates application settings for a Web App.")
async def update_web_app_settings(
    resource_group: str,
    name: str,
    settings: Dict[str, str],
    tags: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """Update application settings for a Web App.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the Web App
        settings: Dictionary of settings to update
        tags: Optional tags for the Web App
    
    Returns:
        Dictionary containing the updated Web App settings
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    web_client = get_web_client()

    # Get current settings
    current_settings = web_client.web_apps.list_application_settings(resource_group, name)

    # Update settings
    updated_settings = current_settings.properties.copy()
    updated_settings.update(settings)

    # Update the settings
    result = web_client.web_apps.update_application_settings(
        resource_group,
        name,
        {'name': name, 'properties': updated_settings}
    )

    # Update tags if provided
    if tags:
        web_client.web_apps.update(
            resource_group,
            name,
            {'tags': tags}
        )

    return {
        'name': result.name,
        'settings': result.properties
    }

@mcp.tool(description="Lists logs from a Web App.")
async def list_web_app_logs(
    resource_group: str,
    name: str,
    log_type: str = "application",
    start_time: Optional[str] = None,
    end_time: Optional[str] = None
) -> Dict[str, Any]:
    """List logs from a Web App.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the Web App
        log_type: Type of logs to retrieve (application, http, failed_request_traces)
        start_time: Start time for log retrieval (ISO format)
        end_time: End time for log retrieval (ISO format)
    
    Returns:
        Dictionary containing the log entries
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    web_client = get_web_client()

    # Get logs based on type
    if log_type == "application":
        logs = web_client.web_apps.get_application_logs(resource_group, name)
    elif log_type == "http":
        logs = web_client.web_apps.get_http_logs(resource_group, name)
    elif log_type == "failed_request_traces":
        logs = web_client.web_apps.get_failed_request_traces(resource_group, name)
    else:
        raise ValueError(f"Unsupported log type: {log_type}")

    return {
        'log_type': log_type,
        'logs': logs
    }

@mcp.tool(description="Restarts a Web App.")
async def restart_web_app(
    resource_group: str,
    name: str,
    soft_restart: bool = False
) -> Dict[str, Any]:
    """Restart a Web App.
    
    Args:
        resource_group: Name of the resource group
        name: Name of the Web App
        soft_restart: Whether to perform a soft restart (preserves memory)
    
    Returns:
        Dictionary containing the restart operation status
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    web_client = get_web_client()

    try:
        if soft_restart:
            web_client.web_apps.restart(resource_group, name)
        else:
            web_client.web_apps.stop(resource_group, name)
            web_client.web_apps.start(resource_group, name)

        return {
            'status': 'success',
            'message': f"Web App {name} has been {'soft restarted' if soft_restart else 'restarted'}"
        }
    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }

@mcp.tool(description="Updates the HTTP settings for an Application Gateway backend pool.")
async def update_app_gateway_http_settings(
    resource_group: str,
    app_gateway_name: str,
    settings_name: str,
    port: int = 443,
    protocol: str = "Https",
    cookie_based_affinity: str = "Disabled",
    timeout: int = 30,
    host_name: str = None,
    probe_name: str = None
) -> Dict[str, Any]:
    """Updates HTTP settings for an Application Gateway backend pool.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
        settings_name: Name of the HTTP settings to update
        port: Backend port (default: 443)
        protocol: Backend protocol (Http/Https)
        cookie_based_affinity: Enable/Disable cookie based affinity
        timeout: Request timeout in seconds
        host_name: Override host header with this host name
        probe_name: Name of the health probe to use
    
    Returns:
        Dictionary containing the updated HTTP settings
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()
    
    try:
        # Get current Application Gateway
        app_gateway = network_client.application_gateways.get(
            resource_group_name=resource_group,
            application_gateway_name=app_gateway_name
        )
        
        # Find or create HTTP settings
        http_settings = None
        for setting in app_gateway.backend_http_settings_collection:
            if setting.name == settings_name:
                http_settings = setting
                break
        
        if not http_settings:
            raise ValueError(f"HTTP settings '{settings_name}' not found")
        
        # Update settings
        http_settings.port = port
        http_settings.protocol = protocol
        http_settings.cookie_based_affinity = cookie_based_affinity
        http_settings.request_timeout = timeout
        
        if host_name:
            # Create host name configuration
            http_settings.host_name_from_backend_pool = False
            http_settings.pick_host_name_from_backend_address = False
            http_settings.host_name = host_name
            
        if probe_name:
            probe = next((p for p in app_gateway.probes if p.name == probe_name), None)
            if probe:
                http_settings.probe = probe
        
        # Update Application Gateway
        poller = network_client.application_gateways.begin_create_or_update(
            resource_group_name=resource_group,
            application_gateway_name=app_gateway_name,
            parameters=app_gateway
        )
        
        result = poller.result()
        
        # Find updated settings in result
        updated_settings = next(
            (s for s in result.backend_http_settings_collection if s.name == settings_name),
            None
        )
        
        return {
            'name': updated_settings.name,
            'port': updated_settings.port,
            'protocol': updated_settings.protocol,
            'cookie_based_affinity': updated_settings.cookie_based_affinity,
            'request_timeout': updated_settings.request_timeout,
            'probe': updated_settings.probe.name if updated_settings.probe else None,
            'host_name': updated_settings.host_name if hasattr(updated_settings, 'host_name') else None,
            'pick_host_name_from_backend_address': updated_settings.pick_host_name_from_backend_address if hasattr(updated_settings, 'pick_host_name_from_backend_address') else None
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'status': 'failed'
        }

@mcp.tool(description="Manages SSL certificates for an Application Gateway (both frontend and backend).")
async def manage_app_gateway_ssl(
    resource_group: str,
    app_gateway_name: str,
    certificate_name: str,
    certificate_type: str = "frontend",
    certificate_path: Optional[str] = None,
    certificate_password: Optional[str] = None,
    key_vault_secret_id: Optional[str] = None
) -> Dict[str, Any]:
    """Manages SSL certificates for an Application Gateway.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
        certificate_name: Name for the certificate
        certificate_type: Type of certificate (frontend/backend/root)
        certificate_path: Path to certificate file (PFX for frontend, CER for backend)
        certificate_password: Password for PFX certificate
        key_vault_secret_id: Key Vault secret ID containing the certificate
    
    Returns:
        Dictionary containing the certificate details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()
    
    try:
        # Get current Application Gateway
        app_gateway = network_client.application_gateways.get(
            resource_group_name=resource_group,
            application_gateway_name=app_gateway_name
        )
        
        if certificate_type == "frontend":
            # Handle frontend SSL certificate
            if key_vault_secret_id:
                ssl_certificate = {
                    'name': certificate_name,
                    'key_vault_secret_id': key_vault_secret_id
                }
            elif certificate_path and certificate_password:
                with open(certificate_path, 'rb') as cert_file:
                    cert_data = cert_file.read()
                    ssl_certificate = {
                        'name': certificate_name,
                        'data': base64.b64encode(cert_data).decode('utf-8'),
                        'password': certificate_password
                    }
            else:
                raise ValueError("Either key_vault_secret_id or both certificate_path and password must be provided")
            
            # Update or add SSL certificate
            cert_found = False
            for i, cert in enumerate(app_gateway.ssl_certificates):
                if cert.name == certificate_name:
                    app_gateway.ssl_certificates[i] = ssl_certificate
                    cert_found = True
                    break
            
            if not cert_found:
                app_gateway.ssl_certificates.append(ssl_certificate)
                
        elif certificate_type in ["backend", "root"]:
            # Handle backend/root certificate
            if not certificate_path:
                raise ValueError("certificate_path is required for backend/root certificates")
                
            with open(certificate_path, 'rb') as cert_file:
                cert_data = cert_file.read()
                auth_cert = {
                    'name': certificate_name,
                    'data': base64.b64encode(cert_data).decode('utf-8')
                }
            
            # Update or add authentication certificate
            cert_found = False
            for i, cert in enumerate(app_gateway.authentication_certificates):
                if cert.name == certificate_name:
                    app_gateway.authentication_certificates[i] = auth_cert
                    cert_found = True
                    break
            
            if not cert_found:
                app_gateway.authentication_certificates.append(auth_cert)
        
        # Update Application Gateway
        poller = network_client.application_gateways.begin_create_or_update(
            resource_group_name=resource_group,
            application_gateway_name=app_gateway_name,
            parameters=app_gateway
        )
        
        result = poller.result()
        
        return {
            'name': certificate_name,
            'type': certificate_type,
            'status': 'success'
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'status': 'failed'
        }

@mcp.tool(description="Manages listeners and routing rules for an Application Gateway.")
async def manage_app_gateway_routing(
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
    """Manages listeners and routing rules for an Application Gateway.
    
    Args:
        resource_group: Name of the resource group
        app_gateway_name: Name of the Application Gateway
        rule_name: Name for the routing rule
        listener_protocol: Protocol for the listener (Http/Https)
        listener_port: Port for the listener
        priority: Priority of the routing rule
        backend_pool_name: Name of the backend pool
        backend_http_settings_name: Name of the backend HTTP settings
        path_pattern: URL path pattern for routing
    
    Returns:
        Dictionary containing the routing rule details
    """
    if not config.subscription_id:
        raise ValueError("Azure configuration is missing. Please set AZURE_SUBSCRIPTION_ID environment variable.")

    network_client = get_network_client()
    
    try:
        # Get current Application Gateway
        app_gateway = network_client.application_gateways.get(
            resource_group_name=resource_group,
            application_gateway_name=app_gateway_name
        )
        
        # Find or create frontend port
        port_name = f"port_{listener_port}"
        frontend_port = next(
            (p for p in app_gateway.frontend_ports if p.port == listener_port),
            None
        )
        
        if not frontend_port:
            frontend_port = {
                'name': port_name,
                'port': listener_port
            }
            app_gateway.frontend_ports.append(frontend_port)
        
        # Create or update listener
        listener_name = f"{rule_name}-listener"
        http_listener = {
            'name': listener_name,
            'frontend_ip_configuration': app_gateway.frontend_ip_configurations[0],
            'frontend_port': frontend_port,
            'protocol': listener_protocol,
            'require_server_name_indication': False
        }
        
        # Find or create listener
        listener_found = False
        for i, listener in enumerate(app_gateway.http_listeners):
            if listener.name == listener_name:
                app_gateway.http_listeners[i] = http_listener
                listener_found = True
                break
        
        if not listener_found:
            app_gateway.http_listeners.append(http_listener)
        
        # Find backend pool and HTTP settings
        backend_pool = next(
            (p for p in app_gateway.backend_address_pools if p.name == backend_pool_name),
            None
        )
        if not backend_pool:
            raise ValueError(f"Backend pool '{backend_pool_name}' not found")
            
        http_settings = next(
            (s for s in app_gateway.backend_http_settings_collection if s.name == backend_http_settings_name),
            None
        )
        if not http_settings:
            raise ValueError(f"HTTP settings '{backend_http_settings_name}' not found")
        
        # Create or update routing rule
        routing_rule = {
            'name': rule_name,
            'rule_type': 'Basic',
            'priority': priority,
            'http_listener': http_listener,
            'backend_address_pool': backend_pool,
            'backend_http_settings': http_settings,
            'url_path_map': None
        }
        
        # Find or create rule
        rule_found = False
        for i, rule in enumerate(app_gateway.request_routing_rules):
            if rule.name == rule_name:
                app_gateway.request_routing_rules[i] = routing_rule
                rule_found = True
                break
        
        if not rule_found:
            app_gateway.request_routing_rules.append(routing_rule)
        
        # Update Application Gateway
        poller = network_client.application_gateways.begin_create_or_update(
            resource_group_name=resource_group,
            application_gateway_name=app_gateway_name,
            parameters=app_gateway
        )
        
        result = poller.result()
        
        # Find updated rule in result
        updated_rule = next(
            (r for r in result.request_routing_rules if r.name == rule_name),
            None
        )
        
        return {
            'name': updated_rule.name,
            'priority': updated_rule.priority,
            'listener': {
                'name': updated_rule.http_listener.name,
                'protocol': updated_rule.http_listener.protocol,
                'port': updated_rule.http_listener.frontend_port.port
            },
            'backend_pool': updated_rule.backend_address_pool.name,
            'backend_http_settings': updated_rule.backend_http_settings.name
        }
        
    except Exception as e:
        return {
            'error': str(e),
            'status': 'failed'
        }

if __name__ == "__main__":
    print(f"Starting Azure Resource MCP Server...")
    mcp.run()
