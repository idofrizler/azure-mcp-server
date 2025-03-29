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
        location: Azure region for the NSG
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
    username: str = "azureuser",
    password: str = "",  # Empty string as default instead of None
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

if __name__ == "__main__":
    print(f"Starting Azure Resource MCP Server...")
    mcp.run()
