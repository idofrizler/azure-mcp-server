from typing import Any, Dict, Optional
from ..managers.dns_manager import AzureDNSManager

class DNSTools:
    """Tools for managing DNS and custom domains in Azure."""
    
    def __init__(self, dns_manager: AzureDNSManager):
        self.dns_manager = dns_manager

    async def create_dns_zone(
        self,
        resource_group: str,
        domain_name: str,
        location: str = "global",
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new DNS zone in Azure.
        
        This tool will:
        1. Create a DNS zone for the domain
        2. Return the name servers to configure at your domain registrar
        """
        return await self.dns_manager.create_dns_zone(
            resource_group=resource_group,
            zone_name=domain_name,
            location=location,
            tags=tags
        )

    async def setup_custom_domain(
        self,
        resource_group: str,
        domain_name: str,
        web_app_name: str
    ) -> Dict[str, Any]:
        """Set up a custom domain for an Azure Web App.
        
        This tool will:
        1. Create a DNS zone for the domain
        2. Add necessary DNS records
        3. Return the name servers to configure at your domain registrar
        """
        # Create DNS zone
        zone_result = await self.dns_manager.create_dns_zone(
            resource_group=resource_group,
            zone_name=domain_name
        )
        
        if "error" in zone_result:
            return zone_result
            
        # Add CNAME record for www subdomain
        cname_result = await self.dns_manager.add_cname_record(
            resource_group=resource_group,
            zone_name=domain_name,
            record_name="www",
            target=f"{web_app_name}.azurewebsites.net"
        )
        
        if "error" in cname_result:
            return cname_result
            
        # Add A record for root domain
        # Note: This requires the web app's IP address
        # You'll need to get this from the web app's properties
        a_record_result = await self.dns_manager.add_a_record(
            resource_group=resource_group,
            zone_name=domain_name,
            record_name="@",
            ip_address="<web_app_ip_address>"  # This needs to be replaced with actual IP
        )
        
        if "error" in a_record_result:
            return a_record_result
            
        return {
            "result": "Custom domain setup completed",
            "domain_name": domain_name,
            "name_servers": zone_result["name_servers"],
            "steps": [
                "1. DNS zone created",
                "2. CNAME record for www subdomain added",
                "3. A record for root domain added"
            ],
            "next_steps": [
                f"Configure your domain registrar to use these name servers: {', '.join(zone_result['name_servers'])}",
                "Wait for DNS propagation (can take up to 48 hours)",
                "Verify domain ownership in Azure Portal"
            ]
        }

    async def verify_domain_ownership(
        self,
        resource_group: str,
        domain_name: str,
        verification_token: str
    ) -> Dict[str, Any]:
        """Add a TXT record to verify domain ownership."""
        return await self.dns_manager.verify_domain_ownership(
            resource_group=resource_group,
            zone_name=domain_name,
            verification_token=verification_token
        )

    async def add_subdomain(
        self,
        resource_group: str,
        domain_name: str,
        subdomain: str,
        target: str,
        record_type: str = "CNAME"
    ) -> Dict[str, Any]:
        """Add a subdomain record to an existing DNS zone."""
        if record_type == "CNAME":
            return await self.dns_manager.add_cname_record(
                resource_group=resource_group,
                zone_name=domain_name,
                record_name=subdomain,
                target=target
            )
        elif record_type == "A":
            return await self.dns_manager.add_a_record(
                resource_group=resource_group,
                zone_name=domain_name,
                record_name=subdomain,
                ip_address=target
            )
        else:
            return {
                "result": "Failed to add subdomain",
                "error": f"Unsupported record type: {record_type}"
            } 