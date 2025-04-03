from typing import Any, Dict, Optional, List
import asyncio

from ..clients.client_factory import AzureClientFactory

class AzureDNSManager:
    """Class for managing Azure DNS zones and records."""
    
    def __init__(self, client_factory: AzureClientFactory):
        self.client_factory = client_factory

    async def create_dns_zone(
        self,
        resource_group: str,
        zone_name: str,
        location: str = "global",
        tags: Optional[Dict[str, str]] = None
    ) -> Dict[str, Any]:
        """Create a new DNS zone for a custom domain."""
        dns_client = self.client_factory.get_dns_client()
        loop = asyncio.get_event_loop()
        
        def create_zone():
            zone_operation = dns_client.zones.create_or_update(
                resource_group_name=resource_group,
                zone_name=zone_name,
                parameters={
                    "location": location,
                    "tags": tags or {}
                }
            )
            return zone_operation
            
        try:
            zone_result = await loop.run_in_executor(None, create_zone)
            return {
                "result": "DNS zone created successfully",
                "zone_name": zone_name,
                "name_servers": zone_result.name_servers,
                "details": zone_result.as_dict()
            }
        except Exception as e:
            return {
                "result": "Failed to create DNS zone",
                "error": str(e)
            }

    async def add_cname_record(
        self,
        resource_group: str,
        zone_name: str,
        record_name: str,
        target: str,
        ttl: int = 3600
    ) -> Dict[str, Any]:
        """Add a CNAME record to point a subdomain to an Azure Web App."""
        dns_client = self.client_factory.get_dns_client()
        loop = asyncio.get_event_loop()
        
        def create_record():
            record_operation = dns_client.record_sets.create_or_update(
                resource_group_name=resource_group,
                zone_name=zone_name,
                relative_record_set_name=record_name,
                record_type="CNAME",
                parameters={
                    "ttl": ttl,
                    "cname_record": {
                        "cname": target
                    }
                }
            )
            return record_operation
            
        try:
            record_result = await loop.run_in_executor(None, create_record)
            return {
                "result": "CNAME record created successfully",
                "record_name": record_name,
                "target": target,
                "details": record_result.as_dict()
            }
        except Exception as e:
            return {
                "result": "Failed to create CNAME record",
                "error": str(e)
            }

    async def add_a_record(
        self,
        resource_group: str,
        zone_name: str,
        record_name: str,
        ip_address: str,
        ttl: int = 3600
    ) -> Dict[str, Any]:
        """Add an A record to point a domain to an IP address."""
        dns_client = self.client_factory.get_dns_client()
        loop = asyncio.get_event_loop()
        
        def create_record():
            record_operation = dns_client.record_sets.create_or_update(
                resource_group_name=resource_group,
                zone_name=zone_name,
                relative_record_set_name=record_name,
                record_type="A",
                parameters={
                    "ttl": ttl,
                    "a_records": [{
                        "ipv4_address": ip_address
                    }]
                }
            )
            return record_operation
            
        try:
            record_result = await loop.run_in_executor(None, create_record)
            return {
                "result": "A record created successfully",
                "record_name": record_name,
                "ip_address": ip_address,
                "details": record_result.as_dict()
            }
        except Exception as e:
            return {
                "result": "Failed to create A record",
                "error": str(e)
            }

    async def verify_domain_ownership(
        self,
        resource_group: str,
        zone_name: str,
        verification_token: str
    ) -> Dict[str, Any]:
        """Add a TXT record for domain ownership verification."""
        dns_client = self.client_factory.get_dns_client()
        loop = asyncio.get_event_loop()
        
        def create_verification_record():
            record_operation = dns_client.record_sets.create_or_update(
                resource_group_name=resource_group,
                zone_name=zone_name,
                relative_record_set_name="@",
                record_type="TXT",
                parameters={
                    "ttl": 3600,
                    "txt_records": [{
                        "value": [verification_token]
                    }]
                }
            )
            return record_operation
            
        try:
            record_result = await loop.run_in_executor(None, create_verification_record)
            return {
                "result": "Domain verification record created successfully",
                "details": record_result.as_dict()
            }
        except Exception as e:
            return {
                "result": "Failed to create domain verification record",
                "error": str(e)
            } 