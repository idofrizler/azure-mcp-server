from dataclasses import dataclass
from typing import Optional

@dataclass
class AzureConfig:
    subscription_id: str
    tenant_id: Optional[str] = None
    client_id: Optional[str] = None
    client_secret: Optional[str] = None 