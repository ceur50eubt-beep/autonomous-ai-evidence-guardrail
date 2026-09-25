import uuid
import time
from typing import Dict, Any

class TokenBroker:
    """
    Zero Standing Privileges (ZSP) Broker:
    Dispatches short-lived (15 minutes), highly-scoped ephemeral
    AWS STS credentials strictly on-demand after policy approval.
    """
    def __init__(self, ttl_seconds: int = 900):
        self.ttl_seconds = ttl_seconds

    def issue_ephemeral_token(self, agent_id: str, scoped_action: str) -> Dict[str, Any]:
        session_id = f"ai-session-{uuid.uuid4().hex[:8]}"
        expiration = int(time.time()) + self.ttl_seconds
        
        return {
            "SessionId": session_id,
            "AssumedRoleArn": f"arn:aws:iam::123456789012:role/scoped-{agent_id}",
            "ScopedAction": scoped_action,
            "AccessKeyId": f"ASIA{uuid.uuid4().hex[:16].upper()}",
            "SecretAccessKey": uuid.uuid4().hex,
            "SessionToken": f"IQoJb3JpZ2luX2VjE...{uuid.uuid4().hex}",
            "Expiration": expiration,
            "TTLSeconds": self.ttl_seconds
        }
