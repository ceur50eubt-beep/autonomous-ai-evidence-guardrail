import json
import sys
from opa_evaluator import OpaEvaluator
from evidence_signer import EvidenceSigner
from token_broker import TokenBroker

def process_agent_request(payload_path: str):
    with open(payload_path, "r") as f:
        request_data = json.load(f)

    evaluator = OpaEvaluator()
    signer = EvidenceSigner()
    broker = TokenBroker(ttl_seconds=900)

    # 1. OPA によるミリ秒判定
    allowed, deny_reasons = evaluator.evaluate(request_data)
    decision = "ALLOW" if allowed else "DENY"

    # 2. Evidence as Code: 暗号署名付き監査レコード生成
    evidence = signer.build_evidence_payload(request_data, decision, deny_reasons)

    print("==================================================")
    print(f"[*] Request Processed: {request_data.get('agent_id')}")
    print(f"[*] Decision         : {decision}")
    
    if not allowed:
        print(f"[!] Deny Reason      : {deny_reasons}")
        print(f"[*] SHA-256 Digest   : {evidence['sha256_digest']}")
        print(f"[*] KMS Signature    : {evidence['signature']}")
        print("[!] Execution Intercepted & Blocked.")
        print("==================================================")
        return False
    else:
        token = broker.issue_ephemeral_token(
            request_data.get("agent_id"),
            request_data.get("action_payload", {}).get("action")
        )
        print(f"[*] Ephemeral Token  : Issued (TTL: {token['TTLSeconds']}s)")
        print(f"[*] Assumed Session  : {token['SessionId']}")
        print(f"[*] KMS Signature    : {evidence['signature']}")
        print("[SUCCESS] Execution Permitted.")
        print("==================================================")
        return True

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 interceptor.py <path_to_payload.json>")
        sys.exit(1)
    process_agent_request(sys.argv[1])
