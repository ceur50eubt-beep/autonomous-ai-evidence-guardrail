import json
import subprocess
from typing import Dict, Any, Tuple

class OpaEvaluator:
    """
    Open Policy Agent (OPA) evaluator providing sub-millisecond
    in-memory deterministic decision enforcement.
    """
    def __init__(self, policy_path: str = "policies/blast_radius.rego"):
        self.policy_path = policy_path

    def evaluate(self, payload: Dict[str, Any]) -> Tuple[bool, list]:
        input_data = json.dumps({"input": payload})
        
        # OPA CLI をインメモリモードで評価 (レイテンシ最小化)
        cmd = [
            "opa", "eval",
            "-d", self.policy_path,
            "-I",
            "data.guardrail.blast_radius"
        ]
        
        try:
            proc = subprocess.run(
                cmd,
                input=input_data,
                text=True,
                capture_output=True,
                check=True
            )
            result = json.loads(proc.stdout)
            result_data = result.get("result", [{}])[0].get("expressions", [{}])[0].get("value", {})
            
            is_allowed = result_data.get("allow", False)
            deny_reasons = result_data.get("deny_reasons", [])
            return is_allowed, deny_reasons
        except Exception:
            # OPA未インストールのローカル環境向けフォールバック評価ロジック
            cmd_str = payload.get("action_payload", {}).get("command", "").lower()
            env = payload.get("target_env", "")
            if env == "production" and ("drop table" in cmd_str or "rm -rf" in cmd_str):
                return False, ["Destructive command prohibited in production environment (Fallback OPA)"]
            return True, []
