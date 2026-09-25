# Autonomous AI Evidence Guardrail
> **Policy-as-Code & Evidence-as-Code for Autonomous AI Agents**

[![Verify & Policy Test](https://github.com/ceur50eubt-beep/autonomous-ai-evidence-guardrail/actions/workflows/verify_and_test.yml/badge.svg)](https://github.com/ceur50eubt-beep/autonomous-ai-evidence-guardrail/actions/workflows/verify_and_test.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

An enterprise-grade safety gateway that enforces real-time **Policy-as-Code (OPA/Rego)** and immutable **Evidence-as-Code (AWS KMS + S3 Object Lock)** for autonomous AI agents (MCP / tool-use APIs) before executing critical infrastructure or database operations.

---

## 1. Background & Problem Statement

As enterprises adopt autonomous AI agents (e.g., Anthropic MCP, LangChain / LangGraph, AutoGen) for site reliability and infrastructure operations, traditional access control models fail:
1. **Unbounded Blast Radius**: Prompt injection or hallucinations can lead to catastrophic infrastructure modifications (e.g., dropping production tables, self-escalating IAM privileges).
2. **Lack of Provable Accountability**: Traditional CloudWatch/Datadog logs are mutable and often omit agent reasoning metadata, failing internal controls and external regulatory audits (SOC 2, ISO 27001, financial compliance).
3. **Standing Privilege Risks**: Assigning long-lived API/IAM credentials to AI agents introduces critical blast radius expansion if compromised.

---

## 2. Core Architecture

[ Autonomous AI Agent ] (MCP / API Request)
│
▼
[ Safety Gateway Interceptor ] (gateway/interceptor.py)
│
├───▶ [ OPA / Rego Engine ] (policies/blast_radius.rego)
│       └─ Evaluates: Actor, Operation, Blast Radius, Production Flags
│
├── [ DENY ] ──▶ 403 Forbidden & Signs Rejection Audit Log
│
└── [ ALLOW ]
│
├──▶ [ STS Token Broker ] (gateway/token_broker.py)
│       └─ Generates 15-min Ephemeral Scoped Credentials (ZSP)
│
├──▶ [ Evidence Signer ] (gateway/evidence_signer.py)
│       └─ Signs (Prompt + Reasoning + Action + Hash) via AWS KMS Asymmetric Key
│
├──▶ [ Immutable Audit Store ] (S3 Object Lock / WORM)
│       └─ Stores digitally signed audit trail with retention lock
│
└──▶ [ Execution Target ] (AWS Infrastructure / Database)

---

## 3. Key Design Highlights

### 1. Deterministic Blast Radius Control (Policy-as-Code)
Instead of relying on prompt engineering or system instructions, the gateway intercepts requests at the network/API layer. Open Policy Agent (OPA) strictly evaluates requests in sub-milliseconds:
* Block dangerous commands (`DROP TABLE`, `rm -rf`, `DeleteVpc`, `PutRolePolicy` privilege escalations).
* Enforce production separation and least-privilege scoping.

### 2. Evidence-as-Code (Immutable Audit Trail)
Every execution attempt (both `ALLOW` and `DENY`) generates an audit payload containing:
* Raw prompt input, agent inference reasoning, executed command payload, and timestamp.
* **Cryptographic Signature**: Signed with an **AWS KMS Asymmetric RSA/ECC key**.
* **WORM Storage**: Uploaded to an **S3 bucket configured with Object Lock (Compliance Mode)** to prevent tampering or deletion by anyone—including the root account.

### 3. Zero Standing Privileges (ZSP)
Agents possess no persistent credentials. Only upon passing policy verification does the gateway request a short-lived (15-minute) dynamic AWS STS assumed role token tailored precisely to the requested action.

---

## 4. Directory Structure

```text
autonomous-ai-evidence-guardrail/
├── README.md
├── terraform/                         # Terraform IaC for immutable storage and KMS signing
│   ├── modules/
│   │   ├── kms_signing/               # AWS KMS Asymmetric Key for digital signature
│   │   └── audit_storage/             # S3 Object Lock (WORM) storage configuration
│   ├── main.tf
│   ├── variables.tf
│   └── outputs.tf
├── policies/                          # Open Policy Agent (Rego) specifications
│   ├── blast_radius.rego              # Restrict destructive commands & production impact
│   ├── rbac.rego                      # Least privilege and role-based action validation
│   ├── blast_radius_test.rego         # Policy unit tests
│   └── fixtures/                      # Mock test payloads
│       ├── safe_request.json
│       └── malicious_drop.json
├── gateway/                           # Interceptor & Signer logic (Python)
│   ├── interceptor.py                 # Gateway proxy entry point
│   ├── opa_evaluator.py               # Policy evaluation connector
│   ├── evidence_signer.py             # KMS hash & signature generator
│   └── token_broker.py                # Ephemeral STS token dispatcher
├── scripts/
│   └── simulate_agent_attack.sh       # Attack simulation & demo execution script
└── .github/
    └── workflows/
        └── verify_and_test.yml        # CI Pipeline (Rego test & Terraform fmt/validate)

opa test ./policies -v

chmod +x ./scripts/simulate_agent_attack.sh
./scripts/simulate_agent_attack.sh

cat << 'EOF' > policies/blast_radius.rego
package guardrail.blast_radius

import future.keywords.in

default allow = false
default deny_reasons = []

destructive_keywords := [
"drop table", "drop database", "truncate", "rm -rf",
"delete from", "deletevpc", "terminateinstances", "deletecluster"
]

allow {
count(deny_reasons) == 0
}

deny_reasons[msg] {
input.target_env == "production"
some keyword in destructive_keywords
contains(lower(input.action_payload.command), keyword)
msg := sprintf("Destructive command '%v' is strictly prohibited in production environment", [keyword])
}

deny_reasons[msg] {
dangerous_iam_actions := ["iam:PutRolePolicy", "iam:AttachRolePolicy", "iam:CreateAccessKey"]
input.action_payload.action in dangerous_iam_actions
not input.context.security_approved
msg := sprintf("IAM privilege escalation attempt '%v' blocked without Security Approval", [input.action_payload.action])
}
