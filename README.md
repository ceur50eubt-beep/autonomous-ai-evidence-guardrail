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

```text
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
```
