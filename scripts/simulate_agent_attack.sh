#!/usr/bin/env bash
set -e

echo "============================================================"
echo " [DEMO] Autonomous AI Agent Guardrail & Evidence Simulation "
echo "============================================================"
echo ""

echo "[1] Testing SAFE Request (Read-only CloudWatch Metric)..."
python3 gateway/interceptor.py policies/fixtures/safe_request.json
echo ""

echo "[2] Testing MALICIOUS Request (Destructive DROP TABLE in Production)..."
python3 gateway/interceptor.py policies/fixtures/malicious_drop.json || true
echo ""

echo "============================================================"
echo " [SUCCESS] Guardrail validation completed successfully!     "
echo "============================================================"
