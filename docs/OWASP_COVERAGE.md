# LICITRA OWASP LLM Coverage

## Coverage Summary

| Risk | Name | LICITRA Coverage | Where Implemented |
|---|---|---|---|
| LLM01 | Prompt Injection | PRIMARY | scan_for_injection() at intent + re-scan at verify check 10 |
| LLM02 | Sensitive Data Disclosure | NONE | Out of scope |
| LLM03 | Supply Chain | NONE | Out of scope |
| LLM04 | Data/Model Poisoning | NONE | Out of scope |
| LLM05 | Improper Output Handling | PRIMARY | validate_output_schema() at verify check 9 |
| LLM06 | Excessive Agency | PRIMARY — CORE | Full 12-check ticket-verify cycle |
| LLM07 | System Prompt Leakage | NONE | Out of scope |
| LLM08 | Vector/Embedding Weaknesses | NONE | Out of scope |
| LLM09 | Misinformation | NONE | Out of scope |
| LLM10 | Unbounded Consumption | PRIMARY | check_rate_limit() + check_budget() at policy |

## Why LLM01 — Prompt Injection
AI agents receive natural language instructions. Malicious inputs can override intended behavior and cause agents to take unauthorized actions. LICITRA intercepts at the intent layer — before any action is approved — and re-scans payloads at verify time. Both entry and execution points are covered.

## Why LLM05 — Improper Output Handling
When an AI agent constructs an action payload, that payload may contain unexpected fields, wrong types, or structures designed to exploit downstream systems. LICITRA requires agents to declare output schemas at registration. Every payload is validated against the declared schema before execution is permitted.

## Why LLM06 — Excessive Agency (CORE)
This is LICITRA's primary value. Agents must not be able to act beyond what was specifically approved. The 12-check verification flow — including exact action matching, exact resource matching, payload hash binding, and decision binding — ensures the exact action that executes is the exact action that was approved. No scope creep. No replay. No drift.

## Why LLM10 — Unbounded Consumption
Autonomous agents with no rate controls can exhaust API quotas, overwhelm downstream services, or accumulate runaway costs. LICITRA enforces per-agent hourly action counts, daily action counts, and daily cost budgets at the policy layer using SELECT FOR UPDATE to prevent race conditions.

## Why NOT LLM02 — Sensitive Data Disclosure
Content classification and output filtering are inference-layer concerns. LICITRA operates at the execution layer — it verifies that approved actions execute correctly, not that outputs are safe. Tools like guardrails or output classifiers own this layer.

## Why NOT LLM03 — Supply Chain
Model provenance, plugin signing, and SBOM verification are build-time and deployment-time concerns. LICITRA operates at runtime. Hardware attestation tools like OPAQUE own this layer.

## Why NOT LLM04 — Data/Model Poisoning
Training pipeline integrity and embedding drift detection are training-time concerns. LICITRA operates at execution time. MLOps tooling owns this layer.

## Why NOT LLM07 — System Prompt Leakage
System prompt protection is an inference-layer concern requiring model-level integration. LICITRA does not intercept model inference. This is a deployment and model configuration concern.

## Why NOT LLM08 — Vector/Embedding Weaknesses
RAG pipeline security, embedding validation, and retrieval integrity are data-layer concerns. LICITRA does not inspect retrieval or embedding operations.

## Why NOT LLM09 — Misinformation
Output truthfulness, factual grounding, and hallucination detection require evaluation of content semantics. LICITRA verifies structural and cryptographic integrity of actions, not the truthfulness of content.

## Positioning Statement
LICITRA claims PRIMARY coverage for LLM01, LLM05, LLM06, LLM10 only. Every claim is verifiable directly from the codebase. We do not claim broad OWASP coverage because broad claims that cannot be verified are worse than narrow claims that can.