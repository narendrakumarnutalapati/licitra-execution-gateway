# LICITRA and MCP (Model Context Protocol)

## What MCP Is

Model Context Protocol is Anthropic's open standard
for connecting AI models to external tools and data
sources. MCP defines how an AI agent discovers and
calls tools at runtime.

## The Gap MCP Does Not Address

MCP defines the communication protocol between an
agent and a tool. It does not:

- Prove the tool call payload was not modified
  between approval and execution
- Prevent replay of approved tool calls
- Validate tool output against a declared schema
- Produce tamper-evident audit records of tool calls

## Where LICITRA Fits

```
Agent (LLM)
│
│ decides to call MCP tool
│
▼
LICITRA (pre-execution check)
│
├─ POST /intent/create — injection scan
├─ POST /policy/evaluate — rate limits
├─ POST /tickets/issue — bind payload hash
└─ POST /actions/verify — 12 checks
│
│ ALLOWED
│
▼
MCP Tool Call (actual execution)
│
▼
LICITRA records evidence
```

## Integration Example

When an agent using MCP wants to call a Salesforce
tool via MCP:

1. Agent constructs the tool call parameters
2. Before calling the MCP server, agent calls
   `POST /actions/verify` with the exact parameters
3. LICITRA verifies payload hash, schema, injection
4. If ALLOWED: agent proceeds with MCP tool call
5. Evidence record written to MMR

## OWASP Agentic AI Alignment

The OWASP Agentic AI framework (2026) identifies
tool misuse as a primary attack surface. LICITRA
addresses this at the MCP layer by:

- Scanning tool call intent for injection (LLM01)
- Validating tool call output schema (LLM05)
- Binding approved parameters to execution (LLM06)
- Rate limiting tool calls per agent (LLM10)

## Positioning vs MCP Authorization

MCP is adding authorization features. LICITRA is
complementary — MCP authorization determines if
the agent can call the tool. LICITRA proves the
call that executed matched the call that was approved.
