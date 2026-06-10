# LICITRA Execution Gateway — Roadmap

## MVP (Current — 13 Days)
Core execution integrity flow end to end:
- Intent creation with LLM01 injection scanning
- Policy evaluation with LLM10 rate limiting and budget
- Ed25519 signed execution tickets
- 12-check verification with LLM05 schema validation
- MMR audit chain with O(log N) inclusion proofs
- 10 attack demo scripts
- React dashboard with OWASP view and MMR verifier
- 81+ pytest tests
- Docker Compose deployment
- PDF evidence generation

## v1.1 — Production Hardening (Month 2)
- Multi-tenancy: tenant_id on all tables, data isolation between organizations
- RBAC: Admin, Security Officer, Developer, Auditor, Read-Only roles
- Key rotation: key_version, key_expiry, key_revocation on agent keys
- Policy versioning: policy_version and policy_snapshot in every ticket
- OpenTelemetry traces on all API endpoints
- Prometheus metrics endpoint
- CI/CD pipeline with GitHub Actions
- Security scanning with Bandit and Safety

## v2.0 — Enterprise (Month 4-6)
- OIDC/SAML SSO integration
- SCIM user provisioning
- SOC2 controls documentation
- SIEM integration (Splunk, Datadog)
- AWS Secrets Manager / HashiCorp Vault for key storage
- Read replica support for audit queries
- Horizontal scaling with load balancer
- Automated backup strategy

## Non-Goals (Permanent)
- NOT a governance platform
- NOT an identity management system
- NOT a credential vault
- NOT a general AI monitoring dashboard
- NOT a chatbot