## Purpose

Bring docs, thresholds, and regression gates back in sync with the shipped code so operators can deploy from README alone and CI blocks wire regressions.

## ADDED Requirements

### Requirement: README is a complete deploy entry

README SHALL document the full PII/AUDIT/TPM/LLM env table, the single-port `127.0.0.1:8877` runtime versus compose three-port mapping semantics, the missing `admin.html` scope, and `VEIL_ALLOW_MOCK_TPM=1` dev-only guidance with zero drift from specs.

#### Scenario: New operator deploys from README

- **WHEN** an operator follows README with a TPM-less dev machine
- **THEN** health checks pass with the documented mock-TPM flag and no undocumented variable is required

### Requirement: Regression gates cover the fixed wires

CI SHALL run the new regression set (forged-header revoke, bare DONE, Anthropic start set, usage monotonicity, Go auth alias, custom-rule fail-closed) plus `scripts/api_conformance.py` with built-in mock-TPM fallback, and SHALL fail on any wire-shape drift.

#### Scenario: DONE pollution blocks merge

- **WHEN** a change reintroduces `event:` on the Chat DONE frame
- **THEN** CI fails before merge
