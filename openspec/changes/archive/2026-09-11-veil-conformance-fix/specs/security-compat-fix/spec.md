## Purpose

Close the security and environment-compatibility gaps that block production: untrusted proxy-header IP, renamed redaction switches, and unvalidated custom PII rules.

## ADDED Requirements

### Requirement: Emergency revoke trusts only TCP peer

The system SHALL resolve emergency-revoke client IP only from the TCP `ConnectInfo`, never from `X-Forwarded-For` or similar proxy headers.

#### Scenario: Forged proxy header is ignored

- **WHEN** `POST /revoke/emergency` carries `X-Forwarded-For: 10.0.0.1` from a non-loopback TCP peer
- **THEN** the system ignores the header for allow-list decisions and returns 403 unless the TCP peer itself qualifies

#### Scenario: Loopback TCP peer still qualifies

- **WHEN** the TCP peer is loopback and no proxy header is present
- **THEN** the intranet exemption path remains available

### Requirement: PII env compatibility and fail-closed custom rules

The system SHALL accept `PII_REDACTION_ENABLED` as an alias of `REDACTION_ENABLED`, honor `PII_RESPONSE_SIDE`, `PII_FUZZY_RESTORE`, and `PII_DETECTION_HARDENING` with original semantics, and SHALL refuse startup when a configured `PII_CUSTOM_*` file is missing or unparsable.

#### Scenario: Legacy alias enables redaction

- **WHEN** only `PII_REDACTION_ENABLED=1` is set
- **THEN** request redaction is enabled exactly as with `REDACTION_ENABLED=1`

#### Scenario: Missing custom rule file blocks startup

- **WHEN** `PII_CUSTOM_RULES_FILE` points to a nonexistent path
- **THEN** startup fails with the variable name and path in the error

### Requirement: Sampling config lives in Config

`PII_VALUE_SAMPLE_ENABLED`, `PII_VALUE_SAMPLE_PERSIST`, and `PII_VALUE_SAMPLE_HMAC_KEY` SHALL be parsed into `Config` at startup instead of ad-hoc process-env reads, with hot-reload explicitly unsupported.

#### Scenario: Sampling flags are observable in config

- **WHEN** the service starts with sampling flags set
- **THEN** the effective values are available from `Config` and used by metrics without direct env reads on the request path
