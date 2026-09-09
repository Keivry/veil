## Purpose

Restore PII value sampler parity with the Python implementation so masks, hashes, and aggregations are correct per kind.

## ADDED Requirements

### Requirement: Masks vary by kind

`sample_mask` SHALL accept `kind` and produce per-kind masks (phone/email/bank/ipv4/api_key/other).

#### Scenario: Phone and email differ

- **WHEN** sampling a phone vs an email
- **THEN** masks follow `138****8000` vs `***@***.com` shapes respectively

### Requirement: Hashes are 16 hex chars

`hash_value` SHALL return the first 16 hex chars of HMAC-SHA256 (or degraded SHA256 with warn).

#### Scenario: Hash length is 16

- **WHEN** any value is hashed
- **THEN** the result is exactly 16 hex chars

### Requirement: Masks truncate at 64

No mask SHALL exceed 64 chars (UTF-8 safe truncation).

#### Scenario: Long email truncates

- **WHEN** sampling a 100-char email
- **THEN** `len(mask) <= 64`

### Requirement: Empty values are counted

Empty-string PII SHALL sample as `***` with hash counted, never skipped as `None`.

#### Scenario: Empty value appears in stats

- **WHEN** value is `""`
- **THEN** it is counted with mask `***`

### Requirement: Dedup keys include kind

In-memory dedup and SQL upsert SHALL key on `(day, upstream, kind, hash)`.

#### Scenario: Same plaintext different kinds do not merge

- **WHEN** identical plaintext appears as phone and as bank
- **THEN** two separate entries with independent hits exist
