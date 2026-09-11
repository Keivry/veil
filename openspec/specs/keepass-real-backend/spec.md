# keepass-real-backend Specification

## Purpose
Provide the production KeePassXC backend with the exact selection, lookup, and protection semantics of the Python proxy so credential fetch works end to end.

## Requirements

### Requirement: Database selection matches original

The system SHALL scan `DB_DIR` for `*.kdbx`, choose the last in sorted order, prefer the same-basename `.key` file, warn when multiple databases exist, and return 503 `密码库未配置` when none exists.

#### Scenario: Multiple databases pick last sorted

- **WHEN** `DB_DIR` contains `a.kdbx` and `z.kdbx`
- **THEN** the gateway opens `z.kdbx` and logs the multi-DB warning

#### Scenario: No database yields 503

- **WHEN** `DB_DIR` has no `.kdbx`
- **THEN** `POST /credential` returns 503 without attempting unlock

### Requirement: Field-level query with tokenization

The system SHALL require `entry` (400 when blank), treat absent `field` as full-entry fetch, default `token` to true, tokenize `password` and protected custom properties via the vault when `use_token` is true, and return raw values otherwise.

#### Scenario: Full entry fetch

- **WHEN** `entry` exists and `field` is absent with `token=true`
- **THEN** the response contains `title/username/password/url` plus tokenized `custom_properties` for protected keys

#### Scenario: Single protected field

- **WHEN** `field` names a protected custom property with `token=true`
- **THEN** the response is `{value: __VG_CRED_NNNNNN__}` and the mapping restores downstream

#### Scenario: Missing entry or attribute

- **WHEN** the title is not found or the attribute is absent
- **THEN** the gateway returns 404 naming the entry or attribute

### Requirement: Serialized access and sealed master password

KDBX open and entry lookup SHALL be serialized by a permit-1 semaphore executed off the async runtime, the master password SHALL come from TPM unseal (`TPM_DIR/seal.pub|priv`), SHALL be zeroized on drop/rotation, and any failure on the auto-approve path SHALL notify Matrix and return 500 `KeePass 内部错误`.

#### Scenario: Concurrent fetches serialize

- **WHEN** two credential fetches race on a cold cache
- **THEN** the database opens once and both complete without data race

#### Scenario: Auto-approve query failure notifies

- **WHEN** the KDBX query throws on the auto-approve path
- **THEN** Matrix receives the failure notice and the caller gets 500
