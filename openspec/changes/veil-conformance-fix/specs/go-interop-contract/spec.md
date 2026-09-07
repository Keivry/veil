## Purpose

Make the stock Go `get` client work unchanged against the Rust gateway by closing the six documented interop gaps, which also completes veil-hardening 5.1 through 5.3.

## ADDED Requirements

### Requirement: Gateway reads Go credential auth fields

The system SHALL accept `body.auth.get_binary_hash` and `body.auth.get_binary_secret` as aliases of the `X-Get-Binary-Hash` / `X-Get-Binary-Secret` headers (and existing `body.secret`) for credential fetch.

#### Scenario: Go fetch without headers authenticates

- **WHEN** `POST /credential` carries Go-style `body.auth.get_binary_secret` matching the server secret with consistent caller fields
- **THEN** authentication passes to the enrolled/approval path instead of fixed 403

### Requirement: Missing entry field fails loudly

`POST /credential` without a resolvable `entry`/`field` selector SHALL return 400 with a machine-readable hint instead of silently ignoring the fields.

#### Scenario: Entry-less request is rejected with guidance

- **WHEN** a credential request omits both header/body secrets resolution and entry selection
- **THEN** the gateway returns 400 naming the missing selector and the Go upgrade path

### Requirement: Error and health shapes are Go-readable

Error bodies SHALL remain `{error:{code,message}}` but SHALL also include a top-level string `error_detail` mirror, and `GET /health` SHALL include Go-compatible `status` and `unlocked` mirrors alongside `ok/sqlite_ok`.

#### Scenario: Go client surfaces the real error

- **WHEN** authentication fails for a Go fetch
- **THEN** the Go client can parse and display the server message instead of a generic parse failure

#### Scenario: Go status shows gateway health

- **WHEN** `get status` queries `GET /health`
- **THEN** it reads `status`/`unlocked` mirrors without breaking existing `ok` consumers
