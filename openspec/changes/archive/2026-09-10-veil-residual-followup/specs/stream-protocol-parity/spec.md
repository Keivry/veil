# stream-protocol-parity Specification — MODIFIED delta

## MODIFIED Requirements

### Requirement: Empty streams stay open-ended for chat/anthropic

Chat/Anthropic streams with zero residual bytes SHALL stay open-ended (no fabricated success termination) and the open-ended outcome SHALL be observable (`truncated_mode=open_ended`); Responses SHALL still synthesize a failed terminal. Downstream stub protection (e.g. Hermes) SHALL NOT be asserted as an in-repo guarantee; its evidence is tracked as an open item in README §8.6.

#### Scenario: Vacuum stream does not fabricate stop

- **WHEN** a chat stream ends with zero bytes written and no residue
- **THEN** downstream sees no synthetic `delta+stop+[DONE]`, `open_ended` is recorded, and any downstream stub protection remains an external dependency (README §8.6)

#### Scenario: Anthropic vacuum stream stays open-ended

- **WHEN** an anthropic stream ends with zero bytes written and no residue
- **THEN** downstream sees no synthetic `message_stop` and `open_ended` is recorded
