# OAS Error Contract

Error types, classification, and recovery strategies per module.

See `oas_error.mli` for the classification API.

## Error Classes

| Class | Meaning | Caller Action |
|-------|---------|---------------|
| **Transient** | Temporary condition (congestion, timing) | Back off, retry |
| **Protocol** | Malformed data or invalid packet | Drop packet, log, continue |
| **Fatal** | Unrecoverable (abort, auth failure) | Tear down connection |
| **Config** | Wrong state or invalid setup | Fix configuration, re-establish |

## Module Error Inventory

### Sctp_core (Sans-IO State Machine)

| Error String Pattern | Class | Recovery |
|---------------------|-------|----------|
| `"Congestion window full"` | Transient | Wait for SACK, retry |
| `"Packet too short for SCTP header"` | Protocol | Drop packet |
| `"CRC32c mismatch"` | Protocol | Drop packet |
| `"DATA decode: ..."` | Protocol | Drop packet |
| `"SACK decode: ..."` | Protocol | Drop packet |
| `"INIT processing: ..."` | Protocol | Drop, may retry handshake |
| `"INIT-ACK processing: ..."` | Protocol | Drop, may retry handshake |
| `"COOKIE-ECHO processing: ..."` | Protocol | Drop, may retry handshake |
| `"RE-CONFIG decode: ..."` | Protocol | Drop packet |
| `"Association aborted by peer ..."` | Fatal | Tear down |
| `"Shutdown timeout"` | Fatal | Tear down |
| `"Peer reported N error cause(s)"` | Protocol | Log, may tear down |
| `"Received INIT-ACK but no handshake in progress"` | Config | State mismatch |
| `"Received COOKIE-ACK in unexpected state"` | Config | State mismatch |
| `"RE-CONFIG requires Established state"` | Config | Wait for Established |

Output type: `output = ... | Error of string` (line 77 of `sctp_core.mli`).

Return type for functions: N/A (Sans-IO outputs via `output list`).

### Sctp_heartbeat

| Error String Pattern | Class | Recovery |
|---------------------|-------|----------|
| `"Heartbeat info too short"` | Protocol | Drop |
| `"HEARTBEAT chunk too short"` | Protocol | Drop |
| `"Not a HEARTBEAT chunk"` | Protocol | Drop |
| `"HEARTBEAT-ACK chunk too short"` | Protocol | Drop |
| `"Not a HEARTBEAT-ACK chunk"` | Protocol | Drop |
| `"HEARTBEAT-ACK nonce mismatch"` | Protocol | Drop |
| `"Unexpected HEARTBEAT-ACK"` | Transient | Ignore, may retry |

Return type: `(T, string) result`.

### Sctp_handshake

Return type: `(T, string) result`.

All errors are Protocol class (malformed INIT/INIT-ACK/COOKIE chunks).

### Sctp_reconfig

| Error String Pattern | Class | Recovery |
|---------------------|-------|----------|
| `"Invalid stream list length"` | Protocol | Drop |
| `"Reset request too short"` | Protocol | Drop |
| `"Reconfig response too short"` | Protocol | Drop |
| `"Add streams parameter too short"` | Protocol | Drop |
| `"Invalid parameter length"` | Protocol | Drop |
| `"Not a RE-CONFIG chunk"` | Protocol | Drop |

Return type: `(T, string) result`.

### Dcep (DataChannel Establishment Protocol)

| Error String Pattern | Class | Recovery |
|---------------------|-------|----------|
| `"DATA_CHANNEL_OPEN too short"` | Protocol | Drop |
| `"Expected OPEN (0x03), got ..."` | Protocol | Drop |
| `"DATA_CHANNEL_OPEN truncated"` | Protocol | Drop |
| `"ACK for unknown channel N"` | Config | Channel not registered |

Return type: `(T, string) result`.

### Dtls / Dtls_eio

| Error Pattern | Class | Recovery |
|---------------|-------|----------|
| `"Handshake timeout: max retransmits exceeded"` | Fatal | Restart DTLS |
| Decode/parse errors | Protocol | Drop record |

State type: `dtls_state = ... | Error of string` (`dtls_types.mli`).

### Dtls_sctp_transport

Output type: `output = ... | Error of string`.

Errors follow the same classification as the underlying DTLS and SCTP layers.

### Sctp_transport / Sctp_full_transport

| Function | Return Type | Error Class |
|----------|-------------|-------------|
| `send_data` | `(int, string) result` | Transient (congestion) or Fatal |
| `recv_data` | `(bytes, string) result` | Transient (timeout) or Protocol |

### Udp_transport / Eio_udp_transport

| Function | Return Type | Error Class |
|----------|-------------|-------------|
| `send` | `(int, string) result` | Transient (network) |
| `recv` | `(int * endpoint, string) result` | Transient (timeout) |
| `recv_timeout` | `(int * endpoint, string) result` | Transient (timeout) |

### SRTP

All errors are Protocol class (cryptographic failures, malformed packets).

Return type: `(T, string) result` for all functions.

Exception: `"AES-GCM authentication failed"` is Fatal (indicates MITM or key mismatch).

### STUN

Has its own `error_code` type (RFC 5389 Section 15.6):

| Error Code | Mapping |
|-----------|---------|
| `Try_alternate` (300) | Transient |
| `Bad_request` (400) | Protocol |
| `Unauthorized` (401) | Config |
| `Unknown_attribute` (420) | Protocol |
| `Stale_nonce` (438) | Transient |
| `Server_error` (500) | Transient |

`decode : bytes -> (message, string) result` — Protocol class errors.

### TURN

| Function | Return Type | Error Class |
|----------|-------------|-------------|
| `allocate` | `(string * int, string) result` | Transient or Config |
| `refresh` | `(int, string) result` | Transient |
| `create_permission` | `(unit, string) result` | Config or Transient |
| `channel_bind` | `(unit, string) result` | Config |
| `send_data` | `(unit, string) result` | Transient |

### Webrtc_crypto

| Error Pattern | Class | Recovery |
|---------------|-------|----------|
| `"AES-GCM authentication failed"` | Fatal | Key mismatch, re-handshake |

### ICE / Ice_check / Ice_eio

No `(T, string) result` in public API. Errors are communicated via ICE state transitions (failed/disconnected).

### Sctp_error (RFC 4960 Wire Protocol)

Not an application error module. Encodes/decodes RFC 4960 ERROR chunks for wire protocol. See `oas_error.ml` for application-level classification.

### Oas_error (Application-Level Classification)

Provides `classify : string -> error_class` to convert any raw error string from the modules above into `Transient | Protocol | Fatal | Config`.

## Classification Defaults

Unknown error strings default to **Protocol** (conservative: do not retry what you do not understand).

## Migration Path

Current: `Error of string` in `Sctp_core.output`.

Future: Replace with `Error of Oas_error.t` to carry classification inline. This is a breaking change and should be done in a major version bump.
