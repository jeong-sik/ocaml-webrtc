# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.6.2] - 2026-01-22

### Added
- **DTLS-SRTP use_srtp Extension** (RFC 5764 Section 4.1.2)
  - `profile_to_code`/`code_to_profile` for SRTP protection profiles
  - `encode_use_srtp_extension`/`decode_use_srtp_extension` for TLS handshake
  - `client_use_srtp`/`server_use_srtp` helpers for ClientHello/ServerHello
  - `negotiate_profile` for SRTP profile negotiation
  - 6 new tests in `dtls_srtp_test.ml`

- **RTCP SDES/BYE Packets** (RFC 3550 Section 6.5, 6.6)
  - Full SDES (Source Description) encode/decode with CNAME, NAME, EMAIL, etc.
  - Full BYE (Goodbye) packet encode/decode with optional reason
  - `make_sdes_cname` and `make_bye` helper functions
  - 6 new tests for SDES/BYE/timing

- **RTCP Timing Calculation** (RFC 3550 Section 6.3)
  - `calculate_rtcp_interval` implements RFC 3550 deterministic algorithm
  - Bandwidth allocation: 75% receivers, 25% senders
  - Minimum interval handling (5s normal, 2.5s initial)

### Changed
- RTCP test count: 6 → 12 tests
- README.md Media Stack status updated (RTCP 70%, DTLS-SRTP 80%)

## [0.6.1] - 2026-01-20

### Added
- TURN TLS (`turns:`) allocate path with CA bundle support
- ICE TURN config `tls_ca` and `turns:` default port (5349)
- TURN relay smoke test supports TLS via `TURN_TLS_CA`

### Changed
- SCTP RE-CONFIG stream handling: separate outbound/inbound SSNs, pending reset flow
- RFC compliance docs updated for TURN TLS + SCTP RE-CONFIG improvements

## [0.6.0] - 2026-01-19

### Added
- **Functor-based Transport Interface** (`transport_intf.ml`)
  - Swappable transport abstraction for DTLS/ICE backends
- **DTLS Functor Adapter** (`dtls_functor.ml`)
  - Functorized DTLS stack binding transport implementations

### Changed
- Export functor transport modules in `webrtc.ml`
- Bump library version to 0.6.0

## [0.5.0] - 2025-01-19

### Added
- **ICE-DTLS-SCTP Transport** (`ice_dtls_transport.ml` - 574 lines)
  - Full stack integration combining ICE + DTLS + SCTP + DCEP
  - RFC 7983 packet demultiplexing (STUN vs DTLS based on first byte)
  - State machine: Disconnected → Ice_gathering → Ice_connected → Dtls_handshaking → Established
  - Callbacks: `on_local_candidate`, `on_state_change`, `on_channel_open`, `on_channel_data`

- **ICE Connectivity Checks** (`ice_check.ml` - 372 lines)
  - Sans-IO state machine for RFC 8445 connectivity checks
  - States: Frozen → Waiting → In_progress → Succeeded/Failed
  - Retransmission timer with exponential backoff (500ms → 3000ms max)
  - Transaction ID tracking and nomination support (USE-CANDIDATE)

- **Examples** (`examples/`)
  - `stun_client.ml` - Discover public IP via STUN server (tested with stun.l.google.com)
  - `ice_gathering.ml` - ICE candidate gathering with trickle callbacks
  - `dtls_echo.ml` - DTLS echo server/client for testing encryption
  - `datachannel.ml` - Full WebRTC DataChannel stack demo
  - `eio_datachannel.ml` - Eio-based async DataChannel example

- **DTLS Server-Side Handshake** (in `dtls.ml`)
  - `handle_record_as_server` for incoming ClientHello processing
  - Cookie validation with HMAC-based DoS protection
  - Retransmission timer per RFC 6347 §4.2.4

### Changed
- Updated README.md with v0.5.0 status, code examples, and architecture diagram
- DTLS module refactored for cleaner client/server role separation
- ICE module now fully integrates with Ice_check for connectivity verification

### Fixed
- STUN API: Corrected pattern matching to use `msg_class`/`msg_method` instead of `msg_type`
- Lwt async: Proper `Lwt_main.run` wrapping for `Ice.gather_candidates`
- Format vs Printf: Fixed pretty-printer compatibility for state display functions

## [0.4.0] - 2025-01-15

### Added
- **SCTP Core** (`sctp_core.ml` - 824 lines)
  - Full RFC 4960 state machine implementation
  - 4-way handshake: INIT → INIT-ACK → COOKIE-ECHO → COOKIE-ACK
  - DATA/SACK reliable delivery with congestion control
  - Stream multiplexing support

- **SCTP Tests**
  - `sctp_core_handshake_test.ml` - 9 handshake tests
  - `sctp_bundling_test.ml` - Chunk bundling tests

### Changed
- Improved SCTP packet encoding with proper CRC32c checksums

## [0.3.0] - 2025-01-10

### Added
- **DCEP** (`dcep.ml` - 310 lines)
  - DATA_CHANNEL_OPEN message encoding
  - DATA_CHANNEL_ACK handling
  - Reliable/Unreliable/Partial-Reliable modes
  - Protocol and label support

- **SCTP Packet Layer** (`sctp.ml` - 585 lines)
  - Chunk type definitions (DATA, INIT, SACK, etc.)
  - Binary encoding/decoding

## [0.2.0] - 2025-01-05

### Added
- **DTLS 1.2** (`dtls.ml` - 1728 lines)
  - Client handshake state machine
  - HelloVerifyRequest/Cookie handling
  - Record layer encryption/decryption
  - Effect-based I/O abstraction

- **ICE Agent** (`ice.ml` - 1182 lines)
  - Host candidate enumeration
  - Server-reflexive candidate gathering via STUN
  - Candidate priority calculation (RFC 8445)
  - Local credential generation

### Changed
- STUN module extended with FINGERPRINT and MESSAGE-INTEGRITY

## [0.1.0] - 2025-01-01

### Added
- **STUN** (`stun.ml` - 793 lines)
  - RFC 5389 Binding Request/Response
  - XOR-MAPPED-ADDRESS attribute
  - Transaction ID generation
  - Message encoding/decoding

- **Project Infrastructure**
  - Pure OCaml 5.x implementation
  - Dune build system with automatic c_flags.sexp generation
  - Mirage-crypto for cryptography
  - Type-safe binary protocol parsing with Cstruct

### Technical Decisions
- Sans-IO pattern for testability and formal verification
- No C bindings - pure OCaml throughout
- Support for both Lwt and Eio async runtimes
