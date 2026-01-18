# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-01-18

### Added
- Initial alpha release
- STUN protocol implementation (RFC 5389)
- TURN protocol implementation (RFC 5766)
- Basic ICE agent (RFC 8445) - in progress
- DTLS handshake (RFC 6347) - in progress
- SDP parser (RFC 8866) - basic support

### Technical
- Pure OCaml 5.x implementation
- Eio-based async I/O
- Mirage-crypto for cryptography
- Type-safe binary protocol parsing

### Planned
- SCTP (RFC 4960)
- DCEP (RFC 8832)
- Full ICE connectivity checks
- DTLS 1.2/1.3 support
