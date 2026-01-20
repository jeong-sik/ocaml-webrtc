# RFC Test Expansion Plan

Goal: expand ocaml-webrtc tests to reach RFC 100% compliance for
DataChannel + Media (audio + video). This plan follows the
`docs/RFC-COMPLIANCE.md` gap list.

## Test layers

1) Unit tests: pure encode/decode and deterministic helpers.
2) State-machine tests: Sans-IO transitions with fixed inputs.
3) Integration tests: loopback pipelines (ICE -> DTLS -> SCTP -> DCEP).
4) Interop tests: Chrome/Firefox and Pion/aiortc smoke suites.
5) Fuzz tests: decode paths for STUN/DTLS/SCTP/SDP.

## Planned test suites (by RFC area)

### STUN (RFC 5389/8489)
- Add STUN message vectors (binding request/response, error codes).
- Validate MESSAGE-INTEGRITY and FINGERPRINT against known vectors.
- Exercise unknown/optional attributes and length/padding rules.
- File targets: `test/stun_rfc_test.ml`, `test/fixtures/stun/*.hex`.

### ICE (RFC 8445/8838)
- Validate candidate priority formula and pair ordering.
- Connectivity checks: role conflict, tie-breaker, nomination, and retry backoff.
- Trickle ICE: end-of-candidates, mid-check candidate injection, restart.
- File targets: `test/ice_rfc_test.ml`, `test/ice_trickle_test.ml`.

### TURN (RFC 5766/6156)
- Allocate/refresh/channel bind, permissions, and nonce/realm auth flows.
- Data indications and channel data framing.
- IPv6 address parsing and XOR-RELAYED-ADDRESS handling.
- File targets: `test/turn_rfc_test.ml`, `test/turn_relay_smoke.ml`, `test/fixtures/turn/*.hex`.

### DTLS (RFC 6347 + 5246/5288/8422/5705)
- Handshake transcript tests with deterministic randoms.
- HelloVerifyRequest, cookie retry, and retransmission timing.
- Key exporter vectors for DTLS-SRTP (RFC 5764 prep).
- File targets: `test/dtls_rfc_test.ml`, `test/dtls_key_export_test.ml`.

### SCTP (RFC 4960/3758/8985/6525/8261)
- Full chunk coverage: INIT/INIT-ACK/COOKIE/ABORT/SHUTDOWN/ERROR/HEARTBEAT.
- RE-CONFIG (RFC 6525) once implemented; add chunk parse/encode vectors.
- SCTP-over-DTLS framing and demux correctness.
- File targets: `test/sctp_rfc_test.ml`, `test/sctp_reconfig_test.ml`.

### DataChannel (RFC 8831/8832)
- DCEP open/ack for reliable/unreliable modes and edge cases.
- Stream ID parity (client even, server odd) and ordering semantics.
- PPID mapping correctness for string/binary/empty.
- File targets: `test/dcep_rfc_test.ml`, `test/datachannel_rfc_test.ml`.

### SDP / Offer-Answer (RFC 4566/8866/3264/8839/8841)
- Round-trip parse/serialize for ICE, DTLS fingerprint, and SCTP attrs.
- Offer/Answer validation for DataChannel and media sections.
- File targets: `test/sdp_rfc_test.ml`, `test/fixtures/sdp/*.sdp`.

### RTP/RTCP/SRTP (RFC 3550/3551/3711/4585/5764)
- RTP header extension parsing (CSRC + extension length).
- RTCP compound packet parsing (SR/RR/SDES/BYE) and scheduling rules.
- SRTP protect/unprotect test vectors (AES-CTR + HMAC-SHA1, AES-GCM if added).
- DTLS-SRTP end-to-end: exporter -> SRTP keys -> encrypt/decrypt.
- File targets: `test/rtp_rtcp_rfc_test.ml`, `test/srtp_rfc_test.ml`.

### RTP Payload Formats (RFC 7587/7741/7742/6184)
- Opus payload format compliance vectors (RFC 7587).
- VP8/VP9 payload framing and partition handling (RFC 7741/7742).
- H.264 payload format (NALU aggregation, FU-A) vectors (RFC 6184).
- File targets: `test/rtp_payload_test.ml`, `test/fixtures/rtp/*.bin`.

## Interop plan

1) DataChannel:
   - Chrome/Firefox loopback with sdp offer/answer from `sdp.ml`.
   - Pion/aiortc interop using SCTP over DTLS.
2) Audio:
   - Chrome/Firefox Opus audio-only call via DTLS-SRTP.
   - Record SDP and packet traces as fixtures.
3) Video:
   - Chrome/Firefox VP8 or H.264 call via DTLS-SRTP.
   - Pion/aiortc video interop smoke tests.

## Priorities

- P0: DTLS-SRTP, SRTP, RTP/RTCP core coverage (blocks media RFC completion).
- P1: TURN relay integration and Trickle ICE full lifecycle.
- P2: SCTP reconfiguration (RFC 6525) + full SDP Offer/Answer (RFC 3264).
- P3: RTP payload format coverage (Opus/VP8/VP9/H.264).
