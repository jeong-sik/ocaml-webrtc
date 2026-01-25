# Interop/Test Status (2026-01-25)

Status: local run (not CI). No browser interop or external TURN relay executed.

## Environment

- Host: maladies.local
- OS: Darwin
- OCaml: 5.4.0
- Opam switch: 5.4.0
- Commit: 3c98c01

## Executed Tests (Pass)

All commands were run with `dune exec --root . -- ./test/<name>.exe`.

| Test | Result | Notes | Log |
|------|--------|-------|-----|
| dtls_handshake_test | pass | DTLS 1.2 handshake unit tests | /Users/dancer/me/logs/ocaml-webrtc-dtls-handshake-20260125-213257.log |
| rfc_compliance_test | pass | SCTP RFC 4960/8985/3758 unit tests | /Users/dancer/me/logs/ocaml-webrtc-rfc-compliance-20260125-213424.log |
| ice_check_test | pass | ICE connectivity checks | /Users/dancer/me/logs/ocaml-webrtc-ice-check-20260125-213456.log |
| ice_trickle_test | pass | Trickle ICE callbacks | /Users/dancer/me/logs/ocaml-webrtc-ice-trickle-20260125-213521.log |
| sctp_core_handshake_test | pass | SCTP Sans-IO handshake | /Users/dancer/me/logs/ocaml-webrtc-sctp-core-handshake-20260125-213540.log |
| sctp_handshake_test | pass | SCTP handshake unit tests | /Users/dancer/me/logs/ocaml-webrtc-sctp-handshake-20260125-213558.log |
| sctp_reconfig_test | pass | SCTP RE-CONFIG | /Users/dancer/me/logs/ocaml-webrtc-sctp-reconfig-20260125-213618.log |
| sctp_rack_test | pass | RACK algorithm | /Users/dancer/me/logs/ocaml-webrtc-sctp-rack-20260125-213638.log |
| sctp_bundling_test | pass | SCTP bundling | /Users/dancer/me/logs/ocaml-webrtc-sctp-bundling-20260125-213658.log |
| sctp_error_test | pass | SCTP error handling | /Users/dancer/me/logs/ocaml-webrtc-sctp-error-20260125-213719.log |
| dcep_test | pass | DCEP encode/decode | /Users/dancer/me/logs/ocaml-webrtc-dcep-20260125-213743.log |
| sdp_test | pass | SDP parsing/offer/answer | /Users/dancer/me/logs/ocaml-webrtc-sdp-20260125-213803.log |
| srtp_test | pass | SRTP/SRTCP + AES-GCM | /Users/dancer/me/logs/ocaml-webrtc-srtp-20260125-213821.log |
| rtp_test | pass | RTP encode/decode | /Users/dancer/me/logs/ocaml-webrtc-rtp-20260125-213840.log |
| rtcp_test | pass | RTCP SR/RR/SDES/BYE | /Users/dancer/me/logs/ocaml-webrtc-rtcp-20260125-213858.log |
| webrtc_crypto_test | pass | PRF/AEAD vectors | /Users/dancer/me/logs/ocaml-webrtc-crypto-20260125-213918.log |
| turn_rfc_test | pass | TURN unit tests | /Users/dancer/me/logs/ocaml-webrtc-turn-rfc-20260125-213936.log |

## Not Run (External Dependencies)

- `test/turn_relay_smoke.exe`: requires TURN server (`TURN_SERVER`, optional TLS CA)
- `examples/browser_media_smoke.exe`: requires public IP, cert/key, and a browser peer
- Pion/aiortc interop suites: not available in this local run

## TODO (Pending)

- TURN relay smoke
  - Required: `TURN_SERVER`, `TURN_USERNAME`, `TURN_PASSWORD`
  - Optional (TLS): `TURN_TLS_CA`
- Browser interop smoke
  - Required: public IP, `WEBRTC_CERT_PEM`, `WEBRTC_KEY_PEM`
  - Peer: Chrome/Firefox offer/answer

## Notes

- Logs are local-only paths and are not published.
- No benchmark results are recorded here. See `docs/PERFORMANCE-OPTIMIZATION.md` for policy.
