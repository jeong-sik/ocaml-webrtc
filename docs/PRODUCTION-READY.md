# Production Readiness Plan (Draft)

> ⚠️ Experimental project note  
> This document is a checklist-style plan, not a claim of production readiness.

Target: ocaml-webrtc 1.0 readiness for DataChannel + Media.
Priority: P0 -> P1 -> P2 in order.

Local verification logs (date-stamped): `docs/INTEROP-STATUS-2026-01-25.md`

## Readiness Definition
- Browser interop: Chrome/Firefox (DataChannel + basic media)
- NAT traversal: STUN/TURN (turn/turns) stable under loss/jitter
- Media path: DTLS-SRTP -> SRTP/SRTCP -> RTP/RTCP end-to-end
- CI signal: automated interop + critical RFC tests

## P0 - Must Have

### P0.1 Media End-to-End
- [x] DTLS-SRTP key export wired to SRTP/SRTCP contexts
- [x] Minimal RTP/RTCP send/receive pipeline (single SSRC)
- [x] Browser interop smoke (WebRTC peer vs OCaml): RTP/SRTP decrypt + RTCP RR/SDES
- [x] Example: `examples/media_loopback.ml` (documented)
- [x] Example: `examples/browser_media_smoke.ml` (Chrome offer/answer)

### P0.2 ICE/TURN Stability
- [x] ICE: peer-reflexive candidate support
- [x] ICE: restart flow + SDP attrs (ice-options/restart)
- [x] TURN: TLS path without blocking threads (timeout-safe)
- [x] TURN: permission/channel-bind basic flow test

## P1 - Quality Gate

### P1.1 Interop Matrix CI (env-gated)
- [ ] WebRTC interop (Chrome/Firefox) on CI runners
- [ ] TURN relay smoke (turn/turns) gated by env secrets
- [ ] Loss/jitter soak (10-30 min) with packet-loss simulation

### P1.2 RFC Test Coverage
- [ ] Expand `RFC-TEST-PLAN` for Media + ICE/SDP details
- [ ] Add missing negative tests (auth failures, bad tags, stale nonce)

## P2 - Operations & Release
- [ ] Metrics: key handshake/ICE/TURN failure counters
- [ ] Logging: structured logs with correlation IDs
- [ ] Security checklist: cert pinning option, auth secret rotation
- [ ] Release checklist + versioning guide

## Execution Order (first three)
1) P0.1: DTLS-SRTP -> SRTP/SRTCP wiring
2) P0.1: RTP/RTCP minimal pipeline + example
3) P0.2: TURN TLS non-blocking timeout safety
