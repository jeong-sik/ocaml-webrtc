# ocaml-webrtc

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/jeong-sik/ocaml-webrtc)
[![OCaml](https://img.shields.io/badge/OCaml-5.x-orange.svg)](https://ocaml.org/)
[![Status](https://img.shields.io/badge/status-Experimental-orange.svg)]()
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)

**Pure OCaml implementation of WebRTC DataChannel protocol stack.**

No C bindings. Suitable for formal verification. Sans-IO architecture.

> ⚠️ **Experimental project**  
> This is a research-grade implementation. APIs, behavior, and security properties are not stable.  
> **No official benchmarks yet.** Use at your own risk.

## v0.1.0 Status

### DataChannel Stack (Feature-complete, not production-ready)

| Component | Status | RFC | Notes |
|-----------|--------|-----|-------|
| STUN | ✅ Complete | RFC 5389/8489 | Binding request/response, MESSAGE-INTEGRITY, FINGERPRINT |
| ICE | ✅ Complete | RFC 8445 | Host + Server-reflexive candidates, connectivity checks |
| ICE Trickle | ✅ Complete | RFC 8838 | Callbacks, end-of-candidates, restart, SDP ice-options |
| DTLS | ✅ Complete | RFC 6347 | Client/Server handshake, retransmission, cookie validation |
| SCTP | ✅ Complete | RFC 4960 | Full 4-way handshake, DATA/SACK, congestion control |
| PR-SCTP | ✅ Complete | RFC 3758 | Partial reliability extension |
| RACK | ✅ Complete | RFC 8985 | Loss detection |
| DCEP | ✅ Complete | RFC 8832 | DATA_CHANNEL_OPEN/ACK, reliable/unreliable modes |
| SDP | ✅ Complete | RFC 4566/8866 | Parse + generate, ICE/DTLS attributes |
| TURN | 🚧 80% | RFC 5766 | Allocate/refresh/channel, TLS support (turns:) |

### Media Stack (In Progress)

| Component | Status | RFC | Notes |
|-----------|--------|-----|-------|
| RTP | 🚧 50% | RFC 3550 | Header encode/decode, CSRC, extension, padding |
| RTCP | 🚧 70% | RFC 3550 | SR/RR/SDES/BYE, compound packets, timing rules |
| SRTP | 🚧 60% | RFC 3711 | AES-CM + HMAC-SHA1 protect/unprotect |
| DTLS-SRTP | 🚧 80% | RFC 5764 | Key export, use_srtp extension, profile negotiation |
| SCTP Reconfig | 🚧 70% | RFC 6525 | RE-CONFIG request/response |

### Planned

| Component | RFC | Notes |
|-----------|-----|-------|
| RTCP Feedback | RFC 4585 | NACK, PLI, FIR |
| Opus Payload | RFC 7587 | Audio codec |
| VP8 Payload | RFC 7741 | Video codec |
| H.264 Payload | RFC 6184 | Video codec |

## Quick Start

```bash
# Install
opam pin add ocaml-webrtc git+https://github.com/jeong-sik/ocaml-webrtc.git#main -y

# Build
dune build

# Run examples
dune exec ./examples/stun_client.exe           # Discover public IP
dune exec ./examples/ice_gathering.exe         # Gather ICE candidates
dune exec ./examples/datachannel.exe           # Full stack demo
dune exec ./examples/dtls_echo.exe -- server 12345  # DTLS server
dune exec ./examples/media_loopback.exe -- server 12345  # DTLS-SRTP media server
dune exec ./examples/media_loopback.exe -- client 127.0.0.1 12345  # DTLS-SRTP media client
dune exec ./examples/browser_media_smoke.exe -- --public-ip 1.2.3.4 --listen-port 5004  # Browser interop (set WEBRTC_CERT_PEM/WEBRTC_KEY_PEM)

# TURN relay smoke (supports TURN_USERNAME / TURN_PASSWORD if set)
TURN_SERVER=127.0.0.1:3478 dune exec ./test/turn_relay_smoke.exe
# TURN over TLS (turns) - set CA if needed
TURN_SERVER=turns:turn.example.com:5349 TURN_TLS_CA=/etc/ssl/certs/ca-certificates.crt \
  dune exec ./test/turn_relay_smoke.exe
```

## Examples

### STUN Client - Discover Your Public IP
```ocaml
open Webrtc

let () =
  let request = Stun.create_binding_request () in
  (* Send to stun.l.google.com:19302, parse XOR-MAPPED-ADDRESS *)
  match Stun.decode response_bytes with
  | Ok response ->
    List.iter (fun attr ->
      match attr.Stun.value with
      | Stun.Xor_mapped_address addr ->
        Printf.printf "Public IP: %s:%d\n" addr.ip addr.port
      | _ -> ()
    ) response.attributes
  | Error e -> Log.error "Error: %s" e
```

### ICE Candidate Gathering
```ocaml
open Webrtc

let () =
  let config = Ice.default_config in
  let agent = Ice.create config in

  (* Get local credentials for SDP *)
  let (ufrag, pwd) = Ice.get_local_credentials agent in

  (* Set up trickle ICE callback *)
  Ice.on_candidate agent (fun candidate ->
    Printf.printf "New candidate: %s:%d (%s)\n"
      candidate.address candidate.port
      (Ice.string_of_candidate_type candidate.cand_type)
  );

  (* Gather candidates (host + srflx + relay) *)
  Lwt_main.run (Ice.gather_candidates_full agent);

  (* Get SDP-format candidate lines *)
  List.iter (fun c ->
    let sdp_cand = Sdp.ice_candidate_of_ice c in
    Printf.printf "a=%s\n" (Sdp.candidate_to_string sdp_cand)
  ) (Ice.get_local_candidates agent)
```

### Browser Media Interop (DTLS-SRTP)
```bash
# Self-signed cert (P-256)
openssl ecparam -name prime256v1 -genkey -noout -out key.pem
openssl req -new -x509 -key key.pem -out cert.pem -subj "/CN=ocaml-webrtc" -days 365

# Run server (paste browser offer SDP, then paste answer back)
WEBRTC_CERT_PEM="$(cat cert.pem)" WEBRTC_KEY_PEM="$(cat key.pem)" \
  dune exec ./examples/browser_media_smoke.exe -- --public-ip 1.2.3.4 --listen-port 5004
```

### Full WebRTC DataChannel
```ocaml
open Webrtc

let () =
  (* Create ICE-DTLS-SCTP transport *)
  let config = {
    Ice_dtls_transport.default_config with
    is_controlling = true;
    ice_servers = [];
  } in
  let transport = Ice_dtls_transport.create ~config () in

  (* Set up callbacks *)
  Ice_dtls_transport.on_channel_open transport (fun sid label ->
    Printf.printf "Channel opened: [%d] %s\n" sid label
  );

  Ice_dtls_transport.on_channel_data transport (fun sid data ->
    Printf.printf "Received: %s\n" (Bytes.to_string data)
  );

  (* Create DataChannel via DCEP *)
  let dcep = Dcep.create ~is_client:true in
  let (stream_id, open_msg) = Dcep.open_channel dcep
    ~label:"chat" ~protocol:"" () in
  Printf.printf "Created channel on stream %d\n" stream_id
```

### DTLS-SRTP Media Loopback
```ocaml
open Webrtc

let profile = Srtp.SRTP_AES128_CM_HMAC_SHA1_80

let () =
  let (local_keys, remote_keys) =
    match Dtls_srtp.session_keys_of_dtls ~dtls ~role:Dtls_srtp.Client ~profile () with
    | Ok keys -> keys
    | Error e -> failwith e
  in
  let media = Media_transport.create
    ~profile
    ~local_keys
    ~remote_keys
    ~ssrc:0x11223344l
    ~payload_type:111
  in
  let payload = Bytes.of_string "hello-media" in
  match Media_transport.protect_rtp media ~timestamp:0l ~payload () with
  | Ok packet -> ignore packet
  | Error e -> Log.error "SRTP error: %s" e
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              Application (Your Code)                │
├─────────────────────────────────────────────────────┤
│     DCEP (Data Channel Establishment Protocol)      │
│         RFC 8832 - DATA_CHANNEL_OPEN/ACK            │
├─────────────────────────────────────────────────────┤
│          SCTP (Reliable Message Transport)          │
│     RFC 4960 - INIT/INIT-ACK/COOKIE/DATA/SACK       │
├─────────────────────────────────────────────────────┤
│            DTLS 1.2 (Encryption Layer)              │
│   RFC 6347 - ClientHello/ServerHello/Finished       │
├─────────────────────────────────────────────────────┤
│         ICE (NAT Traversal & Connectivity)          │
│   RFC 8445 - Candidate Gathering & Connectivity     │
├─────────────────────────────────────────────────────┤
│               STUN/TURN (Discovery)                 │
│         RFC 5389/5766 - Address Discovery           │
├─────────────────────────────────────────────────────┤
│                      UDP                            │
└─────────────────────────────────────────────────────┘
```

## Module Overview

| Module | Lines | Description |
|--------|-------|-------------|
| `Ice` | 1182 | ICE agent, candidate gathering, connectivity checks |
| `Ice_check` | 372 | Sans-IO connectivity check state machine |
| `Dtls` | 1728 | DTLS 1.2 handshake, encryption/decryption |
| `Sctp` | 585 | SCTP packet encoding/decoding |
| `Sctp_core` | 824 | SCTP association state machine |
| `Dcep` | 310 | DataChannel establishment protocol |
| `Stun` | 793 | STUN message encoding/decoding |
| `Ice_dtls_transport` | 574 | Full stack integration |

## Sans-IO Design

This library follows the [Sans-IO](https://sans-io.readthedocs.io/) pattern:

```ocaml
(* State machine returns output commands, not side effects *)
type input = Start_check | Stun_response_received of ... | Timer_fired
type output = Send_stun_request of ... | Set_timer of ... | Check_completed of ...

let step (state : t) (input : input) : t * output = ...
```

Benefits:
- **Testable**: No mocking needed, just call `step` with test inputs
- **Portable**: Works with Lwt, Eio, or blocking I/O
- **Verifiable**: Pure functions suitable for formal verification

## Testing

```bash
# Run all tests (62 test files)
dune runtest

# Run specific tests
dune exec ./test/dtls_handshake_test.exe   # 16 tests
dune exec ./test/sctp_core_handshake_test.exe  # 9 tests
```

## Benchmarks

- Not published yet (experimental only).

## Compliance

- `docs/RFC-COMPLIANCE.md` - RFC coverage matrix and gap tracking
- `docs/RFC-TEST-PLAN.md` - RFC test expansion plan (DataChannel + Media)

## Dependencies

- `lwt` / `eio` - Async I/O
- `mirage-crypto` - Cryptography primitives
- `x509` - Certificate handling
- `tls` / `ptime` - TURN TLS verification
- `cstruct` - Binary data parsing
- `digestif` - Hash functions (CRC32c for SCTP)

## Roadmap

### ✅ Completed
- [x] STUN client (RFC 5389/8489)
- [x] ICE candidate gathering (RFC 8445)
- [x] ICE connectivity checks (RFC 8445)
- [x] ICE Trickle (RFC 8838)
- [x] DTLS 1.2 handshake (RFC 6347)
- [x] SCTP association (RFC 4960)
- [x] PR-SCTP partial reliability (RFC 3758)
- [x] RACK loss detection (RFC 8985)
- [x] DCEP DataChannels (RFC 8832)
- [x] ICE-DTLS-SCTP integration
- [x] SDP parse/generate (RFC 4566/8866)

### 🚧 In Progress
- [ ] TURN relay full support (RFC 5766) - 80%
- [ ] DTLS-SRTP key export (RFC 5764) - 50%
- [ ] SRTP protect/unprotect (RFC 3711) - 60%
- [ ] SCTP stream reconfig (RFC 6525) - 70%
- [ ] RTP/RTCP full (RFC 3550) - 40%

### 📋 Planned
- [ ] RTCP feedback NACK/PLI/FIR (RFC 4585)
- [ ] Opus RTP payload (RFC 7587)
- [ ] VP8/VP9 RTP payload (RFC 7741/7742)
- [ ] H.264 RTP payload (RFC 6184)
- [ ] Peer-reflexive candidates
- [ ] Full SDP Offer/Answer (RFC 3264)

## Related Projects

- [masc-mcp](https://github.com/jeong-sik/masc-mcp) - Multi-agent coordination (may use WebRTC)
- [llm-mcp](https://github.com/jeong-sik/llm-mcp) - LLM orchestration

## License

Apache-2.0
