# ocaml-webrtc

[![Version](https://img.shields.io/badge/version-0.6.1-blue.svg)](https://github.com/jeong-sik/ocaml-webrtc)
[![OCaml](https://img.shields.io/badge/OCaml-5.x-orange.svg)](https://ocaml.org/)
[![Status](https://img.shields.io/badge/status-Beta-green.svg)]()
[![License](https://img.shields.io/badge/license-Private-red.svg)]()

**Pure OCaml implementation of WebRTC DataChannel protocol stack.**

No C bindings. Suitable for formal verification. Sans-IO architecture.

## v0.6.1 Status

| Component | Status | RFC | Notes |
|-----------|--------|-----|-------|
| STUN | ✅ Complete | RFC 5389 | Binding request/response, XOR-MAPPED-ADDRESS |
| ICE | ✅ Complete | RFC 8445 | Host + Server-reflexive candidates, connectivity checks |
| DTLS | ✅ Complete | RFC 6347 | Client/Server handshake, retransmission, cookie validation |
| SCTP | ✅ Complete | RFC 4960 | Full 4-way handshake, DATA/SACK, congestion control |
| DCEP | ✅ Complete | RFC 8832 | DATA_CHANNEL_OPEN/ACK, reliable/unreliable modes |
| TURN | 🚧 In Progress | RFC 5766 | Relay candidate gathering (turn/turns, long-term auth) |
| SDP | ✅ Basic | RFC 8866 | Candidate/credential encoding |

## Quick Start

```bash
# Install
opam pin add ocaml-webrtc git+ssh://git@github.com/jeong-sik/ocaml-webrtc.git#main -y

# Build
dune build

# Run examples
dune exec ./examples/stun_client.exe           # Discover public IP
dune exec ./examples/ice_gathering.exe         # Gather ICE candidates
dune exec ./examples/datachannel.exe           # Full stack demo
dune exec ./examples/dtls_echo.exe -- server 12345  # DTLS server

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
  | Error e -> Printf.eprintf "Error: %s\n" e
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

- [x] STUN client (RFC 5389)
- [x] ICE candidate gathering (RFC 8445)
- [x] ICE connectivity checks (RFC 8445)
- [x] DTLS 1.2 handshake (RFC 6347)
- [x] SCTP association (RFC 4960)
- [x] DCEP DataChannels (RFC 8832)
- [x] ICE-DTLS-SCTP integration
- [ ] TURN relay support (RFC 5766, full feature set)
- [ ] Peer-reflexive candidates
- [ ] ICE Trickle (RFC 8838)
- [ ] DTLS-SRTP for media (RFC 5764)

## Related Projects

- [masc-mcp](https://github.com/jeong-sik/masc-mcp) - Multi-agent coordination (may use WebRTC)
- [llm-mcp](https://github.com/jeong-sik/llm-mcp) - LLM orchestration

## License

Private - All rights reserved
