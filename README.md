# ocaml-webrtc

[![Version](https://img.shields.io/badge/version-0.1.0-blue.svg)](https://github.com/jeong-sik/ocaml-webrtc)
[![OCaml](https://img.shields.io/badge/OCaml-5.x-orange.svg)](https://ocaml.org/)
[![Status](https://img.shields.io/badge/status-Alpha-yellow.svg)]()
[![License](https://img.shields.io/badge/license-Private-red.svg)]()

Pure OCaml implementation of WebRTC protocol stack.

## Status

| Component | Status | RFC |
|-----------|--------|-----|
| STUN | ✅ Complete | RFC 5389 |
| TURN | ✅ Complete | RFC 5766 |
| ICE | 🚧 In Progress | RFC 8445 |
| DTLS | 🚧 In Progress | RFC 6347 |
| SCTP | 📋 Planned | RFC 4960 |
| DCEP | 📋 Planned | RFC 8832 |
| SDP | ✅ Basic | RFC 8866 |

**Current Phase**: Alpha - Core protocols implemented, integration testing in progress.

## Features

- **DTLS**: Datagram Transport Layer Security
- **SCTP**: Stream Control Transmission Protocol
- **ICE**: Interactive Connectivity Establishment
- **STUN**: Session Traversal Utilities for NAT
- **TURN**: Traversal Using Relays around NAT
- **SDP**: Session Description Protocol
- **DCEP**: Data Channel Establishment Protocol

## Installation

```bash
# From GitHub (recommended)
opam pin add ocaml-webrtc git+ssh://git@github.com/jeong-sik/ocaml-webrtc.git#main -y

# Or local development
opam pin add ocaml-webrtc . -y
```

## Usage

```ocaml
open Webrtc

(* Create ICE agent *)
let agent = Ice.create_agent ~stun_servers:["stun.l.google.com:19302"] ()

(* Create data channel *)
let channel = Dcep.create_data_channel ~label:"chat" ~reliable:true ()

(* STUN binding request *)
let request = Stun.create_binding_request ()
```

## Architecture

```
┌─────────────────────────────────────────┐
│           WebRTC Application            │
├─────────────────────────────────────────┤
│    Data Channels (DCEP)  │  Media       │
├──────────────────────────┼──────────────┤
│         SCTP             │   SRTP       │
├──────────────────────────┴──────────────┤
│                 DTLS                    │
├─────────────────────────────────────────┤
│         ICE (STUN/TURN)                 │
├─────────────────────────────────────────┤
│              UDP/TCP                    │
└─────────────────────────────────────────┘
```

## Dependencies

- eio (for async I/O)
- mirage-crypto (cryptography)
- x509 (certificates)
- cstruct (binary parsing)

## Related Projects

- [masc-mcp](https://github.com/jeong-sik/masc-mcp) - May use WebRTC for distributed agent coordination

## License

Private - All rights reserved
