# ocaml-webrtc

Pure OCaml implementation of WebRTC protocol stack.

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
opam pin add ocaml-webrtc git+ssh://git@github.com/jeong-sik/ocaml-webrtc.git#main
```

## Usage

```ocaml
open Ocaml_webrtc

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

## License

Private - All rights reserved
