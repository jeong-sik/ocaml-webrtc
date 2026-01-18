# OCaml SCTP Implementation

> RFC 4960 compliant SCTP implementation for WebRTC data channels

## Features

- **RFC 4960** - Full SCTP base protocol compliance
- **RFC 8985** - RACK time-based loss detection
- **RFC 3758** - PR-SCTP partial reliability
- **Sans-IO** - Pure state machine architecture (str0m-inspired)
- **Hardware CRC32c** - ARM64/x86 SIMD acceleration
- **OCaml 5.x Multicore** - Domain-parallel packet processing

## Quick Start

```ocaml
open Webrtc

(* Create transport *)
let transport = Eio_sctp_full_transport.create
  ~host:"127.0.0.1"
  ~port:5000
  ()

(* Connect to peer *)
Eio_sctp_full_transport.connect transport
  ~host:"127.0.0.1"
  ~port:5001

(* Send data *)
let data = Bytes.of_string "Hello SCTP!" in
Eio_sctp_full_transport.send_data transport
  ~stream_id:0
  ~data

(* Receive data *)
match Eio_sctp_full_transport.recv_data transport with
| Some { stream_id; data } ->
  Printf.printf "Received on stream %d: %s\n" stream_id (Bytes.to_string data)
| None -> ()

(* Cleanup *)
Eio_sctp_full_transport.close transport
```

## Architecture

```
┌─────────────────────────────────────────┐
│           Application Layer             │
├─────────────────────────────────────────┤
│  Eio_sctp_full_transport (High-level)   │  ← Use this
├─────────────────────────────────────────┤
│         Sctp_core (Sans-IO)             │  ← Pure state machine
│  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │ State   │ │ Encode  │ │ Decode  │   │
│  │ Machine │ │ Output  │ │ Input   │   │
│  └─────────┘ └─────────┘ └─────────┘   │
├─────────────────────────────────────────┤
│          Udp_transport (I/O)            │  ← Side effects
└─────────────────────────────────────────┘
```

## Performance

| Metric | Value |
|--------|-------|
| Throughput (honest) | ~59 MB/s |
| Delivery ratio | 100% |
| Bundling ratio | 5.9x |
| Multicore (8 domains) | 47 GB/s |

See [PERFORMANCE-OPTIMIZATION.md](PERFORMANCE-OPTIMIZATION.md) for details.

## RFC Compliance

```
RFC 4960 §3.3 - Chunk Encoding ✅
RFC 4960 §3.3.4 - SACK ✅
RFC 4960 §5 - 4-Way Handshake ✅
RFC 4960 §7.2 - Congestion Control ✅
RFC 8985 - RACK Algorithm ✅
RFC 3758 - PR-SCTP ✅
```

Run compliance tests: `dune exec ./test/rfc_compliance_test.exe`

## Modules

| Module | Description |
|--------|-------------|
| `Sctp` | Chunk encoding/decoding |
| `Sctp_core` | Sans-IO state machine |
| `Sctp_reliable` | Reliability layer (SACK, TSN) |
| `Sctp_rack` | RACK loss detection |
| `Sctp_bundling` | Chunk bundling |
| `Eio_sctp_full_transport` | High-level Eio transport |

## Documentation

- [API Reference](API.md)
- [Performance Optimization](PERFORMANCE-OPTIMIZATION.md)

## License

MIT
