# Media Worker Interface (FFmpeg, Phase 1: Audio-Only)

This document defines the interface between the pure OCaml WebRTC core
(ICE/DTLS/SRTP/RTP/RTCP/SDP/PeerConnection) and an external media worker
process that performs codec operations. The goal is to keep the core pure
OCaml while delegating codec complexity to a specialized worker (FFmpeg
first, GStreamer later) using a stable IPC contract.

## Goals

- Keep the WebRTC core pure OCaml and deterministic.
- Isolate codecs in an external worker (FFmpeg).
- Use a minimal, stable IPC protocol that can be reused by other backends.
- Start with audio-only (Opus) and expand to audio+video later.

## Non-Goals (Phase 1)

- Implement media codecs in OCaml.
- Provide a full video pipeline (VP8/H264) in phase 1.
- Handle network I/O or SRTP inside the worker.

## Architecture Overview

Core (OCaml):
- ICE/DTLS/SRTP, RTP/RTCP, SDP/JSEP, PeerConnection
- Jitter/packet scheduling, RTCP feedback
- RTP packetization/depacketization

Worker (External process):
- Encode PCM -> Opus frames
- Decode Opus frames -> PCM
- No SRTP, no network I/O

RTP/RTCP ownership stays in the core. The worker handles codec payloads only.

## Process Model

- One worker process per PeerConnection (phase 1).
- The core spawns the worker and owns its lifetime.
- The worker communicates over stdin/stdout using a framed binary protocol.
- The worker MUST NOT open network sockets.

## IPC Protocol

Transport:
- stdin (core -> worker) and stdout (worker -> core)
- Framed binary messages
- Big-endian for all integers

Frame Header (fixed-size):

```
struct Frame {
  u8  kind;        // 1=CONTROL, 2=PCM, 3=ENCODED
  u8  flags;       // reserved, must be 0
  u16 reserved;    // must be 0
  u32 stream_id;   // 0 = audio (phase 1)
  u64 timestamp;   // RTP timestamp units (sample-rate based)
  u32 length;      // payload length
  u8  payload[length];
}
```

Notes:
- `timestamp` is in RTP ticks (e.g., 48 kHz for Opus).
- For CONTROL frames, `timestamp` MUST be 0.

### CONTROL Frames (JSON)

Payload: UTF-8 JSON (single object).

Required handshake:
1. Worker -> Core: `hello`
2. Core -> Worker: `configure`
3. Worker -> Core: `ready`

Examples:

```
{"type":"hello","version":1,"backend":"ffmpeg","capabilities":["opus"]}
{"type":"configure","stream_id":0,"codec":"opus","sample_rate":48000,"channels":1,"frame_ms":20,"bitrate_bps":24000}
{"type":"ready","stream_id":0}
```

Optional control messages:

```
{"type":"stats","stream_id":0,"encoded_frames":1234,"dropped_frames":0}
{"type":"error","code":"EENCODE","message":"ffmpeg error detail"}
{"type":"close","stream_id":0}
```

## DATA Frames

### PCM Frame (core -> worker)

`kind = 2`

Payload:
- Raw PCM (s16le)
- Sample rate + channels defined in `configure`

Timestamp:
- RTP timestamp in sample ticks
- Example: 20 ms at 48 kHz => +960 per frame

### ENCODED Frame (worker -> core)

`kind = 3`

Payload:
- One Opus frame (no RTP header)

Timestamp:
- Same RTP timestamp as the input PCM frame

## Audio-Only Defaults (Phase 1)

- Codec: Opus
- Sample rate: 48000
- Channels: 1 (mono)
- Frame duration: 20 ms
- Bitrate: 24 kbps (configurable)
- RTP payload type: 111 (core-defined)

## RTP/RTCP Responsibilities

Core:
- Builds RTP headers and sequences
- Applies SRTP protection
- Sends/receives RTCP, handles feedback
- Runs jitter buffer and playout scheduling

Worker:
- Codec-only transformations
- No RTP/RTCP, no SRTP, no network I/O

## Error Handling

- Worker sends `error` control frames and exits with non-zero status on fatal errors.
- Core treats worker exit as track failure and triggers reconnection or stream teardown.

## Future Extensions

Phase 2 (Audio+Video):
- Add codec: VP8 or H264
- Multiple `stream_id` values (audio=0, video=1)
- Add video frame format descriptors (width/height, pix_fmt)

Phase 3 (GStreamer backend):
- Keep the same IPC protocol
- Swap worker backend without changing the core

## Interop Targets

- Phase 1: Chrome/Firefox audio-only calls
- Phase 2: Chrome/Firefox audio+video
- Phase 3: Server-to-server interop (Pion/aiortc)
