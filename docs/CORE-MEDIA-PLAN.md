# Core Media Plan (Phase 2: RTP/RTCP + SRTP/DTLS-SRTP)

This document defines the core WebRTC media plan for ocaml-webrtc, focusing on
RTP/RTCP and SRTP/DTLS-SRTP integration. Codec work is delegated to the external
media worker (FFmpeg) defined in `MEDIA-WORKER-INTERFACE.md`.

## Scope (Phase 2A: Audio-Only)

- RTP/RTCP transport for audio
- SRTP + SRTCP protection
- DTLS-SRTP keying (RFC 5764)
- Minimal PeerConnection media surface
- Opus payloads via media worker (PCM <-> Opus)

Out of scope:
- Video pipeline (VP8/H264)
- Advanced congestion control (GCC/TFRC)
- Full WebRTC data stats parity

## Architecture

```
Mic/PCM
  -> Media Worker (FFmpeg Opus)
  -> RTP packetize
  -> SRTP protect
  -> ICE/DTLS transport
  -> Network
  -> SRTP unprotect
  -> RTP depacketize
  -> Media Worker decode
  -> PCM to app
```

Core owns network + SRTP + RTP/RTCP; worker owns codec only.

## Modules (Planned)

- `rtp.ml`: RTP header encode/decode, sequence, timestamp
- `rtcp.ml`: RTCP packet encode/decode (SR/RR, SDES, BYE)
- `rtcp_fb.ml`: RTCP feedback (NACK for audio loss recovery)
- `srtp.ml`: SRTP/SRTCP crypto (AES-CTR + HMAC-SHA1 or AES-GCM)
- `dtls_srtp.ml`: derive SRTP keys from DTLS (RFC 5764)
- `jitter_buffer.ml`: reorder + playout delay
- `media_track.ml`: audio track, clock, stats
- `peer_media.ml`: glue between PeerConnection and tracks

## RTP Details (Audio)

- Payload type: 111 (default for Opus)
- Clock rate: 48000
- Frame size: 20 ms (960 samples)
- SSRC: random per track
- Sequence: 16-bit, wrap
- Timestamp: sample-based, +960 per 20 ms frame

## RTCP Minimal Set

- Sender Report (SR) for outbound audio
- Receiver Report (RR) for inbound audio
- RTCP compound packets (SR/RR + SDES)
- RTCP interval scheduling (RFC 3550)

Phase 2B:
- NACK (RFC 4585) for packet loss recovery
- Extended stats (jitter, RTT, loss)

## SRTP/DTLS-SRTP

- DTLS handshake already in `dtls.ml`
- Use DTLS-SRTP exporter to derive keys
- Support profiles:
  - `SRTP_AES128_CM_HMAC_SHA1_80` (phase 2A)
  - `SRTP_AES128_CM_HMAC_SHA1_32` (phase 2B)
- SRTCP for RTCP protection

## Jitter and Playout

- Initial playout delay: 60-120 ms
- Simple jitter buffer: reorder by sequence, fill missing with silence
- Drift correction: adjust playout delay based on RTCP jitter

## PeerConnection Surface (Minimal)

- `add_audio_track` / `on_audio_track`
- `set_remote_description` / `create_offer` / `create_answer`
- ICE/DTLS state events (existing)
- Media state: `connecting` -> `established`

## Interop Targets

Phase 2A:
- Chrome audio-only call (Opus)
- Firefox audio-only call (Opus)

Phase 2B:
- Pion audio interop (Opus)
- aiortc audio interop (Opus)

## Testing Plan

- Unit: RTP/RTCP encode/decode roundtrips
- Unit: SRTP protect/unprotect with test vectors
- Integration: loopback RTP -> SRTP -> RTP
- Interop: Chrome/Firefox call scripts with known SDP

## Milestones

1) RTP/RTCP skeleton + tests
2) SRTP/SRTCP crypto + DTLS keying
3) Jitter buffer + playout
4) Media worker wiring
5) Chrome/Firefox interop

## Decisions Needed

- AES-GCM support in phase 2A or 2B
- RTCP feedback scope (NACK only vs include PLI/REMB for video later)
