# RFC Compliance Matrix

Scope: ocaml-webrtc DataChannel + Media (audio + video). This tracks RFC
coverage and links to current code/tests. It is not a certification; it is a
gap tracker to reach 100% compliance.

Status legend:
- implemented: code exists and basic tests cover core behavior
- partial: code exists but major sections or tests are missing
- planned: not implemented yet
- out-of-scope: explicitly excluded (requires decision)

## Core transport and crypto

| RFC | Area | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| 6347 | DTLS 1.2 | implemented | `dtls.ml`, `test/dtls_handshake_test.ml` | handshake, retransmission, cookie validation |
| 8422 | ECDHE P-256 | implemented | `ecdhe.ml`, `test/integration_test.ml` | named curve P-256 only |
| 5246 | TLS 1.2 PRF | implemented | `webrtc_crypto.ml`, `test/webrtc_crypto_test.ml` | DTLS key schedule |
| 5288 | AES-GCM | implemented | `webrtc_crypto.ml`, `test/webrtc_crypto_test.ml` | DTLS record protection |
| 5705 | Key exporter | implemented | `dtls.ml` | PRF exporter with optional context |
| 5764 | DTLS-SRTP | partial | `dtls_srtp.ml`, `dtls.ml`, `test/dtls_srtp_test.ml` | exporter + key split, no use_srtp ext yet |
| 7983 | STUN/DTLS demux | implemented | `ice_dtls_sctp_transport.ml` | first-byte demux |

## STUN / TURN / ICE

| RFC | Area | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| 5389 | STUN | implemented | `stun.ml`, `test/integration_test.ml` | binding request/response, integrity |
| 8489 | STUN update | partial | `stun.mli` | not fully audited vs updated spec |
| 8445 | ICE | implemented | `ice.ml`, `ice_check.ml`, `test/ice_check_test.ml` | host + srflx, connectivity checks |
| 8838 | Trickle ICE | implemented | `ice.ml`, `test/ice_trickle_test.ml` | callbacks + end-of-candidates + restart + SDP ice-options |
| 5766 | TURN | partial | `turn.ml`, `test/turn_rfc_test.ml`, `test/turn_relay_smoke.ml` | client allocate/refresh/channel, relay via `gather_candidates_full` (long-term auth + turns/TLS supported) |
| 6156 | TURN IPv6 | partial | `turn.mli` | extension noted, not verified |
| 5245 | ICE SDP attrs | partial | `sdp.ml`, `test/sdp_test.ml` | ice-options + end-of-candidates + candidate conversion |
| 8839 | ICE SDP update | partial | `sdp.mli` | not fully audited |

## SCTP / DataChannel

| RFC | Area | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| 4960 | SCTP base | implemented | `sctp_core.ml`, `sctp_reliable.ml`, `test/rfc_compliance_test.ml` | 4-way handshake, SACK, CC |
| 3758 | PR-SCTP | implemented | `sctp_pr.ml`, `test/rfc_compliance_test.ml` | partial reliability |
| 8985 | RACK | implemented | `sctp_rack.ml`, `test/sctp_rack_test.ml` | loss detection |
| 6525 | Stream reconfig | partial | `sctp_reconfig.ml`, `sctp_core.ml`, `test/sctp_reconfig_test.ml` | RE-CONFIG reset request/response, no full stream state |
| 8261 | SCTP over DTLS | partial | `dtls_sctp_transport.ml` | integration exists, not fully audited |
| 8831 | DataChannel protocol | partial | `sctp.ml`, `dcep.ml` | PPIDs + basics, reconfig not wired |
| 8832 | DCEP | partial | `dcep.ml`, `test/dcep_test.ml` | encoding/decoding + lifecycle tests |

## SDP / Offer-Answer

| RFC | Area | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| 4566 | SDP core | implemented | `sdp.ml`, `test/sdp_test.ml` | parse + generate |
| 8866 | SDP update | partial | `sdp.mli` | not fully audited |
| 3264 | Offer/Answer | partial | `sdp.ml`, `test/sdp_test.ml` | minimal helpers only |
| 8841 | SCTP SDP | partial | `sdp.ml` | sctpmap / sctp-port only |
| 8832 | DataChannel SDP | partial | `sdp.ml` | max-message-size, basic attrs |

## Media (RTP / RTCP / SRTP)

| RFC | Area | Status | Evidence | Notes |
| --- | --- | --- | --- | --- |
| 3550 | RTP/RTCP | partial | `rtp.ml`, `rtcp.ml`, `test/rtp_test.ml`, `test/rtcp_test.ml` | minimal encode/decode only |
| 3551 | RTP profile | partial | `rtp.ml`, `rtcp.ml`, `test/rtcp_test.ml` | payload profiles not validated |
| 7587 | Opus RTP payload | planned | `docs/CORE-MEDIA-PLAN.md` | Opus payload formatting |
| 3711 | SRTP | partial | `srtp.ml`, `test/srtp_test.ml` | AES-CM + HMAC-SHA1 + SRTP/SRTCP protect |
| 4585 | RTCP feedback | planned | `docs/CORE-MEDIA-PLAN.md` | NACK planned |
| 5764 | DTLS-SRTP | partial | `dtls.mli` | key export only |
| 6184 | H.264 RTP payload | planned | `docs/CORE-MEDIA-PLAN.md` | video payload format |
| 7741 | VP8 RTP payload | planned | `docs/CORE-MEDIA-PLAN.md` | video payload format |
| 7742 | VP9 RTP payload | planned | `docs/CORE-MEDIA-PLAN.md` | video payload format |

## Top gaps to reach 100%

- SRTP/SRTCP + DTLS-SRTP full media pipeline
- RTP/RTCP full RFC 3550/3551 behavior and feedback (RFC 4585)
- RTP payload formats (Opus, VP8, VP9, H.264)
- SCTP stream reconfiguration (RFC 6525) full state machine + stream reset handling
- Full SDP Offer/Answer semantics for media (audio/video)

See `docs/RFC-TEST-PLAN.md` for the test expansion plan.
