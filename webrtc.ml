(** OCaml WebRTC - Pure OCaml 5.x implementation of WebRTC protocols

    This library provides a complete WebRTC stack for OCaml applications,
    enabling peer-to-peer communication in browsers and native applications.

    Uses OCaml 5.x Effect Handlers for clean async I/O abstraction.

    {1 Modules}

    - {!module:Stun} - RFC 5389: Session Traversal Utilities for NAT
    - {!module:Turn} - RFC 5766: Traversal Using Relays around NAT
    - {!module:Ice} - RFC 8445: Interactive Connectivity Establishment
    - {!module:Dtls} - RFC 6347: Datagram Transport Layer Security 1.2
    - {!module:Sctp} - RFC 4960: Stream Control Transmission Protocol
    - {!module:Sdp} - RFC 4566: Session Description Protocol

    {1 Quick Start}

    {[
      (* Create ICE agent *)
      let agent = Ice.create Ice.default_config in

      (* Gather candidates *)
      Ice.gather_candidates agent;

      (* Create SDP offer for DataChannel *)
      let offer = Sdp.create_datachannel_offer
        ~ice_ufrag:"abcd" ~ice_pwd:"xyz..."
        ~fingerprint:{ hash_func = "sha-256"; fingerprint = "..." }
        ~sctp_port:5000
      in

      (* Exchange SDP with peer... *)

      (* DTLS handshake *)
      let dtls = Dtls.create Dtls.default_client_config in
      let records = Dtls.start_handshake dtls in

      (* Send data via SCTP *)
      let assoc = Sctp.create Sctp.default_config in
      Sctp.establish assoc;
    ]}

    @author Second Brain
    @version 0.2.0
*)

(** Re-export core modules *)

module Stun = Stun
module Turn = Turn
module Ice = Ice
module Ice_check = Ice_check  (** RFC 8445 ICE Connectivity Checks (Sans-IO) *)
module Dtls = Dtls
module Dtls_srtp = Dtls_srtp
module Sctp = Sctp
module Sdp = Sdp
module Rtp = Rtp
module Rtcp = Rtcp
module Srtp = Srtp
module Ecdhe = Ecdhe  (** RFC 8422 ECDHE key exchange *)
module Webrtc_crypto = Webrtc_crypto  (** TLS 1.2 PRF and AES-GCM *)

(** {1 Transport Layers} *)

module Udp_transport = Udp_transport  (** Real UDP socket I/O *)
module Sctp_transport = Sctp_transport  (** SCTP over UDP with real network I/O *)
module Ice_dtls_transport = Ice_dtls_transport  (** Full ICE + DTLS + SCTP WebRTC stack *)

(** {1 Reliable Transport (Full SCTP State Machine)} *)

module Sctp_reliable = Sctp_reliable  (** SACK, cwnd, retransmission *)
module Sctp_full_transport = Sctp_full_transport  (** Complete reliable SCTP transport *)

(** {1 High-Performance Data Structures} *)

module Sctp_ring_buffer = Sctp_ring_buffer  (** Zero-alloc ring buffer for SCTP queue *)
module Buffer_pool = Buffer_pool  (** Pre-allocated buffer pool for packet processing *)

(** {1 Sans-IO SCTP Architecture (Phase 3)} *)

module Sctp_core = Sctp_core  (** Pure SCTP state machine (no I/O) *)
module Sctp_eio = Sctp_eio  (** Eio I/O adapter for Sctp_core *)
module Sctp_rack = Sctp_rack  (** RFC 8985 RACK loss detection *)
module Sctp_bundling = Sctp_bundling  (** RFC 4960 §6.10 Chunk bundling *)
module Sctp_handshake = Sctp_handshake  (** RFC 4960 §5 4-Way handshake *)
module Sctp_heartbeat = Sctp_heartbeat  (** RFC 4960 §8.3 Path heartbeat *)
module Sctp_error = Sctp_error  (** RFC 4960 §3.2, §3.3.10 Unknown chunk handling and ERROR chunk *)

(** {1 Advanced Features (Phase 4)} *)

module Sctp_pr = Sctp_pr  (** RFC 3758 PR-SCTP Partial Reliability *)

(** {1 WebRTC DataChannel (Phase 5)} *)

module Dcep = Dcep  (** RFC 8832 DataChannel Establishment Protocol *)
module Dtls_sctp_transport = Dtls_sctp_transport  (** DTLS-encrypted SCTP transport *)

(** {1 Eio-native Async Transport (OCaml 5 Effects)} *)

module Eio_udp_transport = Eio_udp_transport  (** True async UDP with Eio *)
module Eio_sctp_full_transport = Eio_sctp_full_transport  (** Concurrent SCTP with fibers *)

(** {1 Eio Full Stack (v0.6.0)} *)

module Ice_eio = Ice_eio  (** Eio-based ICE agent with fibers *)
module Dtls_eio = Dtls_eio  (** Eio-based DTLS with timer management *)
module Webrtc_eio = Webrtc_eio  (** Full WebRTC stack with Eio integration *)

(** {1 Functor-based Transport (v0.6.0)} *)

module Transport_intf = Transport_intf  (** Swappable transport interface *)
module Dtls_functor = Dtls_functor  (** DTLS with functor-based transport *)

(** Library version *)
let version = "0.6.0"

(** Library name for User-Agent headers *)
let user_agent = "ocaml-webrtc/" ^ version
