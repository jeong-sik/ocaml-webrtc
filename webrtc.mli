(** OCaml WebRTC - Pure OCaml WebRTC Implementation

    Top-level module re-exporting the full WebRTC protocol stack.

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

(** {1 Protocol Modules} *)

module Stun = Stun
module Turn = Turn
module Ice = Ice
module Ice_check = Ice_check
module Dtls = Dtls
module Sctp = Sctp
module Sdp = Sdp
module Rtp = Rtp
module Rtcp = Rtcp
module Srtp = Srtp
module Dtls_srtp = Dtls_srtp
module Media_transport = Media_transport
module Ecdhe = Ecdhe
module Webrtc_crypto = Webrtc_crypto

(** {1 Transport Layers} *)

module Udp_transport = Udp_transport
module Sctp_transport = Sctp_transport

(** {1 Reliable Transport} *)

module Sctp_reliable = Sctp_reliable
module Sctp_full_transport = Sctp_full_transport

(** {1 High-Performance Data Structures} *)

module Sctp_ring_buffer = Sctp_ring_buffer
module Buffer_pool = Buffer_pool

(** {1 Sans-IO SCTP Architecture} *)

module Sctp_core = Sctp_core
module Sctp_eio = Sctp_eio
module Sctp_rack = Sctp_rack
module Sctp_bundling = Sctp_bundling
module Sctp_handshake = Sctp_handshake
module Sctp_heartbeat = Sctp_heartbeat
module Sctp_error = Sctp_error
module Sctp_reconfig = Sctp_reconfig

(** {1 Advanced Features} *)

module Sctp_pr = Sctp_pr

(** {1 WebRTC DataChannel} *)

module Dcep = Dcep
module Dtls_sctp_transport = Dtls_sctp_transport

(** {1 Eio-native Async Transport} *)

module Eio_udp_transport = Eio_udp_transport
module Eio_sctp_full_transport = Eio_sctp_full_transport

(** {1 Eio Full Stack} *)

module Ice_eio = Ice_eio
module Dtls_eio = Dtls_eio
module Webrtc_eio = Webrtc_eio
module Time_compat = Time_compat

(** {1 Functor-based Transport} *)

module Transport_intf = Transport_intf
module Dtls_functor = Dtls_functor

(** {1 Error Classification} *)

module Oas_error = Oas_error

(** {1 Version Info} *)

val version : string
val user_agent : string
