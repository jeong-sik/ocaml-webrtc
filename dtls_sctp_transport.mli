(** DTLS-SCTP Transport - Encrypted SCTP for WebRTC DataChannels

    WebRTC DataChannel stack:
    {v
    ┌─────────────────────────────────────────┐
    │           Application (DataChannel)     │
    ├─────────────────────────────────────────┤
    │           DCEP (Channel Setup)          │
    ├─────────────────────────────────────────┤
    │           SCTP (Reliable Transport)     │
    ├─────────────────────────────────────────┤
    │     >>>  DTLS (Encryption)  <<<         │  ← This module
    ├─────────────────────────────────────────┤
    │           ICE (NAT Traversal)           │
    ├─────────────────────────────────────────┤
    │           UDP (Network)                 │
    └─────────────────────────────────────────┘
    v}

    DTLS 1.2 (RFC 6347) encrypts SCTP packets before UDP transmission.
    Uses TLS 1.2 crypto primitives (AES-GCM, ECDHE, SHA-256).

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

type dtls_state =
  | Disconnected
  | Handshaking
  | Connected
  | Closed
  | Error of string

type config =
  { mtu : int
  ; sctp_port : int
  ; fingerprint : string
  ; is_client : bool
  }

val default_config : config

type t =
  { config : config
  ; dtls : Dtls.t
  ; sctp : Sctp_core.t
  ; dcep : Dcep.t
  ; udp : Udp_transport.t
  ; mutable state : dtls_state
  ; recv_buffer : bytes
  ; mutable on_channel_open : (int -> string -> unit) option
  ; mutable on_channel_data : (int -> bytes -> unit) option
  ; mutable on_channel_close : (int -> unit) option
  ; mutable on_connected : (unit -> unit) option
  ; mutable on_error : (string -> unit) option
  }

val create : ?config:config -> host:string -> port:int -> unit -> t
val on_channel_open : t -> (int -> string -> unit) -> unit
val on_channel_data : t -> (int -> bytes -> unit) -> unit
val on_channel_close : t -> (int -> unit) -> unit
val on_connected : t -> (unit -> unit) -> unit
val on_error : t -> (string -> unit) -> unit
val send_records : t -> bytes list -> unit
val start_handshake : t -> remote_host:string -> remote_port:int -> unit
val process_dtls_record : t -> bytes -> unit
val process_sctp_packet : t -> bytes -> unit
val process_sctp_outputs : t -> Sctp_core.output list -> unit
val process_sctp_data : t -> stream_id:int -> bytes -> unit

val open_channel
  :  t
  -> label:string
  -> ?protocol:string
  -> ?priority:int
  -> ?channel_type:Dcep.channel_type
  -> unit
  -> (int, string) result

val send : t -> stream_id:int -> data:bytes -> (int, string) result
val close_channel : t -> stream_id:int -> unit
val tick : t -> unit
val get_state : t -> dtls_state
val is_connected : t -> bool

type stats =
  { dtls_state : dtls_state
  ; sctp_stats : Sctp_core.stats
  ; dcep_stats : Dcep.stats
  }

val get_stats : t -> stats
val close : t -> unit
