(** SCTP Transport Layer

    Integrates SCTP protocol with UDP transport for real network I/O.
    This provides the complete data path for WebRTC Data Channels.

    Architecture:
    - Application sends data via send_data
    - SCTP fragments into chunks, encodes packets
    - UDP transport sends actual bytes over network
    - Receive path reverses: UDP recv -> SCTP decode -> Application

    @author Second Brain
    @since ocaml-webrtc 0.3.0
*)

type config =
  { local_port : int
  ; remote_port : int
  ; mtu : int
  ; max_message_size : int
  }

val default_config : config

type stats =
  { mutable messages_sent : int
  ; mutable messages_recv : int
  ; mutable bytes_sent : int
  ; mutable bytes_recv : int
  ; mutable chunks_sent : int
  ; mutable chunks_recv : int
  ; mutable retransmits : int
  ; mutable errors : int
  }

type t =
  { config : config
  ; udp : Udp_transport.t
  ; sctp : Sctp.association
  ; stats : stats
  ; mutable next_tsn : int32
  ; mutable next_stream_seq : int
  ; recv_buffer : bytes
  }

val create_stats : unit -> stats
val get_stats : t -> stats
val create : ?config:config -> host:string -> port:int -> unit -> t
val connect : t -> host:string -> port:int -> unit
val local_endpoint : t -> Udp_transport.endpoint
val send_data : t -> stream_id:int -> data:bytes -> (int, string) result
val send_data_batch : t -> stream_id:int -> data:bytes -> (int, string) result
val recv_data : t -> timeout_ms:int -> (bytes, string) result
val try_recv_data : t -> bytes option
val close : t -> unit
val is_closed : t -> bool
val pp_stats : Format.formatter -> stats -> unit
