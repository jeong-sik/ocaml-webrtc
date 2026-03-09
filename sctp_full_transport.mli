(** Full SCTP Transport - Complete Reliable Transport Layer

    Integrates all SCTP components for fair comparison with Pion:
    - sctp.ml: Chunk encoding/decoding
    - sctp_reliable.ml: SACK, congestion control, retransmission
    - udp_transport.ml: Real network I/O

    This provides the same functionality as Pion's SCTP implementation:
    - Reliable, ordered delivery
    - Congestion control (Slow Start, Congestion Avoidance)
    - Fast Retransmit (3 dup SACKs)
    - T3-rtx timeout retransmission

    @author Second Brain
    @since ocaml-webrtc 0.3.0
*)

type stats =
  { mutable messages_sent : int
  ; mutable messages_recv : int
  ; mutable bytes_sent : int
  ; mutable bytes_recv : int
  ; mutable sacks_sent : int
  ; mutable sacks_recv : int
  ; mutable retransmissions : int
  ; mutable fast_retransmissions : int
  }

type t =
  { udp : Udp_transport.t
  ; reliable : Sctp_reliable.t
  ; config : Sctp.config
  ; mutable next_stream_seq : int
  ; recv_buffer : bytes
  ; send_buffer : bytes
  ; stats : stats
  ; mutable packets_since_sack : int
  ; mutable pending_sack : bool
  ; mutable bundle_offset : int
  }

val create_stats : unit -> stats

val create
  :  ?config:Sctp.config
  -> ?initial_tsn:int32
  -> host:string
  -> port:int
  -> unit
  -> t

val connect : t -> host:string -> port:int -> unit
val local_endpoint : t -> Udp_transport.endpoint
val send_packet : t -> bytes -> (int, string) result
val recv_packet : t -> timeout_ms:int -> (int * Udp_transport.endpoint, string) result
val try_recv_packet_zerocopy : t -> (bytes * int) option
val try_recv_packet : t -> bytes option
val flush_bundle : t -> unit
val bundle_chunk : t -> Sctp.data_chunk -> int
val send_data : t -> stream_id:int -> data:bytes -> (int, string) result

val process_single_chunk
  :  t
  -> buf:bytes
  -> off:int
  -> remaining:int
  -> int * bytes option

val process_packet_view : t -> buf:bytes -> off:int -> len:int -> bytes option
val process_packet : t -> bytes -> bytes option
val send_chunk_immediate : t -> Sctp.data_chunk -> unit
val handle_retransmissions : t -> unit
val recv_data : t -> timeout_ms:int -> (bytes, string) result
val try_recv_data : t -> bytes option
val flush_pending_sack : t -> unit
val tick : t -> unit
val close : t -> unit
val is_closed : t -> bool
val get_udp_transport : t -> Udp_transport.t
val get_stats : t -> stats
val get_reliable_stats : t -> Sctp_reliable.stats
val get_cwnd : t -> int
val get_ssthresh : t -> int
val get_flight_size : t -> int
val get_rto : t -> float
val get_cumulative_tsn : t -> int32
val get_gap_count : t -> int
val get_gap_ranges : t -> (int * int) list
val pp_stats : Format.formatter -> stats -> unit
val pp_cc_state : Format.formatter -> t -> unit
