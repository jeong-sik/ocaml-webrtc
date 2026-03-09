(** RFC 4960 SCTP Reliable Transport Layer

    Implements the full SCTP state machine:
    - SACK (Selective Acknowledgment) handling
    - Congestion Control (Slow Start, Congestion Avoidance)
    - Retransmission (T3-rtx timer, Fast Retransmit)

    This layer sits on top of sctp.ml encoding and sctp_transport.ml network I/O
    to provide reliable, congestion-controlled data transfer.

    @author Second Brain
    @since ocaml-webrtc 0.3.0
*)

type gap_block =
  { start_offset : int
  ; end_offset : int
  }

type dup_tsn = int32

type sack =
  { cumulative_tsn_ack : int32
  ; a_rwnd : int
  ; gap_blocks : gap_block list
  ; dup_tsns : dup_tsn list
  }

type gap_range =
  { gr_start : int32
  ; gr_end : int32
  }

type recv_buffer =
  { mutable cumulative_tsn : int32
  ; mutable gap_ranges : gap_range list
  ; mutable a_rwnd : int
  ; mutable dup_tsns : int32 list
  }

type congestion_state =
  { mutable cwnd : int
  ; mutable ssthresh : int
  ; mutable partial_bytes_acked : int
  ; mutable in_fast_recovery : bool
  ; mutable fast_recovery_exit_point : int32
  }

type rto_state =
  { mutable srtt : float
  ; mutable rttvar : float
  ; mutable rto : float
  ; rto_min : float
  ; rto_max : float
  }

type stats =
  { mutable data_chunks_sent : int
  ; mutable data_chunks_recv : int
  ; mutable sacks_sent : int
  ; mutable sacks_recv : int
  ; mutable retransmissions : int
  ; mutable fast_retransmissions : int
  ; mutable timeouts : int
  ; mutable bytes_sent : int
  ; mutable bytes_acked : int
  }

type t =
  { config : Sctp.config
  ; rtx_queue : Sctp_ring_buffer.t
  ; recv_buf : recv_buffer
  ; cc : congestion_state
  ; rto : rto_state
  ; rack : Sctp_rack.t
  ; mutable t3_rtx_start : float option
  ; stats : stats
  }

val mtu_overhead : int
val sctp_header_size : int
val data_chunk_header_size : int
val sack_chunk_header_size : int
val max_payload_size : Sctp.config -> int
val create_stats : unit -> stats
val random_initial_tsn : unit -> int32
val create : ?config:Sctp.config -> ?initial_tsn:int32 -> unit -> t
val encode_sack : sack -> bytes
val decode_sack : bytes -> (sack, string) result
val tsn_lt : int32 -> int32 -> bool
val tsn_le : int32 -> int32 -> bool
val tsn_gt : int32 -> int32 -> bool
val record_received : t -> int32 -> bool
val generate_sack : t -> sack
val update_rto : t -> float -> unit
val process_sack : t -> sack -> unit
val check_t3_rtx_timeout : t -> Sctp.data_chunk list
val get_fast_retransmit_chunks : t -> Sctp.data_chunk list
val can_send : t -> bool
val queue_data : t -> Sctp.data_chunk -> unit
val alloc_tsn : t -> int32
val get_stats : t -> stats
val get_cwnd : t -> int
val get_ssthresh : t -> int
val get_flight_size : t -> int
val get_rto : t -> float
val all_acked : t -> bool
val pp_stats : Format.formatter -> stats -> unit
val pp_cc_state : Format.formatter -> t -> unit
val get_cumulative_tsn : t -> int32
val get_gap_count : t -> int
val get_gap_ranges : t -> (int * int) list
val get_next_tsn : t -> int32
val get_last_sent_tsn : t -> int32
