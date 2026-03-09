(** High-Performance Ring Buffer for SCTP

    Inspired by Jane Street's zero-allocation patterns:
    - Pre-allocated fixed-size array (no GC pressure)
    - Circular buffer for O(1) enqueue/dequeue
    - Avoids Hashtbl overhead for sequential TSN operations

    Reference: https://blog.janestreet.com/oxidizing-ocaml-locality/

    Performance target: Replace Hashtbl-based rtx_queue for
    ~10x throughput improvement.

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

type entry_state =
  | Empty
  | InFlight of
      { chunk : Sctp.data_chunk
      ; mutable sent_at : float
      ; mutable retransmit_count : int
      ; mutable miss_indications : int
      ; mutable fast_retransmit : bool
      }
  | Acked

type t =
  { entries : entry_state array
  ; capacity : int
  ; mutable head_tsn : int32
  ; mutable tail_tsn : int32
  ; mutable count : int
  ; mutable flight_bytes : int
  }

val default_capacity : int
val create : ?capacity:int -> initial_tsn:int32 -> unit -> t
val tsn_to_index : t -> int32 -> int
val is_full : t -> bool
val is_empty : t -> bool
val flight_size : t -> int
val enqueue : t -> Sctp.data_chunk -> int32 option
val next_tsn : t -> int32
val alloc_tsn : t -> int32
val enqueue_with_tsn : t -> Sctp.data_chunk -> bool
val ack : t -> int32 -> int
val advance_head : t -> int
val get : t -> int32 -> (Sctp.data_chunk * int) option
val mark_retransmit : t -> int32 -> bool
val incr_miss : t -> int32 -> int
val iter_in_flight : t -> (int32 -> Sctp.data_chunk -> float -> int -> unit) -> unit
val get_fast_retransmit_candidates : t -> int32 list
val process_cumulative_ack : t -> Int32.t -> float -> int * float option
val is_acked : t -> int32 -> bool
val set_fast_retransmit : t -> int32 -> bool
val iter_unacked_above : t -> Int32.t -> (int32 -> int -> bool) -> unit
val get_entry_info : t -> int32 -> (bool * int) option
val mark_all_for_retransmit : t -> Sctp.data_chunk list
val get_and_clear_fast_retransmit : t -> Sctp.data_chunk list
val stats : t -> string
