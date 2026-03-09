(** PR-SCTP - Partial Reliability Extension

    Implements RFC 3758: SCTP Partial Reliability Extension.

    Partial Reliability allows senders to abandon messages that:
    - Exceed a time limit (timed reliability)
    - Exceed a retransmission limit
    - Are explicitly abandoned by the application

    Use cases:
    - Real-time media: Old video frames are useless
    - Gaming: Position updates supercede old ones
    - Live telemetry: Stale sensor data is worthless

    WebRTC DataChannel uses PR-SCTP with "maxRetransmits" and "maxPacketLifeTime".

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

type policy =
  | Reliable
  | TimedReliability of { max_lifetime_ms : int }
  | LimitedRetransmit of { max_rtx : int }

type stream_seq =
  { stream_id : int
  ; stream_seq : int
  }

type forward_tsn =
  { new_cumulative_tsn : int32
  ; stream_seqs : stream_seq list
  }

type message_state =
  | Pending
  | InFlight
  | Abandoned
  | Delivered

type message =
  { tsn : int32
  ; stream_id : int
  ; stream_seq : int
  ; policy : policy
  ; send_time : float
  ; mutable rtx_count : int
  ; mutable state : message_state
  }

type t =
  { mutable messages : message list
  ; mutable abandoned_tsns : int32 list
  ; mutable forward_tsn_sent : int32
  }

val create : unit -> t

val track_message
  :  t
  -> tsn:int32
  -> stream_id:int
  -> stream_seq:int
  -> policy:policy
  -> unit

val mark_sent : t -> tsn:int32 -> unit
val mark_delivered : t -> tsn:int32 -> unit
val record_retransmit : t -> tsn:int32 -> unit
val should_abandon : message -> bool
val check_abandonments : t -> int32 list
val generate_forward_tsn : t -> current_cumulative_tsn:Int32.t -> forward_tsn option
val chunk_type_forward_tsn : int
val encode_forward_tsn : forward_tsn -> bytes
val decode_forward_tsn : bytes -> (forward_tsn, string) result
val process_forward_tsn : recv_cumulative_tsn:int32 -> forward_tsn -> int32

type stats =
  { messages_tracked : int
  ; messages_abandoned : int
  ; forward_tsns_sent : int
  }

val get_stats : t -> stats
val string_of_policy : policy -> string
val string_of_state : message_state -> string
