(** SCTP Shutdown - RFC 4960 Section 9

    Graceful connection termination ensuring all data is delivered.

    Shutdown flow (3-way):
    {v
    Initiator                 Peer
      |                         |
      |------ SHUTDOWN -------->|  (1) Cumulative TSN ACK point
      |<----- SHUTDOWN-ACK -----|  (2) Acknowledgment
      |------ SHUTDOWN-COMPLETE>|  (3) Final confirmation
      |                         |
    v}

    Unlike TCP's 4-way close (FIN/ACK each direction), SCTP doesn't have
    half-close. SHUTDOWN means "I have no more data AND I want to close".

    Note: If there's still data to send, use SHUTDOWN-PENDING state first.

    @author Second Brain
    @since RFC 4960 compliance
*)

type shutdown = { cumulative_tsn_ack : int32 }

type state =
  | Active
  | ShutdownPending
  | ShutdownSent
  | ShutdownReceived
  | ShutdownAckSent
  | Closed

val state_to_string : state -> string

type t =
  { mutable state : state
  ; mutable shutdown_sent_time : float option
  ; mutable retransmit_count : int
  ; max_retransmits : int
  ; mutable peer_cumulative_tsn : int32 option
  }

val chunk_type_shutdown : int
val chunk_type_shutdown_ack : int
val chunk_type_shutdown_complete : int
val create : ?max_retransmits:int -> unit -> t
val encode_shutdown : shutdown -> bytes
val decode_shutdown : bytes -> (shutdown, string) result
val encode_shutdown_ack : unit -> bytes
val decode_shutdown_ack : bytes -> (unit, string) result
val encode_shutdown_complete : t_bit:bool -> bytes
val decode_shutdown_complete : bytes -> (bool, string) result
val initiate_shutdown : t -> cumulative_tsn:int32 -> (bytes, string) result
val process_shutdown : t -> bytes -> (bytes, string) result
val process_shutdown_ack : t -> bytes -> (bytes, string) result
val process_shutdown_complete : t -> bytes -> (unit, string) result
val needs_retransmit : t -> rto:float -> bool
val retransmit_shutdown : t -> cumulative_tsn:int32 -> (bytes, string) result
val is_closed : t -> bool
val is_shutting_down : t -> bool
val can_send_data : t -> bool
val pp : Format.formatter -> t -> unit
