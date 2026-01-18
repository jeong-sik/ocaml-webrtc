(** RACK - Recent ACKnowledgment Algorithm (RFC 8985)

    Time-based loss detection that outperforms traditional "3 duplicate SACKs".
*)

(** {1 Types} *)

type t
(** RACK state *)

type xmit_info = {
  tsn: int32;
  mutable sent_at: float;
  size: int;
  mutable retx_count: int;
}
(** Per-packet transmission info *)

(** {1 Creation} *)

val create : unit -> t
(** Create new RACK state *)

(** {1 Packet Tracking} *)

val on_packet_sent : t -> tsn:int32 -> size:int -> now:float -> unit
(** Record packet transmission *)

val on_packet_acked : t -> tsn:int32 -> unit
(** Remove packet from tracking *)

(** {1 Loss Detection} *)

val detect_loss : t -> now:float -> acked_tsns:int32 list -> int32 list
(** RACK loss detection - returns list of TSNs detected as lost *)

(** {1 Tail Loss Probe (TLP)} *)

val tlp_timeout : t -> float
(** Calculate TLP timeout in seconds *)

val should_send_tlp : t -> now:float -> last_send:float -> in_flight:int -> bool
(** Check if TLP probe should be sent *)

val on_tlp_sent : t -> high_tsn:int32 -> unit
(** Record TLP probe sent *)

val on_tlp_acked : t -> unit
(** TLP probe ACKed *)

(** {1 Retransmission} *)

val on_packet_retransmitted : t -> tsn:int32 -> now:float -> unit
(** Mark packet as retransmitted *)

(** {1 Statistics} *)

val get_rtt_min : t -> float
val get_rtt_smoothed : t -> float
val get_reorder_window : t -> float
val get_in_flight_count : t -> int
val pp : Format.formatter -> t -> unit

(** {1 Backward-Compatible API} *)

val record_send : t -> int32 -> unit
(** Record packet send (simplified API for sctp_reliable.ml) *)

val process_sack : t -> cumulative_tsn:int32 -> gap_blocks:(int * int) list -> float option * int32 list
(** Process SACK and return (rtt_sample, lost TSNs) using RACK algorithm *)
