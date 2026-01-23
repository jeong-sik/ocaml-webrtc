(** RACK - Recent ACKnowledgment Algorithm (RFC 8985)

    Time-based loss detection that outperforms traditional "3 duplicate SACKs".
*)

(** {1 Types} *)

(** RACK state *)
type t

(** Per-packet transmission info *)
type xmit_info =
  { tsn : int32
  ; mutable sent_at : float
  ; size : int
  ; mutable retx_count : int
  }

(** {1 Creation} *)

(** Create new RACK state *)
val create : unit -> t

(** {1 Packet Tracking} *)

(** Record packet transmission *)
val on_packet_sent : t -> tsn:int32 -> size:int -> now:float -> unit

(** Remove packet from tracking *)
val on_packet_acked : t -> tsn:int32 -> unit

(** {1 Loss Detection} *)

(** RACK loss detection - returns list of TSNs detected as lost *)
val detect_loss : t -> now:float -> acked_tsns:int32 list -> int32 list

(** {1 Tail Loss Probe (TLP)} *)

(** Calculate TLP timeout in seconds *)
val tlp_timeout : t -> float

(** Check if TLP probe should be sent *)
val should_send_tlp : t -> now:float -> last_send:float -> in_flight:int -> bool

(** Record TLP probe sent *)
val on_tlp_sent : t -> high_tsn:int32 -> unit

(** TLP probe ACKed *)
val on_tlp_acked : t -> unit

(** {1 Retransmission} *)

(** Mark packet as retransmitted *)
val on_packet_retransmitted : t -> tsn:int32 -> now:float -> unit

(** {1 Statistics} *)

val get_rtt_min : t -> float
val get_rtt_smoothed : t -> float
val get_reorder_window : t -> float
val get_in_flight_count : t -> int
val pp : Format.formatter -> t -> unit

(** {1 Backward-Compatible API} *)

(** Record packet send (simplified API for sctp_reliable.ml) *)
val record_send : t -> int32 -> unit

(** Process SACK and return (rtt_sample, lost TSNs) using RACK algorithm *)
val process_sack
  :  t
  -> cumulative_tsn:int32
  -> gap_blocks:(int * int) list
  -> float option * int32 list
