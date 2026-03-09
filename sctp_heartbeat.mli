(** SCTP HEARTBEAT - RFC 4960 Section 8.3

    HEARTBEAT serves multiple purposes:
    1. Path verification - ensure remote endpoint is reachable
    2. RTT measurement - calculate round-trip time for RTO
    3. Keep-alive - prevent NAT/firewall timeout

    Protocol:
    {v
    Sender                    Receiver
      |                         |
      |------ HEARTBEAT ------->|  (timestamp + random info)
      |<----- HEARTBEAT-ACK ----|  (echo back unchanged)
      |                         |
    v}

    @author Second Brain
    @since RFC 4960 compliance
*)

type heartbeat_info =
  { timestamp : float
  ; random_nonce : int32
  ; path_id : int
  }

type t =
  { mutable last_heartbeat_sent : float option
  ; mutable last_heartbeat_acked : float option
  ; mutable pending_heartbeat : heartbeat_info option
  ; mutable consecutive_failures : int
  ; interval_ms : int
  ; max_failures : int
  }

val chunk_type_heartbeat : int
val chunk_type_heartbeat_ack : int
val create : ?interval_ms:int -> ?max_failures:int -> unit -> t
val encode_heartbeat_info : heartbeat_info -> bytes
val decode_heartbeat_info : bytes -> (heartbeat_info, string) result
val encode_heartbeat : heartbeat_info -> bytes
val decode_heartbeat : bytes -> (heartbeat_info, string) result
val encode_heartbeat_ack : heartbeat_info -> bytes
val decode_heartbeat_ack : bytes -> (heartbeat_info, string) result
val should_send_heartbeat : t -> bool
val generate_heartbeat : t -> path_id:int -> bytes
val process_heartbeat : bytes -> (bytes, string) result
val process_heartbeat_ack : t -> bytes -> (float, string) result
val handle_timeout : t -> unit
val is_path_down : t -> bool
val failure_count : t -> int

val update_rto
  :  current_srtt:float
  -> current_rttvar:float
  -> measured_rtt:float
  -> float * float * float

val pp_heartbeat_info : Format.formatter -> heartbeat_info -> unit
val pp : Format.formatter -> t -> unit
