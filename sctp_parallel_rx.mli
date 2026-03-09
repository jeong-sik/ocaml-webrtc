(** Domain-Parallel RX for SCTP (OCaml 5.x Multicore)

    Distributes packet reception across multiple CPU cores for maximum throughput.

    Architecture:
    ┌─────────────────────────────────────────────────────┐
    │                   Main Domain                        │
    │  ┌─────────┐ ┌─────────┐ ┌─────────────────────┐   │
    │  │ Sender  │ │ Timers  │ │ Stats Aggregator    │   │
    │  └─────────┘ └─────────┘ └─────────────────────┘   │
    ├─────────────────────────────────────────────────────┤
    │  RX Domain 0    │  RX Domain 1    │  RX Domain N   │
    │  ┌───────────┐  │  ┌───────────┐  │  ┌──────────┐  │
    │  │ UDP Recv  │  │  │ UDP Recv  │  │  │ UDP Recv │  │
    │  │ Process   │  │  │ Process   │  │  │ Process  │  │
    │  │ Local Sta │  │  │ Local Sta │  │  │ Local St │  │
    │  └───────────┘  │  └───────────┘  │  └──────────┘  │
    └─────────────────────────────────────────────────────┘

    Key Design Decisions:
    - Domain-local mutable stats (no Atomic on hot path)
    - Lock-free MPSC queue for output delivery
    - Periodic stats aggregation (not per-packet)

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

type domain_stats =
  { mutable packets_recv : int
  ; mutable bytes_recv : int
  ; mutable messages_delivered : int
  ; mutable crc_errors : int
  ; mutable parse_errors : int
  }

val create_domain_stats : unit -> domain_stats
val stats_key : domain_stats Domain.DLS.key
val get_local_stats : unit -> domain_stats

type aggregated_stats =
  { total_packets_recv : int
  ; total_bytes_recv : int
  ; total_messages_delivered : int
  ; total_crc_errors : int
  ; total_parse_errors : int
  ; domain_count : int
  }

module Mpsc_queue : sig
  type 'a node
  type 'a t

  val create : unit -> 'a t
  val push : 'a t -> 'a -> unit
  val pop : 'a t -> 'a option
  val drain : 'a t -> 'a list
end

type rx_output =
  | DeliverData of
      { stream_id : int
      ; data : bytes
      }
  | SendSack of bytes
  | Error of string

type rx_domain =
  { id : int
  ; domain : unit Domain.t option ref
  ; output_queue : rx_output Mpsc_queue.t
  ; mutable running : bool
  }

val create_rx_domain : id:int -> output_queue:rx_output Mpsc_queue.t -> rx_domain

type t =
  { domains : rx_domain array
  ; output_queue : rx_output Mpsc_queue.t
  ; mutable stats_snapshot : aggregated_stats option
  ; domain_count : int
  }

val create : ?num_domains:int -> unit -> t
val process_packet_in_domain : core:Sctp_core.t -> packet:bytes -> rx_output list

val start
  :  t
  -> core_factory:(unit -> Sctp_core.t)
  -> recv_packet:(unit -> bytes option)
  -> unit

val stop : t -> unit
val drain_outputs : t -> rx_output list
val aggregate_stats : t -> aggregated_stats
val get_stats : t -> aggregated_stats
val domain_count : t -> int
val is_running : t -> bool
val pp_stats : Format.formatter -> aggregated_stats -> unit
