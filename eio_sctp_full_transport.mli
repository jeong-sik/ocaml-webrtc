(** Eio-native Full SCTP Transport - Concurrent Reliable Transport

    Uses Eio fibers for concurrent send/recv/timer operations:
    - Sender fiber: sends data as fast as cwnd allows
    - Receiver fiber: processes incoming packets and sends SACKs
    - Timer fiber: handles T3-rtx timeouts and periodic tasks

    This is analogous to Pion's goroutine-based architecture.

    Key insight: We use existing non-blocking Unix sockets with
    Eio.Fiber.yield() for cooperative scheduling between fibers.

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

type stats = Sctp_full_transport.stats =
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
  { inner : Sctp_full_transport.t
  ; mutable running : bool
  }

val create
  :  ?config:Sctp.config
  -> ?initial_tsn:int32
  -> host:string
  -> port:int
  -> unit
  -> t

val connect : t -> host:string -> port:int -> unit
val local_endpoint : t -> Udp_transport.endpoint
val send_data : t -> stream_id:int -> data:bytes -> (int, string) result
val try_send_data : t -> stream_id:int -> data:bytes -> (int, string) result
val tick : t -> unit
val run_sender : t -> get_data:(unit -> (int * bytes) option) -> unit
val run_receiver : t -> on_data:(bytes -> unit) -> unit

val run_timer
  :  t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock
  -> interval_ms:int
  -> unit

val run_concurrent
  :  t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock
  -> get_data:(unit -> (int * bytes) option)
  -> on_data:(bytes -> unit)
  -> unit

val stop : t -> unit
val close : t -> unit
val is_closed : t -> bool
val get_stats : t -> Sctp_full_transport.stats
val get_reliable_stats : t -> Sctp_reliable.stats
val get_udp_transport : t -> Udp_transport.t
val get_cwnd : t -> int
val get_ssthresh : t -> int
val get_flight_size : t -> int
val get_rto : t -> float
val get_cumulative_tsn : t -> int32
val get_gap_count : t -> int
val get_gap_ranges : t -> (int * int) list
val pp_stats : Format.formatter -> Sctp_full_transport.stats -> unit
val pp_cc_state : Format.formatter -> t -> unit
