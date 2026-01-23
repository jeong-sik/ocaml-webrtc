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

(** {1 Types} *)

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

(** Eio-enhanced transport wraps blocking transport *)
type t =
  { inner : Sctp_full_transport.t
  ; mutable running : bool
  }

(** {1 Creation} *)

let create ?config ?initial_tsn ~host ~port () =
  let inner = Sctp_full_transport.create ?config ?initial_tsn ~host ~port () in
  { inner; running = true }
;;

let connect t ~host ~port = Sctp_full_transport.connect t.inner ~host ~port
let local_endpoint t = Sctp_full_transport.local_endpoint t.inner

(** {1 Fiber-based Operations} *)

(** Send data with yield on congestion *)
let send_data t ~stream_id ~data =
  let rec try_send () =
    match Sctp_full_transport.send_data t.inner ~stream_id ~data with
    | Error "Congestion window full" ->
      Eio.Fiber.yield ();
      if t.running then try_send () else Error "Stopped"
    | result -> result
  in
  try_send ()
;;

(** Non-blocking send - returns immediately *)
let try_send_data t ~stream_id ~data =
  Sctp_full_transport.send_data t.inner ~stream_id ~data
;;

(** Process incoming packets with yield *)
let tick t = Sctp_full_transport.tick t.inner

(** {1 Concurrent Fiber Runners} *)

(** Run sender fiber - continuously sends data from callback *)
let run_sender t ~get_data =
  while t.running do
    (* Check if we can send *)
    if Sctp_full_transport.get_flight_size t.inner < Sctp_full_transport.get_cwnd t.inner
    then (
      match get_data () with
      | Some (stream_id, data) ->
        ignore (Sctp_full_transport.send_data t.inner ~stream_id ~data)
      | None -> Eio.Fiber.yield ())
    else Eio.Fiber.yield ()
  done
;;

(** Run receiver fiber - continuously processes incoming packets *)
let run_receiver t ~on_data =
  while t.running do
    (* Process any pending packets *)
    Sctp_full_transport.tick t.inner;
    (* Check for received data *)
    match Sctp_full_transport.try_recv_data t.inner with
    | Some data -> on_data data
    | None -> Eio.Fiber.yield ()
  done
;;

(** Run timer fiber - handles retransmissions periodically *)
let run_timer t ~clock ~interval_ms =
  let interval = float_of_int interval_ms /. 1000.0 in
  while t.running do
    Eio.Time.sleep clock interval;
    Sctp_full_transport.tick t.inner
  done
;;

(** Run all fibers concurrently with Eio.Fiber.all *)
let run_concurrent t ~clock ~get_data ~on_data =
  Eio.Fiber.all
    [ (fun () -> run_sender t ~get_data)
    ; (fun () -> run_receiver t ~on_data)
    ; (fun () -> run_timer t ~clock ~interval_ms:1)
    ]
;;

(** {1 Lifecycle} *)

let stop t = t.running <- false

let close t =
  t.running <- false;
  Sctp_full_transport.close t.inner
;;

let is_closed t = Sctp_full_transport.is_closed t.inner

(** {1 Statistics & State} *)

let get_stats t = Sctp_full_transport.get_stats t.inner
let get_reliable_stats t = Sctp_full_transport.get_reliable_stats t.inner
let get_udp_transport t = Sctp_full_transport.get_udp_transport t.inner
let get_cwnd t = Sctp_full_transport.get_cwnd t.inner
let get_ssthresh t = Sctp_full_transport.get_ssthresh t.inner
let get_flight_size t = Sctp_full_transport.get_flight_size t.inner
let get_rto t = Sctp_full_transport.get_rto t.inner
let get_cumulative_tsn t = Sctp_full_transport.get_cumulative_tsn t.inner
let get_gap_count t = Sctp_full_transport.get_gap_count t.inner
let get_gap_ranges t = Sctp_full_transport.get_gap_ranges t.inner
let pp_stats fmt s = Sctp_full_transport.pp_stats fmt s
let pp_cc_state fmt t = Sctp_full_transport.pp_cc_state fmt t.inner
