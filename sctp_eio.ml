(** Eio I/O Adapter for Sans-IO SCTP

    Bridges the pure Sans-IO state machine (sctp_core.ml) with
    actual network I/O using Eio (OCaml 5.x effects-based async).

    Architecture:
    ┌─────────────────────────────────────────┐
    │           Application Layer             │
    ├─────────────────────────────────────────┤
    │         Sctp_core (Pure)                │  ← No I/O
    ├─────────────────────────────────────────┤
    │         This Adapter (Sctp_eio)         │  ← I/O effects
    │  ┌─────────┐ ┌─────────┐ ┌─────────┐   │
    │  │ Recv    │ │ Timer   │ │ Send    │   │
    │  │ Fiber   │ │ Manager │ │ Queue   │   │
    │  └─────────┘ └─────────┘ └─────────┘   │
    ├─────────────────────────────────────────┤
    │            Eio.Net (UDP)                │
    └─────────────────────────────────────────┘

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** {1 Types} *)

type timer_state =
  { mutable active : bool
  ; mutable deadline : float
  }

type t =
  { core : Sctp_core.t
  ; udp : Udp_transport.t
  ; recv_buffer : bytes
  ; buffer_pool : Buffer_pool.t (* Zero-copy buffer pool *)
  ; (* Timer management *)
    timers : (Sctp_core.timer_id, timer_state) Hashtbl.t
  ; mutable timer_check_interval : float (* How often to check timers *)
  ; (* Callbacks for application layer *)
    mutable on_data : (int -> bytes -> unit) option
  ; mutable on_connected : (unit -> unit) option
  ; mutable on_closed : (unit -> unit) option
  ; mutable on_error : (string -> unit) option
  }

(** {1 Creation} *)

let create ?(config = Sctp.default_config) ?initial_tsn ~host ~port () =
  let udp = Udp_transport.create ~host ~port () in
  let core = Sctp_core.create ~config ?initial_tsn () in
  (* Buffer pool: 2048 buffers × 2KB = 4MB pre-allocated for high throughput *)
  let pool_config = Buffer_pool.{ buffer_size = 2048; pool_size = 2048 } in
  { core
  ; udp
  ; recv_buffer = Bytes.create 65536
  ; buffer_pool = Buffer_pool.create ~config:pool_config ()
  ; timers = Hashtbl.create 8
  ; timer_check_interval = 0.010
  ; (* 10ms - fast timer resolution *)
    on_data = None
  ; on_connected = None
  ; on_closed = None
  ; on_error = None
  }
;;

let connect t ~host ~port = Udp_transport.connect t.udp ~host ~port
let local_endpoint t = Udp_transport.local_endpoint t.udp

(** {1 Callback Registration} *)

let on_data t f = t.on_data <- Some f
let on_connected t f = t.on_connected <- Some f
let on_closed t f = t.on_closed <- Some f
let on_error t f = t.on_error <- Some f

(** {1 Output Execution} *)

(** Execute a single output action from the core state machine *)
let execute_output t output =
  match output with
  | Sctp_core.SendPacket packet ->
    (* Send UDP packet *)
    (match Udp_transport.send_connected t.udp ~data:packet with
     | Ok _ -> ()
     | Error e -> Log.error "[SCTP-Eio] Send failed: %s" e)
  | Sctp_core.DeliverData { stream_id; data } ->
    (* Deliver to application callback *)
    (match t.on_data with
     | Some f -> f stream_id data
     | None -> () (* No callback registered, data is dropped *))
  | Sctp_core.SetTimer { timer; delay_ms } ->
    (* Set or update timer *)
    let state =
      match Hashtbl.find_opt t.timers timer with
      | Some s -> s
      | None ->
        let s = { active = false; deadline = 0.0 } in
        Hashtbl.add t.timers timer s;
        s
    in
    state.active <- true;
    state.deadline <- Unix.gettimeofday () +. (delay_ms /. 1000.0)
  | Sctp_core.CancelTimer timer ->
    (match Hashtbl.find_opt t.timers timer with
     | Some state -> state.active <- false
     | None -> ())
  | Sctp_core.ConnectionEstablished ->
    (match t.on_connected with
     | Some f -> f ()
     | None -> ())
  | Sctp_core.ConnectionClosed ->
    (match t.on_closed with
     | Some f -> f ()
     | None -> ())
  | Sctp_core.Error e ->
    (match t.on_error with
     | Some f -> f e
     | None -> Log.error "[SCTP-Eio] Error: %s" e)
;;

(** Execute all outputs from core, then flush pending transmissions *)
let execute_outputs t outputs =
  List.iter (execute_output t) outputs;
  (* Flush any pending SACK or bundled chunks (webrtc-rs poll_transmit pattern) *)
  let pending = Sctp_core.poll_transmit t.core in
  List.iter (execute_output t) pending
;;

(** {1 Input Processing} *)

(** Process incoming UDP packet *)
let process_recv t packet =
  let outputs = Sctp_core.handle t.core (Sctp_core.PacketReceived packet) in
  execute_outputs t outputs
;;

(** Check and fire expired timers *)
let check_timers t =
  let now = Unix.gettimeofday () in
  Hashtbl.iter
    (fun timer_id state ->
       if state.active && now >= state.deadline
       then (
         state.active <- false;
         let outputs = Sctp_core.handle t.core (Sctp_core.TimerFired timer_id) in
         execute_outputs t outputs))
    t.timers
;;

(** {1 Sending} *)

(** Send data through SCTP (application API) *)
let send t ~stream_id ~data =
  let outputs = Sctp_core.handle t.core (Sctp_core.UserSend { stream_id; data }) in
  execute_outputs t outputs;
  (* Return success/failure based on outputs *)
  let has_error =
    List.exists
      (function
        | Sctp_core.Error _ -> true
        | _ -> false)
      outputs
  in
  if has_error then Error "Send failed" else Ok (Bytes.length data)
;;

(** {1 Non-blocking Operations} *)

(** Try to receive and process one packet (non-blocking) *)
let try_recv t =
  match Udp_transport.recv t.udp ~buf:t.recv_buffer with
  | Ok (len, _) ->
    let packet = Bytes.sub t.recv_buffer 0 len in
    process_recv t packet;
    true
  | Error _ -> false
;;

(** Tick: process pending I/O and timers (call from event loop) *)
let tick t =
  (* Process all available incoming packets *)
  while try_recv t do
    ()
  done;
  (* Check timers *)
  check_timers t;
  (* Always flush pending transmissions (webrtc-rs pattern) *)
  (* This ensures SACKs are sent even when no new data arrives *)
  let pending = Sctp_core.poll_transmit t.core in
  List.iter (execute_output t) pending
;;

(** {1 Blocking Operations with Timeout} *)

(** Receive with timeout (blocks up to timeout_ms) *)
let recv_timeout t ~timeout_ms =
  match Udp_transport.recv_timeout t.udp ~buf:t.recv_buffer ~timeout_ms with
  | Ok (len, _) ->
    let packet = Bytes.sub t.recv_buffer 0 len in
    process_recv t packet;
    Ok ()
  | Error e -> Error e
;;

(** {1 Event Loop} *)

(** Run the SCTP event loop (blocking).
    Processes incoming packets and timers continuously.
    Returns when the connection is closed or on error.

    For high-performance scenarios, prefer using tick() in your own loop. *)
let run_loop t =
  while not (Udp_transport.is_closed t.udp) do
    (* Non-blocking receive *)
    ignore (try_recv t);
    (* Check timers *)
    check_timers t;
    (* Small sleep to prevent busy-waiting *)
    Time_compat.sleep 0.001
  done
;;

(** {1 Lifecycle} *)

let close t =
  (* Request graceful shutdown *)
  let outputs = Sctp_core.handle t.core Sctp_core.UserClose in
  execute_outputs t outputs;
  (* Close UDP transport *)
  Udp_transport.close t.udp
;;

let is_closed t = Udp_transport.is_closed t.udp

(** {1 State Access} *)

let get_core t = t.core
let get_stats t = Sctp_core.get_stats t.core
let is_established t = Sctp_core.is_established t.core
let can_send t = Sctp_core.can_send t.core

(** Congestion control metrics *)
let get_cwnd t = Sctp_core.get_cwnd t.core

let get_ssthresh t = Sctp_core.get_ssthresh t.core
let get_flight_size t = Sctp_core.get_flight_size t.core
let get_rto t = Sctp_core.get_rto t.core

(** Debug: Get underlying UDP transport *)
let get_udp_transport t = t.udp
