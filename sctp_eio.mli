(** Eio I/O Adapter for Sans-IO SCTP

    Bridges the pure Sans-IO state machine (sctp_core.ml) with
    actual network I/O using Eio (OCaml 5.x effects-based async).

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
  ; buffer_pool : Buffer_pool.t
  ; timers : (Sctp_core.timer_id, timer_state) Hashtbl.t
  ; mutable timer_check_interval : float
  ; mutable on_data : (int -> bytes -> unit) option
  ; mutable on_connected : (unit -> unit) option
  ; mutable on_closed : (unit -> unit) option
  ; mutable on_error : (string -> unit) option
  }

(** {1 Creation} *)

val create
  :  ?config:Sctp.config
  -> ?initial_tsn:int32
  -> host:string
  -> port:int
  -> unit
  -> t

val connect : t -> host:string -> port:int -> unit
val local_endpoint : t -> Udp_transport.endpoint

(** {1 Callback Registration} *)

val on_data : t -> (int -> bytes -> unit) -> unit
val on_connected : t -> (unit -> unit) -> unit
val on_closed : t -> (unit -> unit) -> unit
val on_error : t -> (string -> unit) -> unit

(** {1 Output Execution} *)

val execute_output : t -> Sctp_core.output -> unit
val execute_outputs : t -> Sctp_core.output list -> unit

(** {1 Input Processing} *)

val process_recv : t -> bytes -> unit
val check_timers : t -> unit

(** {1 Sending} *)

val send : t -> stream_id:int -> data:bytes -> (int, string) result

(** {1 Non-blocking Operations} *)

val try_recv : t -> bool
val tick : t -> unit

(** {1 Blocking Operations with Timeout} *)

val recv_timeout : t -> timeout_ms:int -> (unit, string) result

(** {1 Event Loop} *)

val run_loop : t -> unit

(** {1 Lifecycle} *)

val close : t -> unit
val is_closed : t -> bool

(** {1 State Access} *)

val get_core : t -> Sctp_core.t
val get_stats : t -> Sctp_core.stats
val is_established : t -> bool
val can_send : t -> bool

(** Congestion control metrics *)

val get_cwnd : t -> int
val get_ssthresh : t -> int
val get_flight_size : t -> int
val get_rto : t -> float

(** Debug: Get underlying UDP transport *)

val get_udp_transport : t -> Udp_transport.t
