(** Sans-IO SCTP State Machine - Pure Protocol Logic

    Implements RFC 4960 SCTP as a pure state machine with no I/O.
    Follows the Sans-IO pattern from str0m (Rust WebRTC):
    - Input: Events from the outside world
    - Output: Actions for the I/O layer to execute
    - State: Pure, deterministic state transitions

    {1 Sans-IO Architecture Benefits}

    - Unit testing without mocking (deterministic)
    - Memory efficient (str0m achieves 10MB for 1000 connections)
    - I/O layer is swappable (Eio, Lwt, blocking)
    - Easier to reason about correctness

    {1 Usage Pattern}

    {[
      let t = create ~config () in

      (* Main loop *)
      let rec loop () =
        (* Handle incoming packet *)
        let outputs = handle t (PacketReceived packet) in
        List.iter execute_output outputs;

        (* Check for data to send *)
        match poll_transmit t with
        | Some packet -> send_udp packet; loop ()
        | None -> wait_for_event (); loop ()
      in
      loop ()
    ]}

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** {1 Timer Types} *)

(** Timer identifiers for SCTP timeouts *)
type timer_id =
  | T3Rtx (** Retransmission timeout (RFC 4960 §6.3) *)
  | DelayedAck (** Delayed acknowledgment (RFC 4960 §6.2) *)
  | Heartbeat (** Path heartbeat (RFC 4960 §8.3) *)
  | Shutdown (** Shutdown timer *)

(** {1 Input Events} *)

(** Events that the state machine receives from outside *)
type input =
  | PacketReceived of bytes (** Incoming UDP packet *)
  | TimerFired of timer_id (** A timer expired *)
  | UserSend of
      { stream_id : int
      ; data : bytes
      } (** Application wants to send *)
  | UserResetStreams of { stream_ids : int list } (** Request stream reset (RFC 6525) *)
  | UserClose (** Application requests shutdown *)

(** {1 Output Actions} *)

(** Actions the I/O layer should execute *)
type output =
  | SendPacket of bytes (** Send this UDP packet *)
  | DeliverData of
      { stream_id : int
      ; data : bytes
      } (** Deliver to application *)
  | SetTimer of
      { timer : timer_id
      ; delay_ms : float
      } (** Set a timer *)
  | CancelTimer of timer_id (** Cancel a timer *)
  | ConnectionEstablished (** Notify: connected *)
  | ConnectionClosed (** Notify: closed *)
  | Error of string (** Notify: error *)

(** {1 Connection State} *)

(** SCTP association state machine (RFC 4960 §4) *)
type conn_state =
  | Closed
  | CookieWait (** Sent INIT, waiting for INIT-ACK *)
  | CookieEchoed (** Sent COOKIE-ECHO, waiting for COOKIE-ACK *)
  | Established (** Data transfer ready *)
  | ShutdownPending (** App requested close, draining *)
  | ShutdownSent (** Sent SHUTDOWN, waiting for SHUTDOWN-ACK *)
  | ShutdownReceived
  | ShutdownAckSent

(** {1 Statistics} *)

(** Immutable stats snapshot for external API *)
type stats =
  { messages_sent : int
  ; messages_recv : int
  ; bytes_sent : int
  ; bytes_recv : int
  ; sacks_sent : int
  ; sacks_recv : int
  ; retransmissions : int
  ; fast_retransmissions : int
  }

(** Mutable stats for internal use (single-threaded performance) *)
type mutable_stats =
  { mutable ms_messages_sent : int
  ; mutable ms_messages_recv : int
  ; mutable ms_bytes_sent : int
  ; mutable ms_bytes_recv : int
  ; mutable ms_sacks_sent : int
  ; mutable ms_sacks_recv : int
  ; mutable ms_retransmissions : int
  ; mutable ms_fast_retransmissions : int
  }

(** {1 Core State} *)

(** SCTP state machine (abstract) *)
type t

(** {1 Creation} *)

(** [create ?config ?initial_tsn ?my_vtag ?peer_vtag ?src_port ?dst_port ()]
    creates a new SCTP state machine.

    @param config SCTP configuration (default: Sctp.default_config)
    @param initial_tsn Starting TSN (random if not specified)
    @param my_vtag Our verification tag (random if not specified)
    @param peer_vtag Peer's verification tag (0 until learned)
    @param src_port Source port (default: 5000)
    @param dst_port Destination port (default: 5000) *)
val create
  :  ?config:Sctp.config
  -> ?initial_tsn:int32
  -> ?my_vtag:int32
  -> ?peer_vtag:int32
  -> ?src_port:int
  -> ?dst_port:int
  -> unit
  -> t

(** {1 Main Interface} *)

(** [handle t input] processes an input event and returns output actions.

    This is the main entry point. Call this for:
    - Incoming packets
    - Timer expirations
    - Application send requests
    - Close requests

    @return List of actions for I/O layer to execute *)
val handle : t -> input -> output list

(** [poll_transmit t] returns list of packets ready to send.

    Flushes pending SACK and bundled DATA chunks.
    Uses chunk bundling for efficiency.

    @return List of SendPacket outputs (may be empty) *)
val poll_transmit : t -> output list

(** [has_pending_transmit t] returns true if there's data ready to send. *)
val has_pending_transmit : t -> bool

(** {1 State Queries} *)

(** [get_conn_state t] returns current connection state. *)
val get_conn_state : t -> conn_state

(** [get_stats t] returns immutable snapshot of statistics. *)
val get_stats : t -> stats

(** [get_stats_raw t] returns raw mutable stats (for perf-critical code). *)
val get_stats_raw : t -> mutable_stats

(** [is_established t] returns true if connection is ready for data. *)
val is_established : t -> bool

(** [can_send t] returns true if congestion window allows sending. *)
val can_send : t -> bool

(** {1 Connection Initiation} *)

(** [initiate t] starts SCTP association (client side).

    RFC 4960 §5 4-way handshake:
    1. Generates INIT chunk with random vtag and TSN
    2. Transitions to CookieWait state
    3. Returns SendPacket with INIT chunk

    The INIT-ACK, COOKIE-ECHO, and COOKIE-ACK are processed
    automatically in [handle] when received. *)
val initiate : t -> output list

(** [initiate_direct t] directly transitions to Established state.

    Legacy function for testing without 4-way handshake.
    Use [initiate] for RFC-compliant connection establishment. *)
val initiate_direct : t -> output list

(** {1 Congestion Control Metrics} *)

(** [get_cwnd t] returns current congestion window size. *)
val get_cwnd : t -> int

(** [get_ssthresh t] returns slow-start threshold. *)
val get_ssthresh : t -> int

(** [get_flight_size t] returns bytes currently in flight. *)
val get_flight_size : t -> int

(** [get_rto t] returns current retransmission timeout in ms. *)
val get_rto : t -> float

(** {1 Time Management} *)

(** [set_now t timestamp] sets current time for deterministic testing.

    Call this before processing events to advance time. *)
val set_now : t -> float -> unit

(** [get_now t] returns current timestamp used by state machine. *)
val get_now : t -> float

(** {1 Debug Utilities} *)

(** Convert timer ID to string. *)
val string_of_timer : timer_id -> string

(** Convert connection state to string. *)
val string_of_conn_state : conn_state -> string

(** Pretty-print output action. *)
val pp_output : Format.formatter -> output -> unit

(** Pretty-print statistics. *)
val pp_stats : Format.formatter -> stats -> unit

(** Pretty-print mutable statistics. *)
val pp_mutable_stats : Format.formatter -> mutable_stats -> unit
