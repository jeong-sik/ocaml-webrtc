# OCaml SCTP API Reference

## High-Level API: `Eio_sctp_full_transport`

Use this module for typical application development with Eio.

### Creation and Connection

```ocaml
val create :
  ?config:Sctp.config ->
  ?initial_tsn:int32 ->
  host:string ->
  port:int ->
  unit -> t
(** Create a new SCTP transport bound to host:port *)

val connect : t -> host:string -> port:int -> unit
(** Connect to a remote peer *)

val close : t -> unit
(** Gracefully close the connection *)

val is_closed : t -> bool
(** Check if connection is closed *)
```

### Data Transfer

```ocaml
val send_data : t -> stream_id:int -> data:bytes -> int
(** Send data on a stream. Returns bytes sent.
    Blocks if congestion window is full. *)

val try_send_data : t -> stream_id:int -> data:bytes -> (int, string) result
(** Non-blocking send. Returns Error if cwnd full. *)

val tick : t -> unit
(** Process incoming packets and timers.
    Call this in your main loop. *)
```

### Concurrent Operation

```ocaml
val run_sender : t -> get_data:(unit -> (int * bytes) option) -> unit
(** Run sender fiber. get_data returns (stream_id, data) or None to stop. *)

val run_receiver : t -> on_data:(int -> bytes -> unit) -> unit
(** Run receiver fiber. on_data is called for each received message. *)

val run_timer : t -> clock:Eio.Time.clock -> interval_ms:float -> unit
(** Run timer fiber for retransmissions. *)

val run_concurrent :
  t ->
  clock:Eio.Time.clock ->
  get_data:(unit -> (int * bytes) option) ->
  on_data:(int -> bytes -> unit) ->
  unit
(** Run all fibers concurrently. Recommended for typical use. *)
```

### Statistics

```ocaml
type stats = {
  messages_sent: int;
  messages_recv: int;
  bytes_sent: int;
  bytes_recv: int;
  retransmissions: int;
  fast_retransmissions: int;
  sacks_sent: int;
  sacks_recv: int;
}

val get_stats : t -> stats
(** Get transport statistics *)

val get_cwnd : t -> int
(** Get current congestion window size *)

val get_flight_size : t -> int
(** Get bytes currently in flight *)

val get_rto : t -> float
(** Get current retransmission timeout *)
```

---

## Sans-IO Core: `Sctp_core`

Use this module for custom I/O implementations or testing.

### Types

```ocaml
type input =
  | PacketReceived of bytes       (** Raw packet from network *)
  | TimerFired of timer_id        (** Timer expired *)
  | UserSend of { stream_id: int; data: bytes }  (** User wants to send *)
  | UserResetStreams of { stream_ids: int list } (** Stream reset (RFC 6525) *)
  | UserClose                     (** User wants to close *)

type output =
  | SendPacket of bytes           (** Send this to network *)
  | DeliverData of { stream_id: int; data: bytes }  (** Deliver to user *)
  | SetTimer of { timer: timer_id; delay_ms: float }  (** Set a timer *)
  | CancelTimer of timer_id       (** Cancel a timer *)
  | ConnectionEstablished         (** Connection ready *)
  | ConnectionClosed              (** Connection ended *)
  | Error of string               (** Error occurred *)

type timer_id = T3Rtx | DelayedAck | Heartbeat | Shutdown

type conn_state =
  | Closed | CookieWait | CookieEchoed | Established
  | ShutdownPending | ShutdownSent | ShutdownReceived
  | ShutdownAckSent
```

### Core Function

```ocaml
val create : ?config:Sctp.config -> unit -> t
(** Create a new SCTP state machine *)

val handle : t -> input -> output list
(** THE core function: process input, return outputs.
    This is a PURE function with no side effects.

    Example:
    let outputs = Sctp_core.handle core (PacketReceived packet) in
    List.iter (execute_output socket) outputs
*)

val poll_transmit : t -> output list
(** Flush any pending transmissions.
    Call after handle() to ensure all data is sent. *)

val has_pending_transmit : t -> bool
(** Check if poll_transmit would return non-empty *)
```

### State Queries

```ocaml
val get_conn_state : t -> conn_state
val is_established : t -> bool
val can_send : t -> bool
val get_stats : t -> stats
```

### Testing Support

```ocaml
val set_now : t -> float -> unit
(** Set current time (for deterministic testing) *)

val get_now : t -> float
(** Get current time *)
```

---

## Chunk Encoding: `Sctp`

Low-level chunk encoding/decoding.

### Data Chunk

```ocaml
type data_flags = {
  end_fragment: bool;     (** E bit - last fragment *)
  begin_fragment: bool;   (** B bit - first fragment *)
  unordered: bool;        (** U bit - unordered delivery *)
  immediate: bool;        (** I bit - immediate transmission *)
}

type data_chunk = {
  flags: data_flags;
  tsn: int32;
  stream_id: int;
  stream_seq: int;
  ppid: int32;
  user_data: bytes;
}

val encode_data_chunk : data_chunk -> bytes
(** Encode a DATA chunk *)

val encode_data_chunk_into : buf:bytes -> off:int -> data_chunk -> int
(** Zero-copy encode into existing buffer. Returns bytes written. *)

val decode_data_chunk : bytes -> (data_chunk, string) result
(** Decode a DATA chunk *)
```

### Fragmentation

```ocaml
val fragment_data :
  data:bytes ->
  stream_id:int ->
  stream_seq:int ->
  ppid:int32 ->
  start_tsn:int32 ->
  mtu:int ->
  data_chunk list
(** Fragment large data into multiple chunks (RFC 4960 §6.9) *)
```

### Configuration

```ocaml
type config = {
  mtu: int;              (** Maximum Transmission Unit (default: 1280) *)
  a_rwnd: int;           (** Advertised Receiver Window *)
  max_retrans: int;      (** Maximum retransmissions *)
  rto_initial: float;    (** Initial RTO in seconds *)
  rto_min: float;        (** Minimum RTO *)
  rto_max: float;        (** Maximum RTO *)
}

val default_config : config
```

---

## Reliability: `Sctp_reliable`

Reliability layer with SACK handling.

```ocaml
type sack = {
  cumulative_tsn_ack: int32;
  a_rwnd: int;
  gap_blocks: gap_block list;
  dup_tsns: int32 list;
}

val create : ?config:Sctp.config -> unit -> t
val queue_data : t -> Sctp.data_chunk -> unit
val record_received : t -> int32 -> bool
val generate_sack : t -> sack
val process_sack : t -> sack -> now:float -> Sctp.data_chunk list
```

---

## Example: Custom I/O with Sans-IO

```ocaml
let run_custom_io socket =
  let core = Sctp_core.create () in

  (* Main loop *)
  while not (Sctp_core.get_conn_state core = Closed) do
    (* 1. Check for incoming packets *)
    match recv_packet socket with
    | Some packet ->
      let outputs = Sctp_core.handle core (PacketReceived packet) in
      List.iter (execute_output socket) outputs
    | None -> ()

    (* 2. Check timers *)
    List.iter (fun timer ->
      if timer_expired timer then
        let outputs = Sctp_core.handle core (TimerFired timer) in
        List.iter (execute_output socket) outputs
    ) [T3Rtx; DelayedAck; Heartbeat]

    (* 3. Flush pending *)
    let pending = Sctp_core.poll_transmit core in
    List.iter (execute_output socket) pending
  done

and execute_output socket = function
  | SendPacket bytes -> send_packet socket bytes
  | DeliverData { stream_id; data } -> deliver_to_app stream_id data
  | SetTimer { timer; delay_ms } -> schedule_timer timer delay_ms
  | CancelTimer timer -> cancel_timer timer
  | _ -> ()
```

---

## Build

```bash
dune build
```

## Test

```bash
# RFC compliance tests
dune exec ./test/rfc_compliance_test.exe

# Performance benchmarks (not published)
dune exec ./test/honest_benchmark.exe
dune exec ./test/bundling_benchmark.exe
```
