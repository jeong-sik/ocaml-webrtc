(** DTLS Retransmission — RFC 6347 Section 4.2.4 flight-based reliability

    Implements exponential backoff retransmission for DTLS handshake flights.
    Extracted from dtls.ml for modularity.

    RFC 6347 Section 4.2.4:
    "If the timer expires, the implementation retransmits the flight,
     resets the timer, and doubles the timeout value."

    @author Second Brain
    @since ocaml-webrtc 0.2.2
*)

open Dtls_types

(** Maximum retransmit timeout per RFC 6347 (60 seconds) *)
let max_retransmit_timeout_ms = 60000

(** Calculate next timeout with exponential backoff.
    Timeout doubles on each retransmit, capped at 60 seconds. *)
let next_retransmit_timeout current_ms = min (current_ms * 2) max_retransmit_timeout_ms

(** Store a flight for potential retransmission.
    Called after sending a handshake flight. *)
let store_flight (t : t) (flight : bytes list) =
  let now = Effect.perform Now in
  t.retransmit.last_flight <- flight;
  t.retransmit.retransmit_count <- 0;
  t.retransmit.current_timeout_ms <- t.config.retransmit_timeout_ms;
  t.retransmit.flight_sent_at <- now;
  t.retransmit.timer_active <- true;
  Effect.perform (SetTimer t.retransmit.current_timeout_ms)
;;

(** Clear retransmission state when handshake progresses.
    Called when a valid response is received. *)
let clear_retransmit (t : t) =
  if t.retransmit.timer_active
  then (
    Effect.perform CancelTimer;
    t.retransmit.timer_active <- false);
  t.retransmit.last_flight <- [];
  t.retransmit.retransmit_count <- 0;
  t.retransmit.current_timeout_ms <- t.config.retransmit_timeout_ms
;;

(** Handle retransmission timer expiry.
    Returns the flight to retransmit, or Error if max retransmits exceeded. *)
let handle_retransmit_timeout (t : t) : (bytes list, string) result =
  if not t.retransmit.timer_active
  then Ok []
  else if t.retransmit.retransmit_count >= t.config.max_retransmits
  then (
    t.retransmit.timer_active <- false;
    t.state <- Error "Handshake timeout: max retransmits exceeded";
    Error "Max retransmits exceeded")
  else (
    t.retransmit.retransmit_count <- t.retransmit.retransmit_count + 1;
    t.retransmit.current_timeout_ms
    <- next_retransmit_timeout t.retransmit.current_timeout_ms;
    t.retransmit.flight_sent_at <- Effect.perform Now;
    Effect.perform (SetTimer t.retransmit.current_timeout_ms);
    Ok t.retransmit.last_flight)
;;

(** Check if retransmission is needed based on elapsed time.
    Useful for polling-based timer implementations. *)
let check_retransmit_needed (t : t) : bool =
  if not t.retransmit.timer_active
  then false
  else (
    let now = Effect.perform Now in
    let elapsed_ms = int_of_float ((now -. t.retransmit.flight_sent_at) *. 1000.0) in
    elapsed_ms >= t.retransmit.current_timeout_ms)
;;

(** Get current retransmission state for debugging/monitoring.
    Returns (retransmit_count, current_timeout_ms, timer_active). *)
let get_retransmit_state (t : t) =
  ( t.retransmit.retransmit_count
  , t.retransmit.current_timeout_ms
  , t.retransmit.timer_active )
;;
