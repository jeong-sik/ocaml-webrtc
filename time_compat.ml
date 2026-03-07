(** Time Compatibility Layer - Eio-native timestamps with fallback

    Provides a unified timestamp API for gradual migration from
    Unix.gettimeofday to Eio.Time.now.

    Usage:
    1. At server startup: [Time_compat.set_clock (Eio.Stdenv.clock env)]
    2. In code: [Time_compat.now ()] instead of [Unix.gettimeofday ()]

    When clock is not set (non-Eio contexts), falls back to Unix.gettimeofday.
    This allows incremental migration without changing all call sites at once.

    @since 2026-02 - Async blocking pattern fixes
*)

(** Global clock reference - set at Eio_main.run startup *)
let global_clock : float Eio.Time.clock_ty Eio.Resource.t option ref = ref None

(** Set the global Eio clock. Call once at server startup.
    @param clock The Eio clock from [Eio.Stdenv.clock env] *)
let set_clock clock =
  global_clock := Some clock

(** Clear the global clock (for testing or shutdown) *)
let clear_clock () =
  global_clock := None

(** Check if Eio clock is available *)
let has_clock () =
  Option.is_some !global_clock

(** Get current timestamp (Eio-native when available, fallback to Unix)

    When Eio clock is set via [set_clock], uses [Eio.Time.now] which
    properly yields to the scheduler. Otherwise falls back to
    [Unix.gettimeofday] for backward compatibility.

    @return Current Unix timestamp as float (seconds since epoch) *)
let now () =
  match !global_clock with
  | Some clock -> Eio.Time.now clock
  | None -> Unix.gettimeofday ()

(** Get current timestamp in milliseconds (integer) *)
let now_ms () =
  int_of_float (now () *. 1000.0)

(** Get current timestamp in microseconds (integer) *)
let now_us () =
  Int64.of_float (now () *. 1_000_000.0)

(** Sleep for given duration (Eio-native when available)

    @param seconds Duration to sleep *)
let sleep seconds =
  match !global_clock with
  | Some clock -> Eio.Time.sleep clock seconds
  | None -> Unix.sleepf seconds

(** Measure execution time of a function

    @param f Function to measure
    @return (result, duration_seconds) *)
let timed f =
  let start = now () in
  let result = f () in
  let duration = now () -. start in
  (result, duration)

(** Measure execution time and return duration in milliseconds *)
let timed_ms f =
  let (result, duration) = timed f in
  (result, int_of_float (duration *. 1000.0))
