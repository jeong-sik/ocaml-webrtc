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

val set_clock : float Eio.Time.clock_ty Eio.Resource.t -> unit
val clear_clock : unit -> unit
val has_clock : unit -> bool
val now : unit -> float
val now_ms : unit -> int
val now_us : unit -> int64
val sleep : float -> unit
val timed : (unit -> 'a) -> 'a * float
val timed_ms : (unit -> 'a) -> 'a * int
