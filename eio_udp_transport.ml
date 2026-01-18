(** Eio-compatible UDP Transport Layer

    Wraps Unix non-blocking UDP socket for use with Eio fibers.
    The underlying socket is non-blocking, allowing cooperative
    scheduling between fibers via Eio.Fiber.yield().

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** This module re-exports Udp_transport for Eio compatibility.
    The Unix socket is already set to non-blocking mode,
    which works well with Eio's fiber-based concurrency. *)

include Udp_transport

(** Additional Eio-friendly helpers *)

(** Yield-aware send - yields to other fibers if would block *)
let send_yield t ~data ~host ~port =
  match send t ~data ~host ~port with
  | Error "Would block" ->
    Eio.Fiber.yield ();
    send t ~data ~host ~port
  | result -> result

(** Yield-aware connected send *)
let send_connected_yield t ~data =
  match send_connected t ~data with
  | Error "Would block" ->
    Eio.Fiber.yield ();
    send_connected t ~data
  | result -> result

(** Yield-aware recv - yields if no data available *)
let recv_yield t ~buf =
  match recv t ~buf with
  | Error "Would block" ->
    Eio.Fiber.yield ();
    recv t ~buf
  | result -> result

(** Polling recv with yield - tries multiple times with yield between *)
let recv_poll t ~buf ~max_attempts =
  let rec loop n =
    if n <= 0 then Error "No data"
    else match recv t ~buf with
      | Error "Would block" ->
        Eio.Fiber.yield ();
        loop (n - 1)
      | result -> result
  in
  loop max_attempts
