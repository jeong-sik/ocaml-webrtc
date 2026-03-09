(** DTLS I/O Operations and Effect Handler

    Default I/O implementation and the Effect handler that bridges
    DTLS effect-based code with concrete I/O implementations.

    @author Second Brain
    @since ocaml-webrtc 0.2.2
*)

open Effect.Deep
open Dtls_types

(** Default I/O ops using Unix time and Mirage_crypto RNG.
    send/recv are no-ops — suitable for testing only. *)
let default_io_ops : io_ops =
  { send = (fun _ -> 0)
  ; recv = (fun _ -> Bytes.empty)
  ; now = Time_compat.now
  ; random = (fun n -> Bytes.of_string (Mirage_crypto_rng.generate n))
  ; set_timer = (fun _ -> ())
  ; cancel_timer = (fun () -> ())
  }
;;

(** Run DTLS code with custom I/O operations.
    This is the primary API — works with any transport implementation.

    Example with Eio UDP socket:
    {[
      let ops = {
        send = (fun data -> Udp_socket_eio.send_to socket data remote);
        recv = (fun size ->
          let dgram = Udp_socket_eio.recv socket in
          Bytes.sub dgram.data 0 (min size (Bytes.length dgram.data)));
        now = Unix.gettimeofday;
        random = (fun n -> Bytes.of_string (Mirage_crypto_rng.generate n));
        set_timer = (fun ms -> Eio.Time.sleep clock (float ms /. 1000.0));
        cancel_timer = (fun () -> ());
      } in
      run_with_io ~ops (fun () -> do_handshake conn)
    ]}

    @param ops I/O operations (send, recv, now, random, set_timer, cancel_timer)
    @param f The DTLS function to run *)
let run_with_io ~(ops : io_ops) f =
  try_with
    f
    ()
    { effc =
        (fun (type a) (eff : a Effect.t) ->
          match eff with
          | Send data ->
            Some
              (fun (k : (a, _) continuation) ->
                let bytes_sent = ops.send data in
                continue k bytes_sent)
          | Recv size ->
            Some
              (fun (k : (a, _) continuation) ->
                let data = ops.recv size in
                continue k data)
          | Now -> Some (fun (k : (a, _) continuation) -> continue k (ops.now ()))
          | Random n -> Some (fun (k : (a, _) continuation) -> continue k (ops.random n))
          | SetTimer ms ->
            Some
              (fun (k : (a, _) continuation) ->
                ops.set_timer ms;
                continue k ())
          | CancelTimer ->
            Some
              (fun (k : (a, _) continuation) ->
                ops.cancel_timer ();
                continue k ())
          | _ -> None)
    }
;;

(** Legacy wrapper for backward compatibility.
    Uses default no-op I/O — prefer [run_with_io] for production. *)
let run_with_eio ~net:_ ~clock:_ f = run_with_io ~ops:default_io_ops f
