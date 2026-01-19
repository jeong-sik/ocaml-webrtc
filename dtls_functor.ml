(** DTLS Functor - Swappable Transport Implementation

    Wrap DTLS I/O with functor for compile-time transport selection.
    Keeps existing Dtls module logic, just swaps transport layer.

    {1 Usage}

    {[
      (* Testing with Mock *)
      module Dtls_Test = Make(Transport_intf.Mock_transport)
      let t = Transport_intf.mock_create () in
      let io_ops = Dtls_Test.to_io_ops t in
      Dtls.run_with_io ~ops:io_ops (fun () -> ...)
    ]}

    @since ocaml-webrtc 0.6.0
*)

open Transport_intf

(** Create io_ops from any TRANSPORT module *)
module Make (T : TRANSPORT) = struct
  type transport = T.t

  (** Convert transport to Dtls.io_ops *)
  let to_io_ops (t : transport) : Dtls.io_ops = {
    send = (fun data -> T.send t data);
    recv = (fun n -> T.recv t n);
    now = T.now;
    random = T.random;
    set_timer = (fun _ -> ());
    cancel_timer = (fun () -> ());
  }

  (** Run DTLS with this transport *)
  let run t f =
    Dtls.run_with_io ~ops:(to_io_ops t) f
end

(** Pre-instantiated for convenience *)
module With_Mock = Make(Mock_transport)
module With_Lwt = Make(Lwt_transport)
module With_Eio = Make(Eio_transport)
