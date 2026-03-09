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

    @since ocaml-webrtc 0.1.0
*)

module Make : functor (T : Transport_intf.TRANSPORT) -> sig
  type transport = T.t

  val to_io_ops : transport -> Dtls.io_ops
  val run : transport -> (unit -> 'a) -> 'a
end

module With_Mock : sig
  type transport = Transport_intf.Mock_transport.t

  val to_io_ops : transport -> Dtls.io_ops
  val run : transport -> (unit -> 'a) -> 'a
end

module With_Eio : sig
  type transport = Transport_intf.Eio_transport.t

  val to_io_ops : transport -> Dtls.io_ops
  val run : transport -> (unit -> 'a) -> 'a
end
