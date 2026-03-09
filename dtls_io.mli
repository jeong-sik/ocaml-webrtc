(** DTLS I/O Operations and Effect Handler

    Default I/O implementation and the Effect handler that bridges
    DTLS effect-based code with concrete I/O implementations.

    @author Second Brain
    @since ocaml-webrtc 0.2.2
*)

val default_io_ops : Dtls_types.io_ops
val run_with_io : ops:Dtls_types.io_ops -> (unit -> 'a) -> 'a
val run_with_eio : net:'a -> clock:'b -> (unit -> 'c) -> 'c
