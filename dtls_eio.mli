(** Eio-based DTLS Transport

    Bridges the Sans-IO DTLS implementation (dtls.ml) with Eio's
    fiber-based concurrency for actual network I/O and timer management.

    Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    Application Layer                        │
    │              (encrypt/decrypt application data)             │
    ├─────────────────────────────────────────────────────────────┤
    │                  Dtls_eio (this module)                     │
    │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
    │   │Handshake Fib │  │ Timer Fiber  │  │ Recv Fiber   │     │
    │   └──────────────┘  └──────────────┘  └──────────────┘     │
    ├─────────────────────────────────────────────────────────────┤
    │               Dtls.t (Sans-IO State Machine)                │
    ├─────────────────────────────────────────────────────────────┤
    │                     UDP Transport                           │
    └─────────────────────────────────────────────────────────────┘

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

type send_fn = bytes -> unit
type recv_fn = unit -> bytes option

type t =
  { dtls : Dtls.t
  ; mutable send_fn : send_fn option
  ; mutable recv_fn : recv_fn option
  ; mutable retransmit_deadline : float option
  ; mutable on_handshake_complete : (unit -> unit) option
  ; mutable on_data : (bytes -> unit) option
  ; mutable on_error : (string -> unit) option
  }

val create_client : unit -> t
val create_server : unit -> t
val set_transport : t -> send:send_fn -> recv:recv_fn -> unit
val on_handshake_complete : t -> (unit -> unit) -> unit
val on_data : t -> (bytes -> unit) -> unit
val on_error : t -> (string -> unit) -> unit
val is_established : t -> bool
val get_state : t -> Dtls.state
val get_cipher_suite : t -> Dtls.cipher_suite option
val make_io_ops : clock:[> float Eio.Time.clock_ty ] Eio.Time.clock -> Dtls.io_ops
val send_records : t -> bytes list -> unit
val handshake_client : t -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock -> unit

val handle_record
  :  t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock
  -> bytes
  -> unit

val handle_record_server
  :  t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock
  -> client_addr:string * int
  -> bytes
  -> unit

val check_retransmit : t -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock -> unit
val send : t -> bytes -> (int, string) result
val decrypt : t -> bytes -> (bytes, string) result
val tick : t -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock -> unit

val run_client_handshake
  :  t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock
  -> timeout_s:float
  -> (unit, string) result

val run_server_handshake
  :  t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock
  -> client_addr:string * int
  -> timeout_s:float
  -> (unit, string) result

val run
  :  t
  -> sw:Eio.Switch.t
  -> clock:[> float Eio.Time.clock_ty ] Eio.Time.clock
  -> role:[< `Client | `Server ]
  -> client_addr:string * int
  -> on_established:(unit -> unit)
  -> unit

val export_keying_material
  :  t
  -> label:string
  -> context:bytes option
  -> length:int
  -> (bytes, string) result
