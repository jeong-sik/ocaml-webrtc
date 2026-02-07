(** Transport Interface - Minimal Functor Abstraction

    Simple module types for swappable I/O implementations.
    NOT over-engineered - just the essentials for testing and production.

    @since ocaml-webrtc 0.1.0
*)

(** {1 Core Transport Interface} *)

(** Minimal transport operations for DTLS/ICE *)
module type TRANSPORT = sig
  type t

  (** Send data, returns bytes sent *)
  val send : t -> bytes -> int

  (** Receive up to N bytes *)
  val recv : t -> int -> bytes

  (** Current timestamp *)
  val now : unit -> float

  (** Generate N cryptographically secure random bytes *)
  val random : int -> bytes
end

(** Timer operations (optional, for retransmission) *)
module type TIMER = sig
  (** Set timer with callback after ms *)
  val set : int -> (unit -> unit) -> unit

  (** Cancel pending timer *)
  val cancel : unit -> unit
end

(** {1 Mock Transport for Testing} *)

type mock_t =
  { mutable send_queue : bytes list
  ; mutable recv_queue : bytes list
  }

module Mock_transport : TRANSPORT with type t = mock_t = struct
  type t = mock_t

  let send t data =
    t.send_queue <- data :: t.send_queue;
    Bytes.length data
  ;;

  let recv t n =
    match t.recv_queue with
    | [] -> Bytes.create 0
    | hd :: tl ->
      t.recv_queue <- tl;
      if Bytes.length hd <= n then hd else Bytes.sub hd 0 n
  ;;

  let now () = Unix.gettimeofday ()
  let random n = Bytes.of_string (Mirage_crypto_rng.generate n)
end

let mock_create () : mock_t = { send_queue = []; recv_queue = [] }
let mock_inject (t : mock_t) data = t.recv_queue <- t.recv_queue @ [ data ]

let mock_drain (t : mock_t) =
  let q = List.rev t.send_queue in
  t.send_queue <- [];
  q
;;

(** {1 Eio Transport (OCaml 5 native)} *)

module Eio_transport : sig
  include TRANSPORT

  val create : host:string -> port:int -> t
  val connect : t -> host:string -> port:int -> unit
end = struct
  type t = Eio_udp_transport.t

  let create ~host ~port = Eio_udp_transport.create ~host ~port ()
  let connect t ~host ~port = Eio_udp_transport.connect t ~host ~port

  let send t data =
    match Eio_udp_transport.send_connected_yield t ~data with
    | Ok n -> n
    | Error _ -> 0
  ;;

  let recv t n =
    let buf = Bytes.create n in
    match Eio_udp_transport.recv_yield t ~buf with
    | Ok (len, _endpoint) -> Bytes.sub buf 0 len
    | Error _ -> Bytes.empty
  ;;

  let now () = Unix.gettimeofday ()
  let random n = Bytes.of_string (Mirage_crypto_rng.generate n)
end
