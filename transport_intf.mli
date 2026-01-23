(** Transport Interface - Minimal Functor Abstraction

    Simple module types for swappable I/O implementations.
    NOT over-engineered - just the essentials for testing and production.

    {1 Usage}

    {[
      (* Testing with Mock *)
      let t = Transport_intf.mock_create () in
      Transport_intf.mock_inject t test_data;
      let received = Transport_intf.Mock_transport.recv t 1500 in
      ...

      (* Production with Lwt *)
      let%lwt t = Transport_intf.Lwt_transport.create ~host:"8.8.8.8" ~port:3478 in
      let sent = Transport_intf.Lwt_transport.send t data in
      ...
    ]}

    @since ocaml-webrtc 0.1.0
*)

(** {1 Core Transport Interface} *)

(** Minimal transport operations for DTLS/ICE *)
module type TRANSPORT = sig
  type t

  val send : t -> bytes -> int
  (** Send data, returns bytes sent *)

  val recv : t -> int -> bytes
  (** Receive up to N bytes *)

  val now : unit -> float
  (** Current timestamp *)

  val random : int -> bytes
  (** Generate N cryptographically secure random bytes *)
end

(** Timer operations (optional, for retransmission) *)
module type TIMER = sig
  val set : int -> (unit -> unit) -> unit
  (** Set timer with callback after ms *)

  val cancel : unit -> unit
  (** Cancel pending timer *)
end

(** {1 Mock Transport for Testing} *)

type mock_t = {
  mutable send_queue: bytes list;
  mutable recv_queue: bytes list;
}

module Mock_transport : TRANSPORT with type t = mock_t

val mock_create : unit -> mock_t
(** Create empty mock transport *)

val mock_inject : mock_t -> bytes -> unit
(** Inject data to be received *)

val mock_drain : mock_t -> bytes list
(** Drain all sent data *)

(** {1 Lwt Transport} *)

module Lwt_transport : sig
  include TRANSPORT
  val create : host:string -> port:int -> t Lwt.t
end

(** {1 Eio Transport (OCaml 5 native)} *)

module Eio_transport : sig
  include TRANSPORT
  val create : host:string -> port:int -> t
  val connect : t -> host:string -> port:int -> unit
end
