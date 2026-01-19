(** Transport Interface - Minimal Functor Abstraction

    Simple module types for swappable I/O implementations.
    NOT over-engineered - just the essentials for testing and production.

    @since ocaml-webrtc 0.6.0
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

module Mock_transport : TRANSPORT with type t = mock_t = struct
  type t = mock_t

  let send t data =
    t.send_queue <- data :: t.send_queue;
    Bytes.length data

  let recv t n =
    match t.recv_queue with
    | [] -> Bytes.create 0
    | hd :: tl ->
      t.recv_queue <- tl;
      if Bytes.length hd <= n then hd
      else Bytes.sub hd 0 n

  let now () = Unix.gettimeofday ()

  let random n =
    Bytes.of_string (Mirage_crypto_rng.generate n)
end

let mock_create () : mock_t =
  { send_queue = []; recv_queue = [] }

let mock_inject (t : mock_t) data =
  t.recv_queue <- t.recv_queue @ [data]

let mock_drain (t : mock_t) =
  let q = List.rev t.send_queue in
  t.send_queue <- [];
  q

(** {1 Lwt Transport} *)

module Lwt_transport : sig
  include TRANSPORT
  val create : host:string -> port:int -> t Lwt.t
end = struct
  type t = {
    sock: Lwt_unix.file_descr;
    mutable remote: Unix.sockaddr option;
  }

  let create ~host ~port =
    let open Lwt.Syntax in
    let sock = Lwt_unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    let addr = Unix.ADDR_INET (Unix.inet_addr_of_string host, port) in
    let+ () = Lwt_unix.connect sock addr in
    { sock; remote = Some addr }

  let send t data =
    match t.remote with
    | Some _ ->
      Unix.send (Lwt_unix.unix_file_descr t.sock) data 0 (Bytes.length data) []
    | None -> 0

  let recv t n =
    let buf = Bytes.create n in
    let len = Unix.recv (Lwt_unix.unix_file_descr t.sock) buf 0 n [] in
    Bytes.sub buf 0 len

  let now () = Unix.gettimeofday ()

  let random n =
    Bytes.of_string (Mirage_crypto_rng.generate n)
end

(** {1 Eio Transport (OCaml 5 native)} *)

module Eio_transport : sig
  include TRANSPORT
  val create : host:string -> port:int -> t
  val connect : t -> host:string -> port:int -> unit
end = struct
  type t = Eio_udp_transport.t

  let create ~host ~port =
    Eio_udp_transport.create ~host ~port ()

  let connect t ~host ~port =
    Eio_udp_transport.connect t ~host ~port

  let send t data =
    match Eio_udp_transport.send_connected_yield t ~data with
    | Ok n -> n
    | Error _ -> 0

  let recv t n =
    let buf = Bytes.create n in
    match Eio_udp_transport.recv_yield t ~buf with
    | Ok (len, _endpoint) -> Bytes.sub buf 0 len
    | Error _ -> Bytes.empty

  let now () = Unix.gettimeofday ()

  let random n =
    Bytes.of_string (Mirage_crypto_rng.generate n)
end
