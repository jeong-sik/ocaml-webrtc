(** Eio-compatible UDP Transport Layer

    Wraps Unix non-blocking UDP socket for use with Eio fibers.
    The underlying socket is non-blocking, allowing cooperative
    scheduling between fibers via Eio.Fiber.yield().

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

type endpoint = Udp_transport.endpoint =
  { host : string
  ; port : int
  }

type stats = Udp_transport.stats =
  { mutable packets_sent : int
  ; mutable packets_recv : int
  ; mutable bytes_sent : int
  ; mutable bytes_recv : int
  ; mutable send_errors : int
  ; mutable recv_errors : int
  }

(** Opaque transport handle *)
type t

val create_stats : unit -> stats
val get_stats : t -> stats
val create : ?host:string -> ?port:int -> unit -> t
val bind : t -> host:string -> port:int -> unit
val connect : t -> host:string -> port:int -> unit
val local_endpoint : t -> endpoint
val remote_endpoint : t -> endpoint option
val send : t -> data:bytes -> host:string -> port:int -> (int, string) result
val send_connected : t -> data:bytes -> (int, string) result
val send_view : t -> buf:bytes -> off:int -> len:int -> (int, string) result
val recv : t -> buf:bytes -> (int * endpoint, string) result
val recv_timeout : t -> buf:bytes -> timeout_ms:int -> (int * endpoint, string) result
val close : t -> unit
val is_closed : t -> bool
val pp_endpoint : Format.formatter -> endpoint -> unit
val pp_stats : Format.formatter -> stats -> unit
val send_yield : t -> data:bytes -> host:string -> port:int -> (int, string) result
val send_connected_yield : t -> data:bytes -> (int, string) result
val recv_yield : t -> buf:bytes -> (int * endpoint, string) result
val recv_poll : t -> buf:bytes -> max_attempts:int -> (int * endpoint, string) result
