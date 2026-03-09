(** UDP Transport Layer

    Provides actual network I/O for WebRTC using Eio.
    This is the real transport layer that sends/receives UDP packets.

    @author Second Brain
    @since ocaml-webrtc 0.3.0
*)

type endpoint =
  { host : string
  ; port : int
  }

type stats =
  { mutable packets_sent : int
  ; mutable packets_recv : int
  ; mutable bytes_sent : int
  ; mutable bytes_recv : int
  ; mutable send_errors : int
  ; mutable recv_errors : int
  }

type t =
  { socket : Unix.file_descr
  ; local_endpoint : endpoint
  ; mutable remote_endpoint : endpoint option
  ; mutable remote_sockaddr : Unix.sockaddr option
  ; stats : stats
  ; mutable closed : bool
  }

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
