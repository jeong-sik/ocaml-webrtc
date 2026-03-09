(** Eio-based ICE Agent

    Bridges the Sans-IO ICE implementation (ice.ml, ice_check.ml) with
    Eio's fiber-based concurrency for actual network I/O.

    This implementation uses Unix UDP sockets in non-blocking mode,
    which integrates well with Eio's fiber scheduler.

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

type t =
  { agent : Ice.agent
  ; mutable socket : Unix.file_descr option
  ; recv_buffer : bytes
  ; mutable on_candidate : (Ice.candidate -> unit) option
  ; mutable on_state_change : (Ice.connection_state -> unit) option
  ; mutable on_gathering_complete : (unit -> unit) option
  ; mutable on_data : (bytes -> unit) option
  }

val create : ?config:Ice.config -> unit -> t
val on_candidate : t -> (Ice.candidate -> unit) -> unit
val on_state_change : t -> (Ice.connection_state -> unit) -> unit
val on_gathering_complete : t -> (unit -> unit) -> unit
val on_data : t -> (bytes -> unit) -> unit
val get_state : t -> Ice.connection_state
val get_gathering_state : t -> Ice.gathering_state
val get_local_candidates : t -> Ice.candidate list
val get_remote_candidates : t -> Ice.candidate list
val get_local_credentials : t -> string * string
val get_nominated_pair : t -> Ice.candidate_pair option
val create_socket : host:string -> port:int -> Unix.file_descr

val send_udp
  :  Unix.file_descr
  -> data:bytes
  -> host:string
  -> port:int
  -> (unit, string) result

val recv_udp : Unix.file_descr -> buf:bytes -> bytes option

val gather_srflx
  :  t
  -> stun_server:string
  -> local_addr:string
  -> local_port:int
  -> Ice.candidate option

val start_gathering : t -> clock:'a -> unit
val add_remote_candidate : t -> Ice.candidate -> unit
val set_remote_credentials : t -> ufrag:string -> pwd:string -> unit
val send : t -> bytes -> (unit, string) result
val try_recv : t -> bytes option
val run_checks : t -> clock:'a -> unit
val run : t -> sw:'b -> net:'c -> clock:'d -> on_connected:(unit -> 'e) -> 'e
val close : t -> unit
