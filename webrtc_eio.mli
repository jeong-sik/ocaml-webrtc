(** Eio-based WebRTC Full Stack

    Complete WebRTC stack using Eio for fiber-based concurrency.
    Integrates ICE, DTLS, and SCTP layers into a unified API.

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

(** {1 Types} *)

type role =
  | Client
  | Server

type connection_state =
  | New
  | Connecting
  | Connected
  | Disconnected
  | Failed
  | Closed

val pp_connection_state : Format.formatter -> connection_state -> unit
val equal_connection_state : connection_state -> connection_state -> bool
val show_connection_state : connection_state -> string

type datachannel =
  { id : int
  ; label : string
  ; mutable on_message : (bytes -> unit) option
  ; mutable on_open : (unit -> unit) option
  ; mutable on_close : (unit -> unit) option
  }

type t =
  { role : role
  ; mutable state : connection_state
  ; ice : Ice_eio.t
  ; dtls : Dtls_eio.t
  ; sctp : Sctp_core.t
  ; mutable channels : datachannel list
  ; mutable next_channel_id : int
  ; recv_buffer : bytes
  ; mutable on_state_change : (connection_state -> unit) option
  ; mutable on_datachannel : (datachannel -> unit) option
  ; mutable on_ice_candidate : (Ice.candidate -> unit) option
  }

(** {1 Creation} *)

val default_ice_config : Ice.config
val create : ?ice_config:Ice.config -> role:role -> unit -> t

(** {1 Callbacks} *)

val on_state_change : t -> (connection_state -> unit) -> unit
val on_datachannel : t -> (datachannel -> unit) -> unit
val on_ice_candidate : t -> (Ice.candidate -> unit) -> unit

(** {1 State Access} *)

val get_state : t -> connection_state
val get_local_candidates : t -> Ice.candidate list
val get_local_credentials : t -> string * string

(** {1 DataChannel API} *)

val create_datachannel : t -> label:string -> datachannel
val send_channel : t -> datachannel -> bytes -> (int, string) result

(** {1 Signaling Integration} *)

val add_ice_candidate : t -> Ice.candidate -> unit
val set_remote_credentials : t -> ufrag:string -> pwd:string -> unit

(** {1 Connection Lifecycle} *)

val connect
  :  t
  -> sw:Eio.Switch.t
  -> net:_ Eio.Net.ty Eio.Resource.t
  -> clock:float Eio.Time.clock_ty Eio.Resource.t
  -> unit

val run_event_loop
  :  t
  -> sw:Eio.Switch.t
  -> clock:float Eio.Time.clock_ty Eio.Resource.t
  -> unit

val run
  :  t
  -> sw:Eio.Switch.t
  -> net:_ Eio.Net.ty Eio.Resource.t
  -> clock:float Eio.Time.clock_ty Eio.Resource.t
  -> unit

val close : t -> unit

(** {1 Convenience: Simple API} *)

val run_peer
  :  env:
       < clock : float Eio.Time.clock_ty Eio.Resource.t
       ; net : [> [> `Generic ] Eio.Net.ty ] Eio.Resource.t
       ; .. >
  -> role:role
  -> on_channel:(datachannel -> unit)
  -> on_message:(datachannel -> bytes -> unit)
  -> t
