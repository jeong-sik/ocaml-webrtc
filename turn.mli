(** RFC 5766 TURN - Traversal Using Relays around NAT

    Pure OCaml implementation of TURN protocol for WebRTC.

    TURN provides a relay server for clients behind symmetric NAT
    that cannot establish direct peer-to-peer connections.

    Implements:
    - RFC 5766: TURN (core protocol)
    - RFC 6156: TURN extension for IPv6

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

(** {1 Types} *)

(** TURN methods (extension of STUN methods) *)
type turn_method =
  | Allocate          (** 0x003 - Request relay allocation *)
  | Refresh           (** 0x004 - Refresh existing allocation *)
  | Send              (** 0x006 - Send data indication *)
  | Data              (** 0x007 - Data indication from peer *)
  | CreatePermission  (** 0x008 - Create permission for peer *)
  | ChannelBind       (** 0x009 - Bind channel number to peer *)

(** TURN-specific attribute types *)
type turn_attribute =
  | CHANNEL_NUMBER        (** 0x000C *)
  | LIFETIME              (** 0x000D *)
  | XOR_PEER_ADDRESS      (** 0x0012 *)
  | DATA                  (** 0x0013 *)
  | XOR_RELAYED_ADDRESS   (** 0x0016 *)
  | EVEN_PORT             (** 0x0018 *)
  | REQUESTED_TRANSPORT   (** 0x0019 *)
  | DONT_FRAGMENT         (** 0x001A *)
  | RESERVATION_TOKEN     (** 0x0022 *)
  (* Authentication attributes - RFC 5389 Section 15.4 *)
  | USERNAME              (** 0x0006 *)
  | REALM                 (** 0x0014 *)
  | NONCE                 (** 0x0015 *)
  | MESSAGE_INTEGRITY     (** 0x0008 *)
  | ERROR_CODE            (** 0x0009 *)

(** Transport protocol for allocation *)
type transport =
  | UDP   (** 17 *)
  | TCP   (** 6 *)

(** Allocation state *)
type allocation_state =
  | Inactive
  | Allocating
  | Active of {
      relayed_address : string * int;  (** IP, port *)
      lifetime : int;                   (** seconds *)
      expiry : float;                   (** Unix timestamp *)
    }
  | Refreshing
  | Expired

(** Channel binding *)
type channel = {
  number : int;           (** 0x4000-0x7FFF *)
  peer_address : string * int;
  expiry : float;
}

(** TURN client configuration *)
type config = {
  server_host : string;
  server_port : int;
  username : string;
  password : string;
  realm : string;
  transport : transport;
  lifetime : int;         (** Requested lifetime in seconds *)
}

(** TURN client *)
type t

(** {1 I/O Effects}

    These effects allow custom runtimes or tests to provide TURN I/O. *)
type _ Effect.t +=
  | Send : (bytes * string * int) -> int Effect.t
  | Recv : int -> (bytes * string * int) Effect.t
  | Sleep : float -> unit Effect.t
  | Now : float Effect.t

(** {1 Client Creation} *)

(** Default configuration *)
val default_config : config

(** Create TURN client *)
val create : config -> t

(** {1 Allocation} *)

(** Request relay allocation from server.
    Returns relayed address (IP, port) on success. *)
val allocate : t -> (string * int, string) result

(** Refresh existing allocation.
    @param lifetime New lifetime in seconds (0 to deallocate) *)
val refresh : t -> ?lifetime:int -> unit -> (int, string) result

(** Get current allocation state *)
val get_state : t -> allocation_state

(** Get relayed address if allocated *)
val get_relayed_address : t -> (string * int) option

(** {1 Permissions & Channels} *)

(** Create permission for peer address.
    Must be created before receiving data from peer. *)
val create_permission : t -> string -> (unit, string) result

(** Bind channel number to peer for efficient data transfer.
    Channel numbers must be in range 0x4000-0x7FFF. *)
val channel_bind : t -> int -> string * int -> (unit, string) result

(** Get bound channels *)
val get_channels : t -> channel list

(** {1 Data Transfer} *)

(** Send data to peer via relay.
    Uses ChannelData if channel bound, otherwise Send indication. *)
val send_data : t -> string * int -> bytes -> (unit, string) result

(** Receive callback type *)
type on_data = string * int -> bytes -> unit

(** Set callback for incoming data *)
val on_data : t -> on_data -> unit

(** {1 Utilities} *)

(** Close client and deallocate *)
val close : t -> unit

(** Check if allocation is active *)
val is_active : t -> bool

(** Remaining lifetime in seconds *)
val remaining_lifetime : t -> int option

(** Pretty-print allocation state *)
val pp_state : Format.formatter -> allocation_state -> unit
