(** RFC 5389 STUN - Session Traversal Utilities for NAT

    Pure OCaml implementation of STUN protocol for WebRTC.

    STUN is used to discover public IP address and port when behind NAT,
    and to check connectivity between peers.

    Implements:
    - RFC 5389: STUN (core protocol)
    - RFC 8489: STUN (updated, 2020)

    Wire-format codec is in {!Stun_codec}; this module re-exports those
    types and adds protocol logic (message construction, integrity,
    fingerprint, TLS helpers).
*)

(** {1 Types}

    All codec types are re-exported from {!Stun_codec}. *)

include module type of Stun_codec

(** {1 Message Construction} *)

(** Create a Binding Request message *)
val create_binding_request : ?transaction_id:bytes -> unit -> message

(** Create a Binding Response message *)
val create_binding_response : transaction_id:bytes -> mapped_address:address -> message

(** Create an error response *)
val create_error_response
  :  transaction_id:bytes
  -> error:error_code
  -> ?reason:string
  -> unit
  -> message

(** {1 Message Integrity} *)

(** Calculate MESSAGE-INTEGRITY attribute (HMAC-SHA1). *)
val calculate_integrity : message -> key:string -> bytes

(** Verify MESSAGE-INTEGRITY attribute. *)
val verify_integrity : message -> key:string -> bool

(** Add MESSAGE-INTEGRITY attribute to message. *)
val add_message_integrity : message -> key:string -> message

(** Compute long-term credential key: MD5(username:realm:password) *)
val compute_long_term_key : username:string -> realm:string -> password:string -> string

(** Add USERNAME, REALM, and NONCE attributes. *)
val add_auth_attributes
  :  message
  -> username:string
  -> realm:string
  -> nonce:string
  -> message

(** Extract REALM and NONCE from a message. *)
val find_realm_nonce : message -> string option * string option

(** Extract ERROR-CODE integer from a message. *)
val find_error_code : message -> int option

(** {1 Fingerprint} *)

(** Calculate FINGERPRINT attribute (CRC-32 XOR 0x5354554e). *)
val calculate_fingerprint : bytes -> int32

(** Verify FINGERPRINT attribute. *)
val verify_fingerprint : message -> bool

(** Add FINGERPRINT attribute to message. *)
val add_fingerprint : message -> message

(** {1 TLS/Network Helpers} *)

(** Find TLS CA certificate file path. *)
val find_tls_ca : ?tls_ca:string -> unit -> string option

(** Load CA certificates from PEM file. *)
val load_ca_certificates
  :  string
  -> (X509.Certificate.t list, string) result

(** Build a TLS authenticator from CA certificates. *)
val build_tls_authenticator
  :  ?tls_ca:string
  -> unit
  -> (X509.Authenticator.t, string) result

(** Convert Unix error to human-readable string. *)
val unix_error_to_string : Unix.error -> string

(** Convert TLS/network exceptions to error strings. *)
val error_of_tls_exn : exn -> string

(** Set socket send/receive timeouts. *)
val set_socket_timeouts : Unix.file_descr -> float -> unit

(** Connect TCP socket with timeout. *)
val connect_tcp_with_timeout
  :  host:string
  -> port:int
  -> timeout_s:float
  -> (Unix.file_descr, string) result

(** Create TLS client configuration. *)
val tls_client_config
  :  authenticator:X509.Authenticator.t
  -> string
  -> (Tls.Config.client * [ `host ] Domain_name.t option, string) result

(** Read a complete STUN frame over TLS. *)
val read_stun_frame_tls : Tls_unix.t -> (bytes, string) result

(** Write data over TLS. *)
val write_tls : Tls_unix.t -> bytes -> (unit, string) result

(** {1 Pretty Printing} *)

(** Pretty-print a STUN message *)
val pp_message : Format.formatter -> message -> unit

(** {1 RFC 5766 TURN Functions} *)

(** Create a TURN Allocate Request message. *)
val create_allocate_request
  :  ?transaction_id:bytes
  -> ?transport:int
  -> ?lifetime:int
  -> ?dont_fragment:bool
  -> unit
  -> message

(** Create a TURN Allocate Success Response message. *)
val create_allocate_response
  :  transaction_id:bytes
  -> relayed_address:address
  -> mapped_address:address
  -> lifetime:int
  -> message

(** Create a TURN Refresh Request message. *)
val create_refresh_request : ?transaction_id:bytes -> lifetime:int -> unit -> message

(** TURN Allocate result *)
type allocate_result =
  { relayed_address : address
  ; mapped_address : address
  ; lifetime : int
  }

(** TURN error codes (RFC 5766 Section 15) *)
type turn_error =
  | Allocation_mismatch
  | Wrong_credentials
  | Unsupported_transport
  | Allocation_quota_reached
  | Insufficient_capacity

val turn_error_to_int : turn_error -> int
val int_to_turn_error : int -> turn_error option

(** Extract allocate result from a TURN Allocate Success Response. *)
val parse_allocate_response : message -> (allocate_result, string) result
