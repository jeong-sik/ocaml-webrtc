(** RFC 5389 STUN - Session Traversal Utilities for NAT

    Pure OCaml implementation of STUN protocol for WebRTC.

    STUN is used to discover public IP address and port when behind NAT,
    and to check connectivity between peers.

    Implements:
    - RFC 5389: STUN (core protocol)
    - RFC 8489: STUN (updated, 2020)

    @author Second Brain
    @since MASC v3.1
*)

(** {1 Types} *)

(** STUN message class (2 bits in message type) *)
type message_class =
  | Request           (** 0b00 - Client request *)
  | Indication        (** 0b01 - No response expected *)
  | Success_response  (** 0b10 - Successful response *)
  | Error_response    (** 0b11 - Error response *)

(** STUN message method *)
type message_method =
  | Binding           (** 0x001 - Basic STUN binding *)

(** STUN attribute types *)
type attribute_type =
  (* Comprehension-required (0x0000-0x7FFF) *)
  | MAPPED_ADDRESS        (** 0x0001 *)
  | USERNAME              (** 0x0006 *)
  | MESSAGE_INTEGRITY     (** 0x0008 *)
  | ERROR_CODE            (** 0x0009 *)
  | UNKNOWN_ATTRIBUTES    (** 0x000A *)
  | REALM                 (** 0x0014 *)
  | NONCE                 (** 0x0015 *)
  | XOR_MAPPED_ADDRESS    (** 0x0020 *)
  (* Comprehension-optional (0x8000-0xFFFF) *)
  | SOFTWARE              (** 0x8022 *)
  | ALTERNATE_SERVER      (** 0x8023 *)
  | FINGERPRINT           (** 0x8028 *)
  | Unknown of int        (** Unknown attribute *)

(** IP address family *)
type address_family =
  | IPv4
  | IPv6

(** Network address with port *)
type address = {
  family: address_family;
  port: int;
  ip: string;  (** Dotted quad for IPv4, colon-hex for IPv6 *)
}

(** STUN attribute value *)
type attribute_value =
  | Mapped_address of address
  | Xor_mapped_address of address
  | Username of string
  | Message_integrity of bytes  (** 20 bytes HMAC-SHA1 *)
  | Fingerprint of int32        (** CRC-32 XOR 0x5354554e *)
  | Error_code of { code: int; reason: string }
  | Software of string
  | Realm of string
  | Nonce of string
  | Unknown_attr of bytes

(** STUN attribute *)
type attribute = {
  attr_type: attribute_type;
  value: attribute_value;
}

(** STUN message *)
type message = {
  msg_class: message_class;
  msg_method: message_method;
  transaction_id: bytes;  (** 96 bits (12 bytes) *)
  attributes: attribute list;
}

(** STUN error codes (RFC 5389 Section 15.6) *)
type error_code =
  | Try_alternate       (** 300 *)
  | Bad_request         (** 400 *)
  | Unauthorized        (** 401 *)
  | Unknown_attribute   (** 420 *)
  | Stale_nonce         (** 438 *)
  | Server_error        (** 500 *)

(** {1 Constants} *)

(** Magic cookie value (0x2112A442) - RFC 5389 *)
val magic_cookie : int32

(** Default STUN port *)
val default_port : int

(** {1 Message Construction} *)

(** Generate random 96-bit transaction ID *)
val generate_transaction_id : unit -> bytes

(** Create a Binding Request message *)
val create_binding_request : ?transaction_id:bytes -> unit -> message

(** Create a Binding Response message *)
val create_binding_response :
  transaction_id:bytes ->
  mapped_address:address ->
  message

(** Create an error response *)
val create_error_response :
  transaction_id:bytes ->
  error:error_code ->
  ?reason:string ->
  unit ->
  message

(** {1 Encoding/Decoding} *)

(** Encode message to bytes.
    @param message STUN message
    @return Encoded bytes *)
val encode : message -> bytes

(** Decode bytes to message.
    @param data Raw bytes
    @return Decoded message or error *)
val decode : bytes -> (message, string) result

(** {1 XOR Operations} *)

(** XOR an address with transaction ID (for XOR-MAPPED-ADDRESS).
    @param addr Original address
    @param transaction_id 12-byte transaction ID
    @return XORed address *)
val xor_address : address -> bytes -> address

(** Reverse XOR to get original address.
    @param xored XORed address
    @param transaction_id 12-byte transaction ID
    @return Original address *)
val unxor_address : address -> bytes -> address

(** {1 Message Integrity} *)

(** Calculate MESSAGE-INTEGRITY attribute (HMAC-SHA1).
    @param message Message without MESSAGE-INTEGRITY
    @param key Shared secret
    @return 20-byte HMAC *)
val calculate_integrity : message -> key:string -> bytes

(** Verify MESSAGE-INTEGRITY attribute.
    @param message Message with MESSAGE-INTEGRITY
    @param key Shared secret
    @return true if valid *)
val verify_integrity : message -> key:string -> bool

(** {1 Fingerprint} *)

(** Calculate FINGERPRINT attribute (CRC-32 XOR 0x5354554e).
    @param data Encoded message (without FINGERPRINT)
    @return Fingerprint value *)
val calculate_fingerprint : bytes -> int32

(** Verify FINGERPRINT attribute.
    @param message Message with FINGERPRINT
    @return true if valid *)
val verify_fingerprint : message -> bool

(** {1 Utilities} *)

(** Check if bytes look like a STUN message.
    First two bits must be 0, magic cookie must be present.
    @param data Raw bytes
    @return true if likely STUN *)
val is_stun_message : bytes -> bool

(** Get error code integer from error type *)
val error_code_to_int : error_code -> int

(** Get error type from integer *)
val int_to_error_code : int -> error_code option

(** String representation of message class *)
val string_of_class : message_class -> string

(** String representation of message method *)
val string_of_method : message_method -> string

(** String representation of attribute type *)
val string_of_attr_type : attribute_type -> string

(** Pretty-print a STUN message *)
val pp_message : Format.formatter -> message -> unit

(** {1 Client Functions} *)

(** Result of a STUN binding request *)
type binding_result = {
  local_address: address;   (** Local address used *)
  mapped_address: address;  (** Public address from STUN server *)
  server_software: string option;
  rtt_ms: float;           (** Round-trip time in milliseconds *)
}

(** Send binding request and get response (Lwt async).
    @param server STUN server address (host:port)
    @param timeout Timeout in seconds (default: 3.0)
    @return Binding result or error Lwt promise *)
val binding_request_lwt :
  server:string ->
  ?timeout:float ->
  unit ->
  (binding_result, string) result Lwt.t

(** Send binding request and get response (synchronous).
    Blocks until response or timeout.
    @param server STUN server address (host:port)
    @param timeout Timeout in seconds (default: 3.0)
    @return Binding result or error *)
val binding_request_sync :
  server:string ->
  ?timeout:float ->
  unit ->
  (binding_result, string) result
