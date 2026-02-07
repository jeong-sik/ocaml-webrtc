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
  | Request (** 0b00 - Client request *)
  | Indication (** 0b01 - No response expected *)
  | Success_response (** 0b10 - Successful response *)
  | Error_response (** 0b11 - Error response *)

(** STUN/TURN message method *)
type message_method =
  | Binding (** 0x001 - Basic STUN binding *)
  (* RFC 5766 TURN methods *)
  | Allocate (** 0x003 - TURN allocate relay address *)
  | Refresh (** 0x004 - TURN refresh allocation *)
  | Send (** 0x006 - TURN send indication *)
  | Data (** 0x007 - TURN data indication *)
  | CreatePermission (** 0x008 - TURN create permission *)
  | ChannelBind (** 0x009 - TURN channel bind *)

(** STUN/TURN attribute types *)
type attribute_type =
  (* Comprehension-required (0x0000-0x7FFF) *)
  | MAPPED_ADDRESS (** 0x0001 *)
  | USERNAME (** 0x0006 *)
  | MESSAGE_INTEGRITY (** 0x0008 *)
  | ERROR_CODE (** 0x0009 *)
  | UNKNOWN_ATTRIBUTES (** 0x000A *)
  (* RFC 5766 TURN attributes *)
  | CHANNEL_NUMBER (** 0x000C - TURN channel number *)
  | LIFETIME (** 0x000D - TURN allocation lifetime *)
  | XOR_PEER_ADDRESS (** 0x0012 - TURN peer address *)
  | DATA (** 0x0013 - TURN data attribute *)
  | REALM (** 0x0014 *)
  | NONCE (** 0x0015 *)
  | XOR_RELAYED_ADDRESS (** 0x0016 - TURN relayed address *)
  | EVEN_PORT (** 0x0018 - TURN even port *)
  | REQUESTED_TRANSPORT (** 0x0019 - TURN requested transport *)
  | DONT_FRAGMENT (** 0x001A - TURN don't fragment *)
  | XOR_MAPPED_ADDRESS (** 0x0020 *)
  | RESERVATION_TOKEN (** 0x0022 - TURN reservation token *)
  (* Comprehension-optional (0x8000-0xFFFF) *)
  | SOFTWARE (** 0x8022 *)
  | ALTERNATE_SERVER (** 0x8023 *)
  | FINGERPRINT (** 0x8028 *)
  | Unknown of int (** Unknown attribute *)

(** IP address family *)
type address_family =
  | IPv4
  | IPv6

(** Network address with port *)
type address =
  { family : address_family
  ; port : int
  ; ip : string (** Dotted quad for IPv4, colon-hex for IPv6 *)
  }

(** STUN/TURN attribute value *)
type attribute_value =
  | Mapped_address of address
  | Xor_mapped_address of address
  | Username of string
  | Message_integrity of bytes (** 20 bytes HMAC-SHA1 *)
  | Fingerprint of int32 (** CRC-32 XOR 0x5354554e *)
  | Error_code of
      { code : int
      ; reason : string
      }
  | Software of string
  | Realm of string
  | Nonce of string
  (* RFC 5766 TURN attribute values *)
  | Channel_number of int (** TURN channel number (0x4000-0x7FFF) *)
  | Lifetime of int (** TURN allocation lifetime in seconds *)
  | Xor_peer_address of address (** TURN XOR-PEER-ADDRESS *)
  | Xor_relayed_address of address (** TURN XOR-RELAYED-ADDRESS *)
  | Data_attr of bytes (** TURN DATA attribute *)
  | Requested_transport of int (** TURN transport protocol (17=UDP, 6=TCP) *)
  | Even_port of bool (** TURN even port request *)
  | Dont_fragment (** TURN don't fragment flag *)
  | Reservation_token of bytes (** TURN reservation token (8 bytes) *)
  | Unknown_attr of bytes

(** STUN attribute *)
type attribute =
  { attr_type : attribute_type
  ; value : attribute_value
  }

(** STUN message *)
type message =
  { msg_class : message_class
  ; msg_method : message_method
  ; transaction_id : bytes (** 96 bits (12 bytes) *)
  ; attributes : attribute list
  }

(** STUN error codes (RFC 5389 Section 15.6) *)
type error_code =
  | Try_alternate (** 300 *)
  | Bad_request (** 400 *)
  | Unauthorized (** 401 *)
  | Unknown_attribute (** 420 *)
  | Stale_nonce (** 438 *)
  | Server_error (** 500 *)

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
val create_binding_response : transaction_id:bytes -> mapped_address:address -> message

(** Create an error response *)
val create_error_response
  :  transaction_id:bytes
  -> error:error_code
  -> ?reason:string
  -> unit
  -> message

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

(** Add MESSAGE-INTEGRITY attribute to message. *)
val add_message_integrity : message -> key:string -> message

(** {1 Fingerprint} *)

(** Calculate FINGERPRINT attribute (CRC-32 XOR 0x5354554e).
    @param data Encoded message (without FINGERPRINT)
    @return Fingerprint value *)
val calculate_fingerprint : bytes -> int32

(** Verify FINGERPRINT attribute.
    @param message Message with FINGERPRINT
    @return true if valid *)
val verify_fingerprint : message -> bool

(** Add FINGERPRINT attribute to message. *)
val add_fingerprint : message -> message

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
type binding_result =
  { local_address : address (** Local address used *)
  ; mapped_address : address (** Public address from STUN server *)
  ; server_software : string option
  ; rtt_ms : float (** Round-trip time in milliseconds *)
  }

(** {1 RFC 5766 TURN Functions} *)

(** Create a TURN Allocate Request message.
    @param transaction_id Optional transaction ID (generated if not provided)
    @param transport Transport protocol (17 = UDP, 6 = TCP, default: UDP)
    @param lifetime Optional requested lifetime in seconds
    @param dont_fragment Include DONT-FRAGMENT attribute
    @return TURN Allocate Request message *)
val create_allocate_request
  :  ?transaction_id:bytes
  -> ?transport:int
  -> ?lifetime:int
  -> ?dont_fragment:bool
  -> unit
  -> message

(** Create a TURN Allocate Success Response message.
    @param transaction_id Transaction ID from request
    @param relayed_address The allocated relay address
    @param mapped_address Client's server-reflexive address
    @param lifetime Allocation lifetime in seconds
    @return TURN Allocate Success Response message *)
val create_allocate_response
  :  transaction_id:bytes
  -> relayed_address:address
  -> mapped_address:address
  -> lifetime:int
  -> message

(** Create a TURN Refresh Request message.
    @param transaction_id Optional transaction ID
    @param lifetime Requested lifetime (0 to deallocate)
    @return TURN Refresh Request message *)
val create_refresh_request : ?transaction_id:bytes -> lifetime:int -> unit -> message

(** TURN Allocate result containing the relayed address and lifetime *)
type allocate_result =
  { relayed_address : address (** Allocated relay address *)
  ; mapped_address : address (** Client's reflexive address *)
  ; lifetime : int (** Allocation lifetime in seconds *)
  }

(** TURN error codes (RFC 5766 Section 15) *)
type turn_error =
  | Allocation_mismatch (** 437 - Allocation mismatch *)
  | Wrong_credentials (** 441 - Wrong credentials *)
  | Unsupported_transport (** 442 - Unsupported transport protocol *)
  | Allocation_quota_reached (** 486 - Allocation quota reached *)
  | Insufficient_capacity (** 508 - Insufficient capacity *)

(** Get TURN error code integer *)
val turn_error_to_int : turn_error -> int

(** Get TURN error type from integer *)
val int_to_turn_error : int -> turn_error option

(** Extract allocate result from a TURN Allocate Success Response.
    @param msg TURN Allocate Success Response message
    @return Allocate result or error string *)
val parse_allocate_response : message -> (allocate_result, string) result
