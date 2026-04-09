(** RFC 5389 STUN Codec - Message encoding/decoding, attribute parsing

    Pure binary codec for STUN/TURN message serialization.
    No I/O or protocol logic -- only data types and wire format.
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
  | MAPPED_ADDRESS (** 0x0001 *)
  | USERNAME (** 0x0006 *)
  | MESSAGE_INTEGRITY (** 0x0008 *)
  | ERROR_CODE (** 0x0009 *)
  | UNKNOWN_ATTRIBUTES (** 0x000A *)
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

(** Result of a STUN binding request *)
type binding_result =
  { local_address : address
  ; mapped_address : address
  ; server_software : string option
  ; rtt_ms : float
  }

(** {1 Constants} *)

val magic_cookie : int32
val default_port : int

(** {1 Attribute Type Conversions} *)

val attr_type_to_int : attribute_type -> int
val int_to_attr_type : int -> attribute_type
val error_code_to_int : error_code -> int
val int_to_error_code : int -> error_code option

(** {1 String Conversions} *)

val string_of_class : message_class -> string
val string_of_method : message_method -> string
val string_of_attr_type : attribute_type -> string

(** {1 Binary Helpers} *)

val get_uint16_be : bytes -> int -> int
val get_uint32_be : bytes -> int -> int32
val set_uint16_be : bytes -> int -> int -> unit
val set_uint32_be : bytes -> int -> int32 -> unit

(** {1 Transaction ID} *)

val generate_transaction_id : unit -> bytes

(** {1 Address Encoding/Decoding} *)

val encode_address : address -> bytes
val decode_address : bytes -> int -> (address, string) result
val encode_ipv4 : string -> bytes
val parse_ipv4 : bytes -> int -> string
val encode_ipv6 : string -> bytes
val parse_ipv6 : bytes -> int -> string

(** {1 XOR Operations} *)

val xor_address : address -> bytes -> address
val unxor_address : address -> bytes -> address

(** {1 Attribute Encoding/Decoding} *)

val encode_attribute : attribute -> bytes
val decode_attribute : bytes -> int -> (attribute * int, string) result

(** {1 Message Encoding/Decoding} *)

val encode : message -> bytes
val decode : bytes -> (message, string) result

(** {1 Utilities} *)

val is_stun_message : bytes -> bool
