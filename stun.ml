(** RFC 5389 STUN - Session Traversal Utilities for NAT

    Pure OCaml implementation of STUN protocol.
    Requires OCaml 5.x with Eio for async networking.
*)

(* ============================================
   Types
   ============================================ *)

type message_class =
  | Request
  | Indication
  | Success_response
  | Error_response

type message_method =
  | Binding
  (* RFC 5766 TURN methods *)
  | Allocate          (** 0x003 - TURN allocate relay address *)
  | Refresh           (** 0x004 - TURN refresh allocation *)
  | Send              (** 0x006 - TURN send indication *)
  | Data              (** 0x007 - TURN data indication *)
  | CreatePermission  (** 0x008 - TURN create permission *)
  | ChannelBind       (** 0x009 - TURN channel bind *)

type attribute_type =
  | MAPPED_ADDRESS
  | USERNAME
  | MESSAGE_INTEGRITY
  | ERROR_CODE
  | UNKNOWN_ATTRIBUTES
  (* RFC 5766 TURN attributes *)
  | CHANNEL_NUMBER        (** 0x000C - TURN channel number *)
  | LIFETIME              (** 0x000D - TURN allocation lifetime *)
  | XOR_PEER_ADDRESS      (** 0x0012 - TURN peer address *)
  | DATA                  (** 0x0013 - TURN data attribute *)
  | REALM
  | NONCE
  | XOR_RELAYED_ADDRESS   (** 0x0016 - TURN relayed address *)
  | EVEN_PORT             (** 0x0018 - TURN even port *)
  | REQUESTED_TRANSPORT   (** 0x0019 - TURN requested transport *)
  | DONT_FRAGMENT         (** 0x001A - TURN don't fragment *)
  | XOR_MAPPED_ADDRESS
  | RESERVATION_TOKEN     (** 0x0022 - TURN reservation token *)
  | SOFTWARE
  | ALTERNATE_SERVER
  | FINGERPRINT
  | Unknown of int

type address_family =
  | IPv4
  | IPv6

type address = {
  family: address_family;
  port: int;
  ip: string;
}

type attribute_value =
  | Mapped_address of address
  | Xor_mapped_address of address
  | Username of string
  | Message_integrity of bytes
  | Fingerprint of int32
  | Error_code of { code: int; reason: string }
  | Software of string
  | Realm of string
  | Nonce of string
  (* RFC 5766 TURN attribute values *)
  | Channel_number of int           (** TURN channel number (0x4000-0x7FFF) *)
  | Lifetime of int                 (** TURN allocation lifetime in seconds *)
  | Xor_peer_address of address     (** TURN XOR-PEER-ADDRESS *)
  | Xor_relayed_address of address  (** TURN XOR-RELAYED-ADDRESS *)
  | Data_attr of bytes              (** TURN DATA attribute *)
  | Requested_transport of int      (** TURN transport protocol (17=UDP, 6=TCP) *)
  | Even_port of bool               (** TURN even port request *)
  | Dont_fragment                   (** TURN don't fragment flag *)
  | Reservation_token of bytes      (** TURN reservation token (8 bytes) *)
  | Unknown_attr of bytes

type attribute = {
  attr_type: attribute_type;
  value: attribute_value;
}

type message = {
  msg_class: message_class;
  msg_method: message_method;
  transaction_id: bytes;
  attributes: attribute list;
}

type error_code =
  | Try_alternate
  | Bad_request
  | Unauthorized
  | Unknown_attribute
  | Stale_nonce
  | Server_error

type binding_result = {
  local_address: address;
  mapped_address: address;
  server_software: string option;
  rtt_ms: float;
}

(* ============================================
   Constants
   ============================================ *)

let magic_cookie = 0x2112A442l
let default_port = 3478

(* Attribute type codes *)
let attr_type_to_int = function
  | MAPPED_ADDRESS -> 0x0001
  | USERNAME -> 0x0006
  | MESSAGE_INTEGRITY -> 0x0008
  | ERROR_CODE -> 0x0009
  | UNKNOWN_ATTRIBUTES -> 0x000A
  (* RFC 5766 TURN attributes *)
  | CHANNEL_NUMBER -> 0x000C
  | LIFETIME -> 0x000D
  | XOR_PEER_ADDRESS -> 0x0012
  | DATA -> 0x0013
  | REALM -> 0x0014
  | NONCE -> 0x0015
  | XOR_RELAYED_ADDRESS -> 0x0016
  | EVEN_PORT -> 0x0018
  | REQUESTED_TRANSPORT -> 0x0019
  | DONT_FRAGMENT -> 0x001A
  | XOR_MAPPED_ADDRESS -> 0x0020
  | RESERVATION_TOKEN -> 0x0022
  | SOFTWARE -> 0x8022
  | ALTERNATE_SERVER -> 0x8023
  | FINGERPRINT -> 0x8028
  | Unknown n -> n

let int_to_attr_type = function
  | 0x0001 -> MAPPED_ADDRESS
  | 0x0006 -> USERNAME
  | 0x0008 -> MESSAGE_INTEGRITY
  | 0x0009 -> ERROR_CODE
  | 0x000A -> UNKNOWN_ATTRIBUTES
  (* RFC 5766 TURN attributes *)
  | 0x000C -> CHANNEL_NUMBER
  | 0x000D -> LIFETIME
  | 0x0012 -> XOR_PEER_ADDRESS
  | 0x0013 -> DATA
  | 0x0014 -> REALM
  | 0x0015 -> NONCE
  | 0x0016 -> XOR_RELAYED_ADDRESS
  | 0x0018 -> EVEN_PORT
  | 0x0019 -> REQUESTED_TRANSPORT
  | 0x001A -> DONT_FRAGMENT
  | 0x0020 -> XOR_MAPPED_ADDRESS
  | 0x0022 -> RESERVATION_TOKEN
  | 0x8022 -> SOFTWARE
  | 0x8023 -> ALTERNATE_SERVER
  | 0x8028 -> FINGERPRINT
  | n -> Unknown n

(* Error codes *)
let error_code_to_int = function
  | Try_alternate -> 300
  | Bad_request -> 400
  | Unauthorized -> 401
  | Unknown_attribute -> 420
  | Stale_nonce -> 438
  | Server_error -> 500

let int_to_error_code = function
  | 300 -> Some Try_alternate
  | 400 -> Some Bad_request
  | 401 -> Some Unauthorized
  | 420 -> Some Unknown_attribute
  | 438 -> Some Stale_nonce
  | 500 -> Some Server_error
  | _ -> None

(* ============================================
   String conversions
   ============================================ *)

let string_of_class = function
  | Request -> "Request"
  | Indication -> "Indication"
  | Success_response -> "Success Response"
  | Error_response -> "Error Response"

let string_of_method = function
  | Binding -> "Binding"
  (* RFC 5766 TURN methods *)
  | Allocate -> "Allocate"
  | Refresh -> "Refresh"
  | Send -> "Send"
  | Data -> "Data"
  | CreatePermission -> "CreatePermission"
  | ChannelBind -> "ChannelBind"

let string_of_attr_type = function
  | MAPPED_ADDRESS -> "MAPPED-ADDRESS"
  | USERNAME -> "USERNAME"
  | MESSAGE_INTEGRITY -> "MESSAGE-INTEGRITY"
  | ERROR_CODE -> "ERROR-CODE"
  | UNKNOWN_ATTRIBUTES -> "UNKNOWN-ATTRIBUTES"
  (* RFC 5766 TURN attributes *)
  | CHANNEL_NUMBER -> "CHANNEL-NUMBER"
  | LIFETIME -> "LIFETIME"
  | XOR_PEER_ADDRESS -> "XOR-PEER-ADDRESS"
  | DATA -> "DATA"
  | REALM -> "REALM"
  | NONCE -> "NONCE"
  | XOR_RELAYED_ADDRESS -> "XOR-RELAYED-ADDRESS"
  | EVEN_PORT -> "EVEN-PORT"
  | REQUESTED_TRANSPORT -> "REQUESTED-TRANSPORT"
  | DONT_FRAGMENT -> "DONT-FRAGMENT"
  | XOR_MAPPED_ADDRESS -> "XOR-MAPPED-ADDRESS"
  | RESERVATION_TOKEN -> "RESERVATION-TOKEN"
  | SOFTWARE -> "SOFTWARE"
  | ALTERNATE_SERVER -> "ALTERNATE-SERVER"
  | FINGERPRINT -> "FINGERPRINT"
  | Unknown n -> Printf.sprintf "UNKNOWN(0x%04X)" n

(* ============================================
   Binary helpers
   ============================================ *)

let get_uint16_be buf off =
  (Char.code (Bytes.get buf off) lsl 8) lor
  Char.code (Bytes.get buf (off + 1))

let get_uint32_be buf off =
  Int32.(
    logor (shift_left (of_int (Char.code (Bytes.get buf off))) 24)
      (logor (shift_left (of_int (Char.code (Bytes.get buf (off + 1)))) 16)
         (logor (shift_left (of_int (Char.code (Bytes.get buf (off + 2)))) 8)
            (of_int (Char.code (Bytes.get buf (off + 3))))))
  )

let set_uint16_be buf off v =
  Bytes.set buf off (Char.chr ((v lsr 8) land 0xFF));
  Bytes.set buf (off + 1) (Char.chr (v land 0xFF))

let set_uint32_be buf off v =
  Bytes.set buf off (Char.chr (Int32.(to_int (logand (shift_right_logical v 24) 0xFFl))));
  Bytes.set buf (off + 1) (Char.chr (Int32.(to_int (logand (shift_right_logical v 16) 0xFFl))));
  Bytes.set buf (off + 2) (Char.chr (Int32.(to_int (logand (shift_right_logical v 8) 0xFFl))));
  Bytes.set buf (off + 3) (Char.chr (Int32.(to_int (logand v 0xFFl))))

(* ============================================
   Transaction ID
   ============================================ *)

let generate_transaction_id () =
  let id = Bytes.create 12 in
  for i = 0 to 11 do
    Bytes.set id i (Char.chr (Random.int 256))
  done;
  id

(* ============================================
   Message Type Encoding
   ============================================ *)

(* STUN message type encoding (RFC 5389 Section 6):

   0                 1
   2  3  4 5 6 7 8 9 0 1 2 3 4 5
   +--+--+-+-+-+-+-+-+-+-+-+-+-+-+
   |M |M |M|M|M|C|M|M|M|C|M|M|M|M|
   |11|10|9|8|7|1|6|5|4|0|3|2|1|0|
   +--+--+-+-+-+-+-+-+-+-+-+-+-+-+

   M = Method bits, C = Class bits
   Class: C1C0 where C1 is bit 8, C0 is bit 4
*)

let encode_message_type msg_class msg_method =
  let method_bits = match msg_method with
    | Binding -> 0x0001
    (* RFC 5766 TURN methods *)
    | Allocate -> 0x0003
    | Refresh -> 0x0004
    | Send -> 0x0006
    | Data -> 0x0007
    | CreatePermission -> 0x0008
    | ChannelBind -> 0x0009
  in
  let class_bits = match msg_class with
    | Request -> 0b00
    | Indication -> 0b01
    | Success_response -> 0b10
    | Error_response -> 0b11
  in
  (* C0 goes to bit 4, C1 goes to bit 8 *)
  let c0 = (class_bits land 1) lsl 4 in
  let c1 = ((class_bits lsr 1) land 1) lsl 8 in
  (* Method bits: 0-3 stay, 4-6 shift by 1, 7-11 shift by 2 *)
  let m_low = method_bits land 0x000F in
  let m_mid = (method_bits land 0x0070) lsl 1 in
  let m_high = (method_bits land 0x0F80) lsl 2 in
  m_low lor c0 lor m_mid lor c1 lor m_high

let decode_message_type type_val =
  (* Extract class bits *)
  let c0 = (type_val lsr 4) land 1 in
  let c1 = (type_val lsr 8) land 1 in
  let class_bits = c0 lor (c1 lsl 1) in
  let msg_class = match class_bits with
    | 0b00 -> Request
    | 0b01 -> Indication
    | 0b10 -> Success_response
    | 0b11 -> Error_response
    | _ -> Request  (* Shouldn't happen *)
  in
  (* Extract method bits *)
  let m_low = type_val land 0x000F in
  let m_mid = (type_val lsr 1) land 0x0070 in
  let m_high = (type_val lsr 2) land 0x0F80 in
  let method_bits = m_low lor m_mid lor m_high in
  let msg_method = match method_bits with
    | 0x0001 -> Binding
    (* RFC 5766 TURN methods *)
    | 0x0003 -> Allocate
    | 0x0004 -> Refresh
    | 0x0006 -> Send
    | 0x0007 -> Data
    | 0x0008 -> CreatePermission
    | 0x0009 -> ChannelBind
    | _ -> Binding  (* Default to Binding for unknown methods *)
  in
  (msg_class, msg_method)

(* ============================================
   Address encoding/decoding
   ============================================ *)

let parse_ipv4 ip_bytes off =
  Printf.sprintf "%d.%d.%d.%d"
    (Char.code (Bytes.get ip_bytes off))
    (Char.code (Bytes.get ip_bytes (off + 1)))
    (Char.code (Bytes.get ip_bytes (off + 2)))
    (Char.code (Bytes.get ip_bytes (off + 3)))

let encode_ipv4 ip =
  let parts = String.split_on_char '.' ip in
  let bytes = Bytes.create 4 in
  List.iteri (fun i part ->
    Bytes.set bytes i (Char.chr (int_of_string part))
  ) parts;
  bytes

(** Parse IPv6 address from 16 bytes to string *)
let parse_ipv6 ip_bytes off =
  (* Read 8 groups of 16-bit values *)
  let groups = Array.init 8 (fun i ->
    let hi = Char.code (Bytes.get ip_bytes (off + i * 2)) in
    let lo = Char.code (Bytes.get ip_bytes (off + i * 2 + 1)) in
    (hi lsl 8) lor lo
  ) in
  (* Format as IPv6 string *)
  String.concat ":" (Array.to_list (Array.map (Printf.sprintf "%x") groups))

(** Encode IPv6 string to 16 bytes *)
let encode_ipv6 ip =
  let bytes = Bytes.create 16 in
  (* Use ipaddr library for robust parsing *)
  match Ipaddr.V6.of_string ip with
  | Ok v6 ->
    let octets = Ipaddr.V6.to_octets v6 in
    Bytes.blit_string octets 0 bytes 0 16;
    bytes
  | Error _ ->
    (* Fallback: manual parsing for colon-separated hex *)
    let parts = String.split_on_char ':' ip in
    List.iteri (fun i part ->
      if i < 8 && String.length part > 0 then begin
        let value = int_of_string ("0x" ^ part) in
        Bytes.set bytes (i * 2) (Char.chr ((value lsr 8) land 0xFF));
        Bytes.set bytes (i * 2 + 1) (Char.chr (value land 0xFF))
      end
    ) parts;
    bytes

let decode_address data off =
  let family_byte = Char.code (Bytes.get data (off + 1)) in
  let port = get_uint16_be data (off + 2) in
  match family_byte with
  | 0x01 ->  (* IPv4 *)
    let ip = parse_ipv4 data (off + 4) in
    Ok { family = IPv4; port; ip }
  | 0x02 ->  (* IPv6 *)
    let ip = parse_ipv6 data (off + 4) in
    Ok { family = IPv6; port; ip }
  | _ ->
    Error (Printf.sprintf "Unknown address family: 0x%02X" family_byte)

let encode_address addr =
  let buf = match addr.family with
    | IPv4 ->
      let b = Bytes.create 8 in
      Bytes.set b 0 '\x00';  (* Reserved *)
      Bytes.set b 1 '\x01';  (* IPv4 *)
      set_uint16_be b 2 addr.port;
      let ip_bytes = encode_ipv4 addr.ip in
      Bytes.blit ip_bytes 0 b 4 4;
      b
    | IPv6 ->
      (* IPv6: 1 byte reserved + 1 byte family + 2 bytes port + 16 bytes IP = 20 bytes *)
      let b = Bytes.create 20 in
      Bytes.set b 0 '\x00';  (* Reserved *)
      Bytes.set b 1 '\x02';  (* IPv6 *)
      set_uint16_be b 2 addr.port;
      let ip_bytes = encode_ipv6 addr.ip in
      Bytes.blit ip_bytes 0 b 4 16;
      b
  in
  buf

(* ============================================
   XOR operations
   ============================================ *)

let xor_address addr transaction_id =
  match addr.family with
  | IPv4 ->
    (* XOR port with high 16 bits of magic cookie *)
    let xored_port = addr.port lxor (Int32.to_int (Int32.shift_right_logical magic_cookie 16)) in
    (* XOR IP with magic cookie *)
    let ip_bytes = encode_ipv4 addr.ip in
    let mc_bytes = Bytes.create 4 in
    set_uint32_be mc_bytes 0 magic_cookie;
    for i = 0 to 3 do
      Bytes.set ip_bytes i (Char.chr (
        (Char.code (Bytes.get ip_bytes i)) lxor
        (Char.code (Bytes.get mc_bytes i))
      ))
    done;
    { family = IPv4; port = xored_port; ip = parse_ipv4 ip_bytes 0 }
  | IPv6 ->
    (* XOR port with high 16 bits of magic cookie (same as IPv4) *)
    let xored_port = addr.port lxor (Int32.to_int (Int32.shift_right_logical magic_cookie 16)) in
    (* XOR IP with magic cookie (4 bytes) + transaction_id (12 bytes) = 16 bytes *)
    let ip_bytes = encode_ipv6 addr.ip in
    (* Build 16-byte XOR mask: magic_cookie || transaction_id *)
    let xor_mask = Bytes.create 16 in
    set_uint32_be xor_mask 0 magic_cookie;
    Bytes.blit transaction_id 0 xor_mask 4 12;
    (* XOR each byte *)
    for i = 0 to 15 do
      Bytes.set ip_bytes i (Char.chr (
        (Char.code (Bytes.get ip_bytes i)) lxor
        (Char.code (Bytes.get xor_mask i))
      ))
    done;
    { family = IPv6; port = xored_port; ip = parse_ipv6 ip_bytes 0 }

let unxor_address = xor_address  (* XOR is symmetric *)

(* ============================================
   Attribute encoding/decoding
   ============================================ *)

let encode_attribute attr =
  let type_code = attr_type_to_int attr.attr_type in
  let value_bytes = match attr.value with
    | Mapped_address addr | Xor_mapped_address addr
    | Xor_peer_address addr | Xor_relayed_address addr ->
      encode_address addr
    | Username s | Software s | Realm s | Nonce s ->
      Bytes.of_string s
    | Message_integrity b ->
      b
    | Fingerprint fp ->
      let b = Bytes.create 4 in
      set_uint32_be b 0 fp;
      b
    | Error_code { code; reason } ->
      let reason_bytes = Bytes.of_string reason in
      let len = 4 + Bytes.length reason_bytes in
      let b = Bytes.create len in
      Bytes.set b 0 '\x00';
      Bytes.set b 1 '\x00';
      Bytes.set b 2 (Char.chr (code / 100));  (* Class *)
      Bytes.set b 3 (Char.chr (code mod 100));  (* Number *)
      Bytes.blit reason_bytes 0 b 4 (Bytes.length reason_bytes);
      b
    (* RFC 5766 TURN attributes *)
    | Channel_number num ->
      let b = Bytes.create 4 in
      set_uint16_be b 0 num;
      set_uint16_be b 2 0;  (* RFFU - Reserved *)
      b
    | Lifetime secs ->
      let b = Bytes.create 4 in
      set_uint32_be b 0 (Int32.of_int secs);
      b
    | Data_attr data ->
      data
    | Requested_transport proto ->
      let b = Bytes.create 4 in
      Bytes.set b 0 (Char.chr proto);
      Bytes.set b 1 '\x00';  (* RFFU *)
      Bytes.set b 2 '\x00';  (* RFFU *)
      Bytes.set b 3 '\x00';  (* RFFU *)
      b
    | Even_port reserve ->
      let b = Bytes.create 1 in
      Bytes.set b 0 (if reserve then '\x80' else '\x00');
      b
    | Dont_fragment ->
      Bytes.empty  (* Zero-length attribute *)
    | Reservation_token token ->
      token  (* 8 bytes *)
    | Unknown_attr b ->
      b
  in
  let value_len = Bytes.length value_bytes in
  (* Pad to 4-byte boundary *)
  let padded_len = (value_len + 3) land (lnot 3) in
  let header = Bytes.create 4 in
  set_uint16_be header 0 type_code;
  set_uint16_be header 2 value_len;
  let result = Bytes.create (4 + padded_len) in
  Bytes.blit header 0 result 0 4;
  Bytes.blit value_bytes 0 result 4 value_len;
  (* Padding bytes are already 0 *)
  result

let decode_attribute data off =
  if Bytes.length data < off + 4 then
    Error "Attribute too short"
  else
    let type_code = get_uint16_be data off in
    let value_len = get_uint16_be data (off + 2) in
    let padded_len = (value_len + 3) land (lnot 3) in
    if Bytes.length data < off + 4 + padded_len then
      Error "Attribute value truncated"
    else
      let attr_type = int_to_attr_type type_code in
      let value_data = Bytes.sub data (off + 4) value_len in
      let value = match attr_type with
        | MAPPED_ADDRESS ->
          (match decode_address data (off + 4) with
           | Ok addr -> Mapped_address addr
           | Error _ -> Unknown_attr value_data)
        | XOR_MAPPED_ADDRESS ->
          (match decode_address data (off + 4) with
           | Ok addr -> Xor_mapped_address addr
           | Error _ -> Unknown_attr value_data)
        (* RFC 5766 TURN address attributes *)
        | XOR_PEER_ADDRESS ->
          (match decode_address data (off + 4) with
           | Ok addr -> Xor_peer_address addr
           | Error _ -> Unknown_attr value_data)
        | XOR_RELAYED_ADDRESS ->
          (match decode_address data (off + 4) with
           | Ok addr -> Xor_relayed_address addr
           | Error _ -> Unknown_attr value_data)
        | USERNAME -> Username (Bytes.to_string value_data)
        | SOFTWARE -> Software (Bytes.to_string value_data)
        | REALM -> Realm (Bytes.to_string value_data)
        | NONCE -> Nonce (Bytes.to_string value_data)
        | MESSAGE_INTEGRITY -> Message_integrity value_data
        | FINGERPRINT -> Fingerprint (get_uint32_be value_data 0)
        | ERROR_CODE ->
          let code_class = Char.code (Bytes.get value_data 2) in
          let code_number = Char.code (Bytes.get value_data 3) in
          let code = code_class * 100 + code_number in
          let reason = if value_len > 4
            then Bytes.sub_string value_data 4 (value_len - 4)
            else "" in
          Error_code { code; reason }
        (* RFC 5766 TURN attributes *)
        | CHANNEL_NUMBER ->
          if Bytes.length value_data >= 2 then
            Channel_number (get_uint16_be value_data 0)
          else Unknown_attr value_data
        | LIFETIME ->
          if Bytes.length value_data >= 4 then
            Lifetime (Int32.to_int (get_uint32_be value_data 0))
          else Unknown_attr value_data
        | DATA ->
          Data_attr value_data
        | REQUESTED_TRANSPORT ->
          if Bytes.length value_data >= 1 then
            Requested_transport (Char.code (Bytes.get value_data 0))
          else Unknown_attr value_data
        | EVEN_PORT ->
          if Bytes.length value_data >= 1 then
            Even_port ((Char.code (Bytes.get value_data 0) land 0x80) <> 0)
          else Unknown_attr value_data
        | DONT_FRAGMENT ->
          Dont_fragment
        | RESERVATION_TOKEN ->
          Reservation_token value_data
        | _ -> Unknown_attr value_data
      in
      Ok ({ attr_type; value }, 4 + padded_len)

(* ============================================
   Message encoding/decoding
   ============================================ *)

let encode msg =
  (* Encode attributes first *)
  let attr_bytes = List.map encode_attribute msg.attributes in
  let attr_len = List.fold_left (fun acc b -> acc + Bytes.length b) 0 attr_bytes in

  (* Header: 20 bytes *)
  let header = Bytes.create 20 in
  let msg_type = encode_message_type msg.msg_class msg.msg_method in
  set_uint16_be header 0 msg_type;
  set_uint16_be header 2 attr_len;
  set_uint32_be header 4 magic_cookie;
  Bytes.blit msg.transaction_id 0 header 8 12;

  (* Combine *)
  let result = Bytes.create (20 + attr_len) in
  Bytes.blit header 0 result 0 20;
  let _ = List.fold_left (fun off attr_b ->
    Bytes.blit attr_b 0 result off (Bytes.length attr_b);
    off + Bytes.length attr_b
  ) 20 attr_bytes in
  result

let decode data =
  if Bytes.length data < 20 then
    Error "Message too short (< 20 bytes)"
  else
    (* Check first two bits are 0 *)
    let first_byte = Char.code (Bytes.get data 0) in
    if (first_byte land 0xC0) <> 0 then
      Error "Invalid STUN message: first two bits must be 0"
    else
      (* Check magic cookie *)
      let cookie = get_uint32_be data 4 in
      if cookie <> magic_cookie then
        Error (Printf.sprintf "Invalid magic cookie: 0x%08lX (expected 0x2112A442)" cookie)
      else
        let msg_type = get_uint16_be data 0 in
        let msg_len = get_uint16_be data 2 in
        if Bytes.length data < 20 + msg_len then
          Error "Message truncated"
        else
          let (msg_class, msg_method) = decode_message_type msg_type in
          let transaction_id = Bytes.sub data 8 12 in

          (* Decode attributes *)
          let rec decode_attrs off acc =
            if off >= 20 + msg_len then
              Ok (List.rev acc)
            else
              match decode_attribute data off with
              | Ok (attr, len) -> decode_attrs (off + len) (attr :: acc)
              | Error e -> Error e
          in
          match decode_attrs 20 [] with
          | Ok attributes ->
            Ok { msg_class; msg_method; transaction_id; attributes }
          | Error e -> Error e

(* ============================================
   Message construction
   ============================================ *)

let create_binding_request ?transaction_id () =
  let tid = match transaction_id with
    | Some id -> id
    | None -> generate_transaction_id ()
  in
  {
    msg_class = Request;
    msg_method = Binding;
    transaction_id = tid;
    attributes = [];
  }

let create_binding_response ~transaction_id ~mapped_address =
  (* XOR the address *)
  let xored = xor_address mapped_address transaction_id in
  {
    msg_class = Success_response;
    msg_method = Binding;
    transaction_id;
    attributes = [
      { attr_type = XOR_MAPPED_ADDRESS; value = Xor_mapped_address xored };
    ];
  }

let create_error_response ~transaction_id ~error ?reason () =
  let code = error_code_to_int error in
  let reason_str = match reason with
    | Some r -> r
    | None -> match error with
      | Try_alternate -> "Try Alternate"
      | Bad_request -> "Bad Request"
      | Unauthorized -> "Unauthorized"
      | Unknown_attribute -> "Unknown Attribute"
      | Stale_nonce -> "Stale Nonce"
      | Server_error -> "Server Error"
  in
  {
    msg_class = Error_response;
    msg_method = Binding;
    transaction_id;
    attributes = [
      { attr_type = ERROR_CODE; value = Error_code { code; reason = reason_str } };
    ];
  }

(* ============================================
   RFC 5766 TURN Message Construction
   ============================================ *)

(** Create a TURN Allocate Request message.
    @param transaction_id Optional transaction ID (generated if not provided)
    @param transport Transport protocol (17 = UDP, 6 = TCP, default: UDP)
    @param lifetime Optional requested lifetime in seconds
    @param dont_fragment Include DONT-FRAGMENT attribute
    @return TURN Allocate Request message

    RFC 5766 Section 6.1: The client forms an Allocate request by:
    - Setting the message type to Allocate Request (0x003)
    - Including REQUESTED-TRANSPORT attribute (required)
    - Optionally including LIFETIME, DONT-FRAGMENT, EVEN-PORT attributes *)
let create_allocate_request ?transaction_id ?(transport = 17) ?lifetime
    ?(dont_fragment = false) () =
  let tid = match transaction_id with
    | Some id -> id
    | None -> generate_transaction_id ()
  in
  let attrs = [
    { attr_type = REQUESTED_TRANSPORT; value = Requested_transport transport };
  ] in
  let attrs = match lifetime with
    | Some l -> { attr_type = LIFETIME; value = Lifetime l } :: attrs
    | None -> attrs
  in
  let attrs = if dont_fragment
    then { attr_type = DONT_FRAGMENT; value = Dont_fragment } :: attrs
    else attrs
  in
  {
    msg_class = Request;
    msg_method = Allocate;
    transaction_id = tid;
    attributes = attrs;
  }

(** Create a TURN Allocate Success Response message.
    @param transaction_id Transaction ID from request
    @param relayed_address The allocated relay address (XOR encoded)
    @param mapped_address Client's server-reflexive address (XOR encoded)
    @param lifetime Allocation lifetime in seconds
    @return TURN Allocate Success Response message

    RFC 5766 Section 6.3: The server returns XOR-RELAYED-ADDRESS,
    LIFETIME, and optionally XOR-MAPPED-ADDRESS. *)
let create_allocate_response ~transaction_id ~relayed_address ~mapped_address
    ~lifetime =
  let xored_relay = xor_address relayed_address transaction_id in
  let xored_mapped = xor_address mapped_address transaction_id in
  {
    msg_class = Success_response;
    msg_method = Allocate;
    transaction_id;
    attributes = [
      { attr_type = XOR_RELAYED_ADDRESS; value = Xor_relayed_address xored_relay };
      { attr_type = XOR_MAPPED_ADDRESS; value = Xor_mapped_address xored_mapped };
      { attr_type = LIFETIME; value = Lifetime lifetime };
    ];
  }

(** Create a TURN Refresh Request message.
    @param transaction_id Optional transaction ID
    @param lifetime Requested lifetime (0 to deallocate)
    @return TURN Refresh Request message

    RFC 5766 Section 7: Refresh is used to refresh an allocation
    or to delete it (by setting lifetime to 0). *)
let create_refresh_request ?transaction_id ~lifetime () =
  let tid = match transaction_id with
    | Some id -> id
    | None -> generate_transaction_id ()
  in
  {
    msg_class = Request;
    msg_method = Refresh;
    transaction_id = tid;
    attributes = [
      { attr_type = LIFETIME; value = Lifetime lifetime };
    ];
  }

(** TURN Allocate result containing the relayed address and lifetime *)
type allocate_result = {
  relayed_address: address;  (** Allocated relay address *)
  mapped_address: address;   (** Client's reflexive address *)
  lifetime: int;             (** Allocation lifetime in seconds *)
}

(** TURN error codes (RFC 5766 Section 15) *)
type turn_error =
  | Allocation_mismatch     (** 437 - Allocation mismatch *)
  | Wrong_credentials       (** 441 - Wrong credentials *)
  | Unsupported_transport   (** 442 - Unsupported transport protocol *)
  | Allocation_quota_reached (** 486 - Allocation quota reached *)
  | Insufficient_capacity   (** 508 - Insufficient capacity *)

let turn_error_to_int = function
  | Allocation_mismatch -> 437
  | Wrong_credentials -> 441
  | Unsupported_transport -> 442
  | Allocation_quota_reached -> 486
  | Insufficient_capacity -> 508

let int_to_turn_error = function
  | 437 -> Some Allocation_mismatch
  | 441 -> Some Wrong_credentials
  | 442 -> Some Unsupported_transport
  | 486 -> Some Allocation_quota_reached
  | 508 -> Some Insufficient_capacity
  | _ -> None

(** Extract allocate result from a TURN Allocate Success Response.
    @param msg TURN Allocate Success Response message
    @return Allocate result or error string *)
let parse_allocate_response msg =
  if msg.msg_class <> Success_response || msg.msg_method <> Allocate then
    Error "Not an Allocate Success Response"
  else
    let rec find_attrs relayed mapped lt = function
      | [] -> (relayed, mapped, lt)
      | { value = Xor_relayed_address addr; _ } :: rest ->
        let unxored = unxor_address addr msg.transaction_id in
        find_attrs (Some unxored) mapped lt rest
      | { value = Xor_mapped_address addr; _ } :: rest ->
        let unxored = unxor_address addr msg.transaction_id in
        find_attrs relayed (Some unxored) lt rest
      | { value = Lifetime l; _ } :: rest ->
        find_attrs relayed mapped (Some l) rest
      | _ :: rest -> find_attrs relayed mapped lt rest
    in
    match find_attrs None None None msg.attributes with
    | Some relayed, Some mapped, Some lifetime ->
      Ok { relayed_address = relayed; mapped_address = mapped; lifetime }
    | Some relayed, None, Some lifetime ->
      (* XOR-MAPPED-ADDRESS is optional *)
      let dummy_mapped = { family = IPv4; port = 0; ip = "0.0.0.0" } in
      Ok { relayed_address = relayed; mapped_address = dummy_mapped; lifetime }
    | _ -> Error "Missing required attributes in Allocate Response"

(** Send TURN Allocate request and get response (Lwt async).
    This is an unauthenticated allocate for testing with local TURN servers.
    @param server TURN server address (host:port)
    @param timeout Timeout in seconds (default: 5.0)
    @return Allocate result or error Lwt promise

    RFC 5766 Section 6: Allocate transaction establishes the allocation
    and returns the relayed transport address. *)
let allocate_request_lwt ~server ?(transport = 17) ?lifetime ?timeout () =
  let open Lwt.Infix in
  let timeout_s = Option.value ~default:5.0 timeout in

  (* Parse server address *)
  let parsed = match String.split_on_char ':' server with
    | [h; p] -> Some (h, int_of_string p)
    | [h] -> Some (h, default_port)
    | _ -> None
  in
  match parsed with
  | None -> Lwt.return (Error "Invalid TURN server address")
  | Some (host, port) ->

  (* Create Allocate request *)
  let request = create_allocate_request ~transport ?lifetime () in
  let request_bytes = encode request in

  (* Resolve address *)
  Lwt_unix.getaddrinfo host (string_of_int port)
    [Unix.AI_FAMILY Unix.PF_INET; Unix.AI_SOCKTYPE Unix.SOCK_DGRAM]
  >>= fun addrs ->
  match addrs with
  | [] -> Lwt.return (Error "Could not resolve TURN server address")
  | addr :: _ ->
    (* Create UDP socket *)
    let sock = Lwt_unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in

    (* Send request *)
    Lwt_unix.sendto sock request_bytes 0 (Bytes.length request_bytes) []
      addr.Unix.ai_addr
    >>= fun _sent ->

    (* Receive response with timeout *)
    let response_buf = Bytes.create 1500 in
    let recv_promise =
      Lwt_unix.recvfrom sock response_buf 0 1500 []
      >>= fun (len, _from) ->
      Lwt.return (Bytes.sub response_buf 0 len)
    in

    Lwt.pick [
      recv_promise;
      (Lwt_unix.sleep timeout_s >>= fun () -> Lwt.fail (Failure "Timeout"));
    ]
    >>= fun result ->

    Lwt_unix.close sock >>= fun () ->

    (* Decode response *)
    match decode result with
    | Error e -> Lwt.return (Error e)
    | Ok response ->
      (* Verify transaction ID *)
      if not (Bytes.equal response.transaction_id request.transaction_id) then
        Lwt.return (Error "Transaction ID mismatch")
      else if response.msg_class = Error_response then begin
        (* Extract error code *)
        let rec find_error = function
          | [] -> None
          | { value = Error_code { code; reason }; _ } :: _ ->
            Some (code, reason)
          | _ :: rest -> find_error rest
        in
        match find_error response.attributes with
        | Some (401, _) -> Lwt.return (Error "Unauthorized (401): Authentication required")
        | Some (438, _) -> Lwt.return (Error "Stale Nonce (438)")
        | Some (code, reason) ->
          Lwt.return (Error (Printf.sprintf "TURN error %d: %s" code reason))
        | None -> Lwt.return (Error "TURN error response (unknown error)")
      end else
        match parse_allocate_response response with
        | Ok result -> Lwt.return (Ok result)
        | Error e -> Lwt.return (Error e)

(* ============================================
   Message Integrity (HMAC-SHA1)
   ============================================ *)

(** HMAC-SHA1 using digestif library *)
let hmac_sha1 ~key data =
  let data_str = Bytes.to_string data in
  Digestif.SHA1.hmac_string ~key data_str
  |> Digestif.SHA1.to_raw_string
  |> Bytes.of_string

(** Calculate MESSAGE-INTEGRITY attribute value.
    Per RFC 5389, HMAC covers the STUN message up to (but excluding)
    MESSAGE-INTEGRITY, with adjusted length to include the attribute. *)
let calculate_integrity msg ~key =
  (* Encode message, adjust length to include MESSAGE-INTEGRITY (24 bytes) *)
  let encoded = encode msg in
  let adjusted_len = (get_uint16_be encoded 2) + 24 in
  set_uint16_be encoded 2 adjusted_len;

  (* HMAC-SHA1 over the adjusted message *)
  hmac_sha1 ~key encoded

let verify_integrity msg ~key =
  (* Find MESSAGE-INTEGRITY attribute *)
  let rec find_integrity = function
    | [] -> None
    | { attr_type = MESSAGE_INTEGRITY; value = Message_integrity b; _ } :: _ -> Some b
    | _ :: rest -> find_integrity rest
  in
  match find_integrity msg.attributes with
  | None -> false
  | Some expected ->
    let calculated = calculate_integrity msg ~key in
    Bytes.equal expected calculated

(* ============================================
   Fingerprint (CRC-32)
   ============================================ *)

(* CRC-32 table *)
let crc32_table =
  Array.init 256 (fun i ->
    let rec loop j crc =
      if j = 8 then crc
      else if Int32.(logand crc 1l) = 1l then
        loop (j + 1) Int32.(logxor (shift_right_logical crc 1) 0xEDB88320l)
      else
        loop (j + 1) Int32.(shift_right_logical crc 1)
    in
    loop 0 (Int32.of_int i)
  )

let crc32 data =
  let crc = ref 0xFFFFFFFFl in
  for i = 0 to Bytes.length data - 1 do
    let byte = Char.code (Bytes.get data i) in
    let index = Int32.(to_int (logand (logxor !crc (of_int byte)) 0xFFl)) in
    crc := Int32.(logxor (shift_right_logical !crc 8) crc32_table.(index))
  done;
  Int32.logxor !crc 0xFFFFFFFFl

let calculate_fingerprint data =
  let crc = crc32 data in
  Int32.logxor crc 0x5354554el  (* XOR with "STUN" *)

let verify_fingerprint msg =
  let rec find_fingerprint = function
    | [] -> None
    | { attr_type = FINGERPRINT; value = Fingerprint fp; _ } :: _ -> Some fp
    | _ :: rest -> find_fingerprint rest
  in
  match find_fingerprint msg.attributes with
  | None -> false
  | Some expected ->
    (* Encode without fingerprint, add fingerprint length *)
    let attrs_without_fp = List.filter (fun a -> a.attr_type <> FINGERPRINT) msg.attributes in
    let msg_without_fp = { msg with attributes = attrs_without_fp } in
    let encoded = encode msg_without_fp in
    (* Adjust length to include FINGERPRINT (8 bytes) *)
    let adjusted_len = (get_uint16_be encoded 2) + 8 in
    set_uint16_be encoded 2 adjusted_len;
    let calculated = calculate_fingerprint encoded in
    expected = calculated

(* ============================================
   Utilities
   ============================================ *)

let is_stun_message data =
  if Bytes.length data < 20 then false
  else
    (* First two bits must be 0 *)
    let first_byte = Char.code (Bytes.get data 0) in
    if (first_byte land 0xC0) <> 0 then false
    else
      (* Check magic cookie *)
      let cookie = get_uint32_be data 4 in
      cookie = magic_cookie

let pp_message fmt msg =
  Format.fprintf fmt "STUN %s %s@."
    (string_of_method msg.msg_method)
    (string_of_class msg.msg_class);
  Format.fprintf fmt "  Transaction ID: ";
  for i = 0 to 11 do
    Format.fprintf fmt "%02X" (Char.code (Bytes.get msg.transaction_id i))
  done;
  Format.fprintf fmt "@.";
  List.iter (fun attr ->
    Format.fprintf fmt "  %s: " (string_of_attr_type attr.attr_type);
    (match attr.value with
     | Mapped_address addr | Xor_mapped_address addr
     | Xor_peer_address addr | Xor_relayed_address addr ->
       Format.fprintf fmt "%s:%d" addr.ip addr.port
     | Username s | Software s | Realm s | Nonce s ->
       Format.fprintf fmt "%S" s
     | Message_integrity _ ->
       Format.fprintf fmt "<20 bytes>"
     | Fingerprint fp ->
       Format.fprintf fmt "0x%08lX" fp
     | Error_code { code; reason } ->
       Format.fprintf fmt "%d %s" code reason
     | Channel_number n ->
       Format.fprintf fmt "0x%04X" n
     | Lifetime n ->
       Format.fprintf fmt "%d seconds" n
     | Data_attr b | Reservation_token b ->
       Format.fprintf fmt "<%d bytes>" (Bytes.length b)
     | Requested_transport t ->
       Format.fprintf fmt "%d (%s)" t (if t = 17 then "UDP" else if t = 6 then "TCP" else "?")
     | Even_port b ->
       Format.fprintf fmt "%b" b
     | Dont_fragment ->
       Format.fprintf fmt "true"
     | Unknown_attr b ->
       Format.fprintf fmt "<%d bytes>" (Bytes.length b));
    Format.fprintf fmt "@."
  ) msg.attributes

(* ============================================
   Client Functions (Lwt-based)
   ============================================ *)

let binding_request_lwt ~server ?timeout () =
  let open Lwt.Infix in
  let timeout_s = Option.value ~default:3.0 timeout in

  (* Parse server address *)
  let parsed = match String.split_on_char ':' server with
    | [h; p] -> Some (h, int_of_string p)
    | [h] -> Some (h, default_port)
    | _ -> None
  in
  match parsed with
  | None -> Lwt.return (Error "Invalid server address")
  | Some (host, port) ->

  (* Create request *)
  let request = create_binding_request () in
  let request_bytes = encode request in

  (* Resolve address *)
  Lwt_unix.getaddrinfo host (string_of_int port) [Unix.AI_FAMILY Unix.PF_INET; Unix.AI_SOCKTYPE Unix.SOCK_DGRAM]
  >>= fun addrs ->
  match addrs with
  | [] -> Lwt.return (Error "Could not resolve server address")
  | addr :: _ ->
    (* Create UDP socket *)
    let sock = Lwt_unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in

    let start_time = Unix.gettimeofday () in

    (* Send request *)
    Lwt_unix.sendto sock request_bytes 0 (Bytes.length request_bytes) [] addr.Unix.ai_addr
    >>= fun _sent ->

    (* Get local address after socket is bound *)
    let local_addr = Lwt_unix.getsockname sock in

    (* Receive response with timeout *)
    let response_buf = Bytes.create 576 in  (* Max STUN message size *)

    let recv_promise =
      Lwt_unix.recvfrom sock response_buf 0 576 []
      >>= fun (len, _from) ->
      Lwt.return (Bytes.sub response_buf 0 len)
    in

    Lwt.pick [
      recv_promise;
      (Lwt_unix.sleep timeout_s >>= fun () -> Lwt.fail (Failure "Timeout"));
    ]
    >>= fun result ->

    let end_time = Unix.gettimeofday () in
    let rtt_ms = (end_time -. start_time) *. 1000.0 in

    Lwt_unix.close sock >>= fun () ->

    (* Decode response *)
    match decode result with
    | Error e -> Lwt.return (Error e)
    | Ok response ->
      (* Verify transaction ID *)
      if not (Bytes.equal response.transaction_id request.transaction_id) then
        Lwt.return (Error "Transaction ID mismatch")
      else if response.msg_class = Error_response then
        Lwt.return (Error "STUN error response")
      else
        (* Extract mapped address *)
        let rec find_addr = function
          | [] -> None
          | { value = Xor_mapped_address addr; _ } :: _ ->
            Some (unxor_address addr request.transaction_id)
          | { value = Mapped_address addr; _ } :: _ ->
            Some addr
          | _ :: rest -> find_addr rest
        in
        let rec find_software = function
          | [] -> None
          | { value = Software s; _ } :: _ -> Some s
          | _ :: rest -> find_software rest
        in
        match find_addr response.attributes with
        | None -> Lwt.return (Error "No mapped address in response")
        | Some mapped_address ->
          (* Extract local address from socket *)
          let local_address = match local_addr with
            | Unix.ADDR_INET (ip, p) ->
              { family = IPv4; port = p; ip = Unix.string_of_inet_addr ip }
            | Unix.ADDR_UNIX _ ->
              { family = IPv4; port = 0; ip = "0.0.0.0" }
          in
          Lwt.return (Ok {
            local_address;
            mapped_address;
            server_software = find_software response.attributes;
            rtt_ms;
          })

(* Synchronous wrapper using Lwt_main.run - for simple testing *)
let binding_request_sync ~server ?timeout () =
  Lwt_main.run (binding_request_lwt ~server ?timeout ())
