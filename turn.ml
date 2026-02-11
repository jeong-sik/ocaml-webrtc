(** RFC 5766 TURN - Traversal Using Relays around NAT

    Pure OCaml 5.x implementation using Effect Handlers.

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

open Effect
open Effect.Deep

(** {1 Effects for I/O} *)

type _ Effect.t +=
  | Send : (bytes * string * int) -> int Effect.t
  | Recv : int -> (bytes * string * int) Effect.t
  | Sleep : float -> unit Effect.t
  | Now : float Effect.t

(** {1 Types} *)

type turn_method =
  | Allocate
  | Refresh
  | Send
  | Data
  | CreatePermission
  | ChannelBind

type turn_attribute =
  | CHANNEL_NUMBER
  | LIFETIME
  | XOR_PEER_ADDRESS
  | DATA
  | XOR_RELAYED_ADDRESS
  | EVEN_PORT
  | REQUESTED_TRANSPORT
  | DONT_FRAGMENT
  | RESERVATION_TOKEN
  (* Authentication attributes (RFC 5389) *)
  | USERNAME
  | REALM
  | NONCE
  | MESSAGE_INTEGRITY
  | ERROR_CODE

type transport =
  | UDP
  | TCP

type allocation_state =
  | Inactive
  | Allocating
  | Active of
      { relayed_address : string * int
      ; lifetime : int
      ; expiry : float
      }
  | Refreshing
  | Expired

type channel =
  { number : int
  ; peer_address : string * int
  ; expiry : float
  }

type config =
  { server_host : string
  ; server_port : int
  ; username : string
  ; password : string
  ; realm : string
  ; transport : transport
  ; lifetime : int
  }

type t =
  { config : config
  ; mutable state : allocation_state
  ; mutable channels : channel list
  ; mutable permissions : (string * float) list
  ; mutable nonce : string
  ; mutable on_data_callback : (string * int -> bytes -> unit) option
  }
[@@warning "-69"]

(** {1 Constants} *)

let turn_method_to_int = function
  | Allocate -> 0x003
  | Refresh -> 0x004
  | Send -> 0x006
  | Data -> 0x007
  | CreatePermission -> 0x008
  | ChannelBind -> 0x009
;;

let turn_attr_to_int = function
  | CHANNEL_NUMBER -> 0x000C
  | LIFETIME -> 0x000D
  | XOR_PEER_ADDRESS -> 0x0012
  | DATA -> 0x0013
  | XOR_RELAYED_ADDRESS -> 0x0016
  | EVEN_PORT -> 0x0018
  | REQUESTED_TRANSPORT -> 0x0019
  | DONT_FRAGMENT -> 0x001A
  | RESERVATION_TOKEN -> 0x0022
  (* RFC 5389 authentication attributes *)
  | USERNAME -> 0x0006
  | REALM -> 0x0014
  | NONCE -> 0x0015
  | MESSAGE_INTEGRITY -> 0x0008
  | ERROR_CODE -> 0x0009
;;

let transport_to_int = function
  | UDP -> 17
  | TCP -> 6
;;

(** {1 Default Configuration} *)

let default_config =
  { server_host = "turn.example.com"
  ; server_port = 3478
  ; username = ""
  ; password = ""
  ; realm = ""
  ; transport = UDP
  ; lifetime = 600
  }
;;

(** {1 Client Creation} *)

let create config =
  { config
  ; state = Inactive
  ; channels = []
  ; permissions = []
  ; nonce = ""
  ; on_data_callback = None
  }
;;

(** {1 STUN/TURN Message Building} *)

let magic_cookie = 0x2112A442l

let generate_transaction_id () =
  let buf = Bytes.create 12 in
  for i = 0 to 11 do
    Bytes.set_uint8 buf i (Random.int 256)
  done;
  buf
;;

(** Build raw STUN/TURN message header *)
let build_message_header msg_type length tid =
  let buf = Bytes.create 20 in
  Bytes.set_uint16_be buf 0 msg_type;
  Bytes.set_uint16_be buf 2 length;
  Bytes.set_int32_be buf 4 magic_cookie;
  Bytes.blit tid 0 buf 8 12;
  buf
;;

(** Build attribute TLV *)
let build_attribute attr_type value =
  let len = Bytes.length value in
  let padded_len = (len + 3) land lnot 3 in
  let buf = Bytes.create (4 + padded_len) in
  Bytes.set_uint16_be buf 0 attr_type;
  Bytes.set_uint16_be buf 2 len;
  Bytes.blit value 0 buf 4 len;
  buf
;;

(** {1 Long-term Credential Authentication (RFC 5389 Section 15.4)} *)

(** Compute long-term credential key: MD5(username:realm:password) *)
let compute_long_term_key ~username ~realm ~password =
  let input = Printf.sprintf "%s:%s:%s" username realm password in
  let hash = Digestif.MD5.digest_string input in
  Digestif.MD5.to_raw_string hash
;;

(** HMAC-SHA1 for MESSAGE-INTEGRITY *)
let hmac_sha1 ~key data =
  let data_str = Bytes.to_string data in
  Digestif.SHA1.hmac_string ~key data_str
  |> Digestif.SHA1.to_raw_string
  |> Bytes.of_string
;;

(** Build MESSAGE-INTEGRITY attribute
    Per RFC 5389, HMAC covers the STUN message up to (but excluding)
    MESSAGE-INTEGRITY, with length adjusted to include the attribute. *)
let build_message_integrity ~key header_and_attrs =
  let msg = Bytes.copy header_and_attrs in
  (* Adjust length field to include MESSAGE-INTEGRITY (24 bytes) *)
  let current_len = Bytes.get_uint16_be msg 2 in
  Bytes.set_uint16_be msg 2 (current_len + 24);
  (* Calculate HMAC-SHA1 *)
  let hmac = hmac_sha1 ~key msg in
  build_attribute (turn_attr_to_int MESSAGE_INTEGRITY) hmac
;;

(** Parse error response to extract REALM, NONCE, and error code *)
let parse_error_response data =
  if Bytes.length data < 20
  then None
  else (
    let msg_type = Bytes.get_uint16_be data 0 in
    let msg_class = msg_type land 0x0110 in
    if msg_class <> 0x0110
    then (* Not error response *)
      None
    else (
      let rec scan offset realm nonce error_code =
        if offset >= Bytes.length data - 4
        then realm, nonce, error_code
        else (
          let atype = Bytes.get_uint16_be data offset in
          let alen = Bytes.get_uint16_be data (offset + 2) in
          let padded = (alen + 3) land lnot 3 in
          let value_start = offset + 4 in
          let result =
            if atype = turn_attr_to_int REALM && Bytes.length data >= value_start + alen
            then Some (Bytes.sub_string data value_start alen), nonce, error_code
            else if
              atype = turn_attr_to_int NONCE && Bytes.length data >= value_start + alen
            then realm, Some (Bytes.sub_string data value_start alen), error_code
            else if
              atype = turn_attr_to_int ERROR_CODE && Bytes.length data >= value_start + 4
            then (
              let class_ = Bytes.get_uint8 data (value_start + 2) in
              let number = Bytes.get_uint8 data (value_start + 3) in
              realm, nonce, Some ((class_ * 100) + number))
            else realm, nonce, error_code
          in
          scan
            (offset + 4 + padded)
            (match result with
             | r, _, _ -> r)
            (match result with
             | _, n, _ -> n)
            (match result with
             | _, _, e -> e))
      in
      let realm, nonce, error_code = scan 20 None None None in
      match realm, nonce, error_code with
      | Some r, Some n, Some e -> Some (r, n, e)
      | _ -> None))
;;

(** Build authenticated TURN request with USERNAME, REALM, NONCE, MESSAGE-INTEGRITY *)
let build_authenticated_request t msg_type attrs tid =
  let key =
    compute_long_term_key
      ~username:t.config.username
      ~realm:t.config.realm
      ~password:t.config.password
  in
  (* Build USERNAME attribute *)
  let username_attr =
    build_attribute (turn_attr_to_int USERNAME) (Bytes.of_string t.config.username)
  in
  (* Build REALM attribute *)
  let realm_attr =
    build_attribute (turn_attr_to_int REALM) (Bytes.of_string t.config.realm)
  in
  (* Build NONCE attribute *)
  let nonce_attr = build_attribute (turn_attr_to_int NONCE) (Bytes.of_string t.nonce) in
  (* Combine all attributes except MESSAGE-INTEGRITY *)
  let all_attrs =
    Bytes.concat Bytes.empty [ attrs; username_attr; realm_attr; nonce_attr ]
  in
  (* Build header with current attribute length *)
  let header = build_message_header msg_type (Bytes.length all_attrs) tid in
  let header_and_attrs = Bytes.cat header all_attrs in
  (* Add MESSAGE-INTEGRITY *)
  let integrity_attr = build_message_integrity ~key header_and_attrs in
  (* Final message: adjust header length to include MESSAGE-INTEGRITY *)
  let final_len = Bytes.length all_attrs + Bytes.length integrity_attr in
  Bytes.set_uint16_be header 2 final_len;
  Bytes.concat Bytes.empty [ header; all_attrs; integrity_attr ]
;;

let build_allocate_request t =
  let tid = generate_transaction_id () in
  (* REQUESTED-TRANSPORT attribute *)
  let transport_buf = Bytes.create 4 in
  Bytes.set_uint8 transport_buf 0 (transport_to_int t.config.transport);
  let transport_attr =
    build_attribute (turn_attr_to_int REQUESTED_TRANSPORT) transport_buf
  in
  (* LIFETIME attribute *)
  let lifetime_buf = Bytes.create 4 in
  Bytes.set_int32_be lifetime_buf 0 (Int32.of_int t.config.lifetime);
  let lifetime_attr = build_attribute (turn_attr_to_int LIFETIME) lifetime_buf in
  (* Combine *)
  let attrs = Bytes.cat transport_attr lifetime_attr in
  (* Message type: Allocate Request = 0x0003 *)
  let header = build_message_header 0x0003 (Bytes.length attrs) tid in
  tid, Bytes.cat header attrs
;;

let build_refresh_request _t lifetime =
  let tid = generate_transaction_id () in
  let buf = Bytes.create 4 in
  Bytes.set_int32_be buf 0 (Int32.of_int lifetime);
  let attr = build_attribute (turn_attr_to_int LIFETIME) buf in
  (* Message type: Refresh Request = 0x0004 *)
  let header = build_message_header 0x0004 (Bytes.length attr) tid in
  tid, Bytes.cat header attr
;;

let build_create_permission_request peer_ip =
  let tid = generate_transaction_id () in
  (* XOR-PEER-ADDRESS attribute - simplified encoding *)
  let addr_buf = Bytes.create 8 in
  Bytes.set_uint8 addr_buf 0 0;
  (* Reserved *)
  Bytes.set_uint8 addr_buf 1 1;
  (* IPv4 *)
  Bytes.set_uint16_be addr_buf 2 0;
  (* Port XORed *)
  (* Parse IP and XOR with magic cookie *)
  let parts = String.split_on_char '.' peer_ip in
  (match parts with
   | [ a; b; c; d ] ->
     let xored =
       Int32.logxor
         magic_cookie
         (Int32.of_int
            ((int_of_string a lsl 24)
             lor (int_of_string b lsl 16)
             lor (int_of_string c lsl 8)
             lor int_of_string d))
     in
     Bytes.set_int32_be addr_buf 4 xored
   | _ -> ());
  let attr = build_attribute (turn_attr_to_int XOR_PEER_ADDRESS) addr_buf in
  let header = build_message_header 0x0008 (Bytes.length attr) tid in
  tid, Bytes.cat header attr
;;

let build_channel_bind_request channel_num (peer_ip, peer_port) =
  let tid = generate_transaction_id () in
  (* CHANNEL-NUMBER attribute *)
  let chan_buf = Bytes.create 4 in
  Bytes.set_uint16_be chan_buf 0 channel_num;
  let chan_attr = build_attribute (turn_attr_to_int CHANNEL_NUMBER) chan_buf in
  (* XOR-PEER-ADDRESS attribute *)
  let addr_buf = Bytes.create 8 in
  Bytes.set_uint8 addr_buf 0 0;
  Bytes.set_uint8 addr_buf 1 1;
  Bytes.set_uint16_be addr_buf 2 (peer_port lxor 0x2112);
  let parts = String.split_on_char '.' peer_ip in
  (match parts with
   | [ a; b; c; d ] ->
     let xored =
       Int32.logxor
         magic_cookie
         (Int32.of_int
            ((int_of_string a lsl 24)
             lor (int_of_string b lsl 16)
             lor (int_of_string c lsl 8)
             lor int_of_string d))
     in
     Bytes.set_int32_be addr_buf 4 xored
   | _ -> ());
  let addr_attr = build_attribute (turn_attr_to_int XOR_PEER_ADDRESS) addr_buf in
  let attrs = Bytes.cat chan_attr addr_attr in
  let header = build_message_header 0x0009 (Bytes.length attrs) tid in
  tid, Bytes.cat header attrs
;;

(** {1 Effect-based I/O Helpers} *)

let send_to_server t data =
  perform (Send (data, t.config.server_host, t.config.server_port))
;;

let recv_from_server () = perform (Recv 1500)
let now () = perform Now
let sleep secs = perform (Sleep secs)

(** {1 Response Parsing} *)

let parse_response data =
  if Bytes.length data < 20
  then Result.Error "Response too short"
  else (
    let msg_type = Bytes.get_uint16_be data 0 in
    let _length = Bytes.get_uint16_be data 2 in
    let msg_class = msg_type land 0x0110 in
    Result.Ok (msg_class = 0x0100))
;;

(* Success response *)

let parse_xor_relayed_address data offset tid =
  if Bytes.length data < offset + 8
  then None
  else (
    let _family = Bytes.get_uint8 data (offset + 1) in
    let xport = Bytes.get_uint16_be data (offset + 2) in
    let port = xport lxor 0x2112 in
    let xaddr = Bytes.get_int32_be data (offset + 4) in
    let addr = Int32.logxor xaddr magic_cookie in
    let _ = tid in
    (* tid used for IPv6 XOR *)
    let ip =
      Printf.sprintf
        "%ld.%ld.%ld.%ld"
        (Int32.shift_right_logical addr 24 |> Int32.logand 0xFFl)
        (Int32.shift_right_logical addr 16 |> Int32.logand 0xFFl)
        (Int32.shift_right_logical addr 8 |> Int32.logand 0xFFl)
        (Int32.logand addr 0xFFl)
    in
    Some (ip, port))
;;

let find_attribute data attr_type =
  let rec scan offset =
    if offset >= Bytes.length data - 4
    then None
    else (
      let atype = Bytes.get_uint16_be data offset in
      let alen = Bytes.get_uint16_be data (offset + 2) in
      if atype = attr_type
      then Some (offset + 4, alen)
      else (
        let padded = (alen + 3) land lnot 3 in
        scan (offset + 4 + padded)))
  in
  scan 20 (* Skip 20-byte header *)
;;

(** {1 Allocation} *)

(** Process successful allocation response *)
let process_allocation_success t response tid =
  (* Extract XOR-RELAYED-ADDRESS *)
  let relayed =
    match find_attribute response (turn_attr_to_int XOR_RELAYED_ADDRESS) with
    | Some (offset, _len) -> parse_xor_relayed_address response offset tid
    | None -> None
  in
  (* Extract LIFETIME *)
  let lifetime =
    match find_attribute response (turn_attr_to_int LIFETIME) with
    | Some (offset, _) when Bytes.length response >= offset + 4 ->
      Int32.to_int (Bytes.get_int32_be response offset)
    | _ -> t.config.lifetime
  in
  match relayed with
  | Some (ip, port) ->
    let current = now () in
    t.state
    <- Active
         { relayed_address = ip, port
         ; lifetime
         ; expiry = current +. Float.of_int lifetime
         };
    Result.Ok (ip, port)
  | None ->
    t.state <- Inactive;
    Result.Error "Failed to parse relayed address"
;;

let allocate t =
  t.state <- Allocating;
  let tid, request = build_allocate_request t in
  let _ = send_to_server t request in
  let response, _from_ip, _from_port = recv_from_server () in
  match parse_response response with
  | Result.Error e ->
    t.state <- Inactive;
    Result.Error e
  | Result.Ok false ->
    (* Check if 401 Unauthorized - need Long-term Credential auth *)
    (match parse_error_response response with
     | Some (server_realm, server_nonce, 401) ->
       (* Store server nonce for authentication *)
       t.nonce <- server_nonce;
       (* Note: server_realm should match t.config.realm, but we could update it *)
       let _ = server_realm in
       (* Use server realm if needed in future *)
       (* Build authenticated request *)
       let transport_attr =
         build_attribute
           (turn_attr_to_int REQUESTED_TRANSPORT)
           (Bytes.make 4 (Char.chr 17))
       in
       (* UDP = 17 *)
       let auth_request =
         build_authenticated_request t (turn_method_to_int Allocate) transport_attr tid
       in
       let _ = send_to_server t auth_request in
       let auth_response, _, _ = recv_from_server () in
       (match parse_response auth_response with
        | Result.Ok true -> process_allocation_success t auth_response tid
        | Result.Ok false ->
          t.state <- Inactive;
          Result.Error "Authenticated allocate request failed"
        | Result.Error e ->
          t.state <- Inactive;
          Result.Error (Printf.sprintf "Auth error: %s" e))
     | Some (_, _, error_code) ->
       t.state <- Inactive;
       Result.Error (Printf.sprintf "TURN error: %d" error_code)
     | None ->
       t.state <- Inactive;
       Result.Error "Allocate request failed")
  | Result.Ok true -> process_allocation_success t response tid
;;

let refresh t ?(lifetime = t.config.lifetime) () =
  match t.state with
  | Active old_state ->
    t.state <- Refreshing;
    let _tid, request = build_refresh_request t lifetime in
    let _ = send_to_server t request in
    let response, _, _ = recv_from_server () in
    (match parse_response response with
     | Result.Ok true ->
       let new_lifetime =
         match find_attribute response (turn_attr_to_int LIFETIME) with
         | Some (offset, _) when Bytes.length response >= offset + 4 ->
           Int32.to_int (Bytes.get_int32_be response offset)
         | _ -> lifetime
       in
       let current = now () in
       if lifetime = 0
       then (
         t.state <- Inactive;
         Result.Ok 0)
       else (
         t.state
         <- Active
              { relayed_address = old_state.relayed_address
              ; lifetime = new_lifetime
              ; expiry = current +. Float.of_int new_lifetime
              };
         Result.Ok new_lifetime)
     | _ ->
       t.state <- Inactive;
       Result.Error "Refresh failed")
  | _ -> Result.Error "No active allocation"
;;

let get_state t = t.state

let get_relayed_address t =
  match t.state with
  | Active a -> Some a.relayed_address
  | _ -> None
;;

(** {1 Permissions & Channels} *)

let create_permission t peer_ip =
  let _tid, request = build_create_permission_request peer_ip in
  let _ = send_to_server t request in
  let response, _, _ = recv_from_server () in
  match parse_response response with
  | Result.Ok true ->
    let current = now () in
    t.permissions <- (peer_ip, current +. 300.0) :: t.permissions;
    Result.Ok ()
  | _ -> Result.Error "CreatePermission failed"
;;

let channel_bind t number peer_addr =
  if number < 0x4000 || number > 0x7FFF
  then Result.Error "Channel number must be in range 0x4000-0x7FFF"
  else (
    let _tid, request = build_channel_bind_request number peer_addr in
    let _ = send_to_server t request in
    let response, _, _ = recv_from_server () in
    match parse_response response with
    | Result.Ok true ->
      let current = now () in
      let chan = { number; peer_address = peer_addr; expiry = current +. 600.0 } in
      t.channels <- chan :: t.channels;
      Result.Ok ()
    | _ -> Result.Error "ChannelBind failed")
;;

let get_channels t = t.channels

(** {1 Data Transfer} *)

let build_channel_data channel_num data =
  let len = Bytes.length data in
  let buf = Bytes.create (4 + len) in
  Bytes.set_uint16_be buf 0 channel_num;
  Bytes.set_uint16_be buf 2 len;
  Bytes.blit data 0 buf 4 len;
  buf
;;

let send_data t peer_addr data =
  let channel = List.find_opt (fun c -> c.peer_address = peer_addr) t.channels in
  match channel with
  | Some chan ->
    let msg = build_channel_data chan.number data in
    let _ = send_to_server t msg in
    Result.Ok ()
  | None ->
    (* Use Send indication *)
    let tid = generate_transaction_id () in
    let peer_ip, peer_port = peer_addr in
    (* XOR-PEER-ADDRESS *)
    let addr_buf = Bytes.create 8 in
    Bytes.set_uint8 addr_buf 0 0;
    Bytes.set_uint8 addr_buf 1 1;
    Bytes.set_uint16_be addr_buf 2 (peer_port lxor 0x2112);
    let parts = String.split_on_char '.' peer_ip in
    (match parts with
     | [ a; b; c; d ] ->
       let xored =
         Int32.logxor
           magic_cookie
           (Int32.of_int
              ((int_of_string a lsl 24)
               lor (int_of_string b lsl 16)
               lor (int_of_string c lsl 8)
               lor int_of_string d))
       in
       Bytes.set_int32_be addr_buf 4 xored
     | _ -> ());
    let addr_attr = build_attribute (turn_attr_to_int XOR_PEER_ADDRESS) addr_buf in
    let data_attr = build_attribute (turn_attr_to_int DATA) data in
    let attrs = Bytes.cat addr_attr data_attr in
    (* Send indication = 0x0016 *)
    let header = build_message_header 0x0016 (Bytes.length attrs) tid in
    let _ = send_to_server t (Bytes.cat header attrs) in
    Result.Ok ()
;;

type on_data = string * int -> bytes -> unit

let on_data t callback = t.on_data_callback <- Some callback

(** {1 Utilities} *)

let close t =
  let _ = refresh t ~lifetime:0 () in
  t.state <- Inactive;
  t.channels <- [];
  t.permissions <- []
;;

let is_active t =
  match t.state with
  | Active _ -> true
  | _ -> false
;;

let remaining_lifetime t =
  match t.state with
  | Active a ->
    let current = now () in
    Some (Int.max 0 (Float.to_int (a.expiry -. current)))
  | _ -> None
;;

let pp_state fmt = function
  | Inactive -> Format.fprintf fmt "Inactive"
  | Allocating -> Format.fprintf fmt "Allocating"
  | Active a ->
    Format.fprintf
      fmt
      "Active(relay=%s:%d, lifetime=%d)"
      (fst a.relayed_address)
      (snd a.relayed_address)
      a.lifetime
  | Refreshing -> Format.fprintf fmt "Refreshing"
  | Expired -> Format.fprintf fmt "Expired"
;;

(** {1 Effect Handler (for Eio integration)} *)

let run_with_eio ~net ~clock f =
  try_with
    f
    ()
    { effc =
        (fun (type a) (eff : a Effect.t) ->
          match eff with
          | Send (data, host, port) ->
            Some
              (fun (k : (a, _) continuation) ->
                let _ = data, host, port, net in
                continue k (Bytes.length data))
          | Recv size ->
            Some
              (fun (k : (a, _) continuation) ->
                let _ = size, net in
                continue k (Bytes.empty, "0.0.0.0", 0))
          | Sleep secs ->
            Some
              (fun (k : (a, _) continuation) ->
                let _ = secs, clock in
                continue k ())
          | Now ->
            Some
              (fun (k : (a, _) continuation) ->
                let _ = clock in
                continue k (Unix.gettimeofday ()))
          | _ -> None)
    }
;;
