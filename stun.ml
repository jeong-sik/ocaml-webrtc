(** RFC 5389 STUN - Session Traversal Utilities for NAT

    STUN protocol logic: message construction, integrity, fingerprint,
    TLS/network helpers, and pretty-printing.

    Wire-format encoding/decoding is in {!Stun_codec}.
*)

(* Re-export codec types so external callers see Stun.message etc. unchanged *)
include Stun_codec

(* ============================================
   Message construction
   ============================================ *)

let create_binding_request ?transaction_id () =
  let tid =
    match transaction_id with
    | Some id -> id
    | None -> generate_transaction_id ()
  in
  { msg_class = Request; msg_method = Binding; transaction_id = tid; attributes = [] }
;;

let create_binding_response ~transaction_id ~mapped_address =
  (* XOR the address *)
  let xored = xor_address mapped_address transaction_id in
  { msg_class = Success_response
  ; msg_method = Binding
  ; transaction_id
  ; attributes = [ { attr_type = XOR_MAPPED_ADDRESS; value = Xor_mapped_address xored } ]
  }
;;

let create_error_response ~transaction_id ~error ?reason () =
  let code = error_code_to_int error in
  let reason_str =
    match reason with
    | Some r -> r
    | None ->
      (match error with
       | Try_alternate -> "Try Alternate"
       | Bad_request -> "Bad Request"
       | Unauthorized -> "Unauthorized"
       | Unknown_attribute -> "Unknown Attribute"
       | Stale_nonce -> "Stale Nonce"
       | Server_error -> "Server Error")
  in
  { msg_class = Error_response
  ; msg_method = Binding
  ; transaction_id
  ; attributes =
      [ { attr_type = ERROR_CODE; value = Error_code { code; reason = reason_str } } ]
  }
;;

(* ============================================
   RFC 5766 TURN Message Construction
   ============================================ *)

(** Create a TURN Allocate Request message. *)
let create_allocate_request
      ?transaction_id
      ?(transport = 17)
      ?lifetime
      ?(dont_fragment = false)
      ()
  =
  let tid =
    match transaction_id with
    | Some id -> id
    | None -> generate_transaction_id ()
  in
  let attrs =
    [ { attr_type = REQUESTED_TRANSPORT; value = Requested_transport transport } ]
  in
  let attrs =
    match lifetime with
    | Some l -> { attr_type = LIFETIME; value = Lifetime l } :: attrs
    | None -> attrs
  in
  let attrs =
    if dont_fragment
    then { attr_type = DONT_FRAGMENT; value = Dont_fragment } :: attrs
    else attrs
  in
  { msg_class = Request; msg_method = Allocate; transaction_id = tid; attributes = attrs }
;;

(** Create a TURN Allocate Success Response message. *)
let create_allocate_response ~transaction_id ~relayed_address ~mapped_address ~lifetime =
  let xored_relay = xor_address relayed_address transaction_id in
  let xored_mapped = xor_address mapped_address transaction_id in
  { msg_class = Success_response
  ; msg_method = Allocate
  ; transaction_id
  ; attributes =
      [ { attr_type = XOR_RELAYED_ADDRESS; value = Xor_relayed_address xored_relay }
      ; { attr_type = XOR_MAPPED_ADDRESS; value = Xor_mapped_address xored_mapped }
      ; { attr_type = LIFETIME; value = Lifetime lifetime }
      ]
  }
;;

(** Create a TURN Refresh Request message. *)
let create_refresh_request ?transaction_id ~lifetime () =
  let tid =
    match transaction_id with
    | Some id -> id
    | None -> generate_transaction_id ()
  in
  { msg_class = Request
  ; msg_method = Refresh
  ; transaction_id = tid
  ; attributes = [ { attr_type = LIFETIME; value = Lifetime lifetime } ]
  }
;;

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

let turn_error_to_int = function
  | Allocation_mismatch -> 437
  | Wrong_credentials -> 441
  | Unsupported_transport -> 442
  | Allocation_quota_reached -> 486
  | Insufficient_capacity -> 508
;;

let int_to_turn_error = function
  | 437 -> Some Allocation_mismatch
  | 441 -> Some Wrong_credentials
  | 442 -> Some Unsupported_transport
  | 486 -> Some Allocation_quota_reached
  | 508 -> Some Insufficient_capacity
  | _ -> None
;;

(** Extract allocate result from a TURN Allocate Success Response. *)
let parse_allocate_response msg =
  if msg.msg_class <> Success_response || msg.msg_method <> Allocate
  then Error "Not an Allocate Success Response"
  else (
    let rec find_attrs relayed mapped lt = function
      | [] -> relayed, mapped, lt
      | { value = Xor_relayed_address addr; _ } :: rest ->
        let unxored = unxor_address addr msg.transaction_id in
        find_attrs (Some unxored) mapped lt rest
      | { value = Xor_mapped_address addr; _ } :: rest ->
        let unxored = unxor_address addr msg.transaction_id in
        find_attrs relayed (Some unxored) lt rest
      | { value = Lifetime l; _ } :: rest -> find_attrs relayed mapped (Some l) rest
      | _ :: rest -> find_attrs relayed mapped lt rest
    in
    match find_attrs None None None msg.attributes with
    | Some relayed, Some mapped, Some lifetime ->
      Ok { relayed_address = relayed; mapped_address = mapped; lifetime }
    | Some relayed, None, Some lifetime ->
      (* XOR-MAPPED-ADDRESS is optional *)
      let dummy_mapped = { family = IPv4; port = 0; ip = "0.0.0.0" } in
      Ok { relayed_address = relayed; mapped_address = dummy_mapped; lifetime }
    | _ -> Error "Missing required attributes in Allocate Response")
;;

(* ============================================
   Message Integrity (HMAC-SHA1)
   ============================================ *)

(** HMAC-SHA1 using digestif library *)
let hmac_sha1 ~key data =
  let data_str = Bytes.to_string data in
  Digestif.SHA1.hmac_string ~key data_str
  |> Digestif.SHA1.to_raw_string
  |> Bytes.of_string
;;

(** Calculate MESSAGE-INTEGRITY attribute value.
    Per RFC 5389, HMAC covers the STUN message up to (but excluding)
    MESSAGE-INTEGRITY, with adjusted length to include the attribute. *)
let calculate_integrity msg ~key =
  (* Encode message, adjust length to include MESSAGE-INTEGRITY (24 bytes) *)
  let encoded = encode msg in
  let adjusted_len = get_uint16_be encoded 2 + 24 in
  set_uint16_be encoded 2 adjusted_len;
  (* HMAC-SHA1 over the adjusted message *)
  hmac_sha1 ~key encoded
;;

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
;;

(** Compute long-term credential key: MD5(username:realm:password) *)
let compute_long_term_key ~username ~realm ~password =
  let input = Printf.sprintf "%s:%s:%s" username realm password in
  Digestif.MD5.digest_string input |> Digestif.MD5.to_raw_string
;;

let add_message_integrity msg ~key =
  let integrity = calculate_integrity msg ~key in
  { msg with
    attributes =
      msg.attributes
      @ [ { attr_type = MESSAGE_INTEGRITY; value = Message_integrity integrity } ]
  }
;;

let add_auth_attributes msg ~username ~realm ~nonce =
  { msg with
    attributes =
      msg.attributes
      @ [ { attr_type = USERNAME; value = Username username }
        ; { attr_type = REALM; value = Realm realm }
        ; { attr_type = NONCE; value = Nonce nonce }
        ]
  }
;;

let find_realm_nonce msg =
  let rec loop realm nonce = function
    | [] -> realm, nonce
    | { value = Realm r; _ } :: rest -> loop (Some r) nonce rest
    | { value = Nonce n; _ } :: rest -> loop realm (Some n) rest
    | _ :: rest -> loop realm nonce rest
  in
  loop None None msg.attributes
;;

let find_error_code msg =
  let rec loop = function
    | [] -> None
    | { value = Error_code { code; _ }; _ } :: _ -> Some code
    | _ :: rest -> loop rest
  in
  loop msg.attributes
;;

let default_tls_ca_candidates =
  [ "/etc/ssl/certs/ca-certificates.crt"
  ; (* Debian/Ubuntu *)
    "/etc/ssl/cert.pem"
  ; (* macOS *)
    "/etc/pki/tls/certs/ca-bundle.crt" (* RHEL/CentOS/Fedora *)
  ]
;;

let find_tls_ca ?tls_ca () =
  match tls_ca with
  | Some path -> if Sys.file_exists path then Some path else None
  | None ->
    let env_candidates =
      List.filter_map (fun key -> Sys.getenv_opt key) [ "TURN_TLS_CA"; "SSL_CERT_FILE" ]
    in
    let candidates = env_candidates @ default_tls_ca_candidates in
    List.find_opt Sys.file_exists candidates
;;

let load_ca_certificates path =
  try
    let ic = open_in_bin path in
    let len = in_channel_length ic in
    let data = really_input_string ic len in
    close_in ic;
    match X509.Certificate.decode_pem_multiple data with
    | Ok certs when certs <> [] -> Ok certs
    | Ok _ -> Error "No CA certificates found"
    | Error (`Msg msg) -> Error msg
  with
  | Sys_error msg -> Error msg
;;

let build_tls_authenticator ?tls_ca () =
  match find_tls_ca ?tls_ca () with
  | None ->
    let hint =
      match tls_ca with
      | Some path -> Printf.sprintf "TLS CA not found: %s" path
      | None -> "TLS CA not found (set TURN_TLS_CA or SSL_CERT_FILE)"
    in
    Error hint
  | Some path ->
    load_ca_certificates path
    |> Result.map (fun certs ->
      X509.Authenticator.chain_of_trust ~time:(fun () -> Some (Ptime_clock.now ())) certs)
;;

let unix_error_to_string = function
  | Unix.EAGAIN | Unix.EWOULDBLOCK | Unix.ETIMEDOUT -> "Timeout"
  | err -> Unix.error_message err
;;

(** Convert TLS/network exceptions to error strings. *)
let error_of_tls_exn = function
  | Unix.Unix_error (err, _, _) -> unix_error_to_string err
  | Tls_unix.Closed_by_peer -> "TLS closed by peer"
  | End_of_file -> "TLS EOF"
  | Tls_unix.Tls_alert alert ->
    Printf.sprintf "TLS alert: %s" (Tls.Packet.alert_type_to_string alert)
  | Tls_unix.Tls_failure failure ->
    Printf.sprintf "TLS failure: %s" (Tls.Engine.string_of_failure failure)
  | Invalid_argument msg -> Printf.sprintf "Invalid argument: %s" msg
  | other -> raise other
;;

let set_socket_timeouts sock timeout_s =
  Unix.setsockopt_float sock Unix.SO_RCVTIMEO timeout_s;
  Unix.setsockopt_float sock Unix.SO_SNDTIMEO timeout_s
;;

let connect_tcp_with_timeout ~host ~port ~timeout_s =
  let addrs =
    Unix.getaddrinfo host (string_of_int port) [ Unix.AI_SOCKTYPE Unix.SOCK_STREAM ]
  in
  let rec try_addrs last_error = function
    | [] ->
      Error (Option.value ~default:"Could not resolve TURN server address" last_error)
    | (addr : Unix.addr_info) :: rest ->
      let sock = Unix.socket addr.ai_family addr.ai_socktype addr.ai_protocol in
      let connect_result =
        try
          Unix.set_nonblock sock;
          match Unix.connect sock addr.ai_addr with
          | () -> Ok ()
          | exception Unix.Unix_error (Unix.EINPROGRESS, _, _) ->
            let _, writable, _ = Unix.select [] [ sock ] [] timeout_s in
            if writable = []
            then Error "Timeout"
            else (
              match Unix.getsockopt_error sock with
              | None -> Ok ()
              | Some err -> Error (Unix.error_message err))
          | exception Unix.Unix_error (err, _, _) -> Error (Unix.error_message err)
        with
        | Unix.Unix_error (err, fn, _) ->
          Error (Printf.sprintf "%s: %s" fn (Unix.error_message err))
      in
      (match connect_result with
       | Ok () ->
         Unix.clear_nonblock sock;
         Ok sock
       | Error msg ->
         Unix.close sock;
         try_addrs (Some msg) rest)
  in
  try_addrs None addrs
;;

let tls_client_config ~authenticator host =
  let peer_name =
    match Domain_name.of_string host with
    | Ok dn ->
      (match Domain_name.host dn with
       | Ok host_dn -> Some host_dn
       | Error _ -> None)
    | Error _ -> None
  in
  match Tls.Config.client ~authenticator ?peer_name () with
  | Ok config -> Ok (config, peer_name)
  | Error (`Msg msg) -> Error msg
;;

let read_stun_frame_tls tls =
  let header = Bytes.create 20 in
  try
    Tls_unix.really_read tls header;
    let msg_len = get_uint16_be header 2 in
    let total_len = 20 + msg_len in
    let buf = Bytes.create total_len in
    Bytes.blit header 0 buf 0 20;
    if msg_len > 0 then Tls_unix.really_read tls buf ~off:20 ~len:msg_len;
    Ok buf
  with
  | ( Unix.Unix_error _
    | Tls_unix.Closed_by_peer
    | End_of_file
    | Tls_unix.Tls_alert _
    | Tls_unix.Tls_failure _
    | Invalid_argument _ ) as exn -> Error (error_of_tls_exn exn)
;;

let write_tls tls data =
  try
    Tls_unix.write tls (Bytes.to_string data);
    Ok ()
  with
  | ( Unix.Unix_error _
    | Tls_unix.Closed_by_peer
    | End_of_file
    | Tls_unix.Tls_alert _
    | Tls_unix.Tls_failure _
    | Invalid_argument _ ) as exn -> Error (error_of_tls_exn exn)
;;

(* ============================================
   Fingerprint (CRC-32)
   ============================================ *)

(* CRC-32 table *)
let crc32_table =
  Array.init 256 (fun i ->
    let rec loop j crc =
      if j = 8
      then crc
      else if Int32.(logand crc 1l) = 1l
      then loop (j + 1) Int32.(logxor (shift_right_logical crc 1) 0xEDB88320l)
      else loop (j + 1) Int32.(shift_right_logical crc 1)
    in
    loop 0 (Int32.of_int i))
;;

let crc32 data =
  let crc = ref 0xFFFFFFFFl in
  for i = 0 to Bytes.length data - 1 do
    let byte = Char.code (Bytes.get data i) in
    let index = Int32.(to_int (logand (logxor !crc (of_int byte)) 0xFFl)) in
    crc := Int32.(logxor (shift_right_logical !crc 8) crc32_table.(index))
  done;
  Int32.logxor !crc 0xFFFFFFFFl
;;

let calculate_fingerprint data =
  let crc = crc32 data in
  Int32.logxor crc 0x5354554el (* XOR with "STUN" *)
;;

let add_fingerprint msg =
  let attrs = List.filter (fun a -> a.attr_type <> FINGERPRINT) msg.attributes in
  let msg_without_fp = { msg with attributes = attrs } in
  let encoded = encode msg_without_fp in
  let adjusted_len = get_uint16_be encoded 2 + 8 in
  set_uint16_be encoded 2 adjusted_len;
  let fp = calculate_fingerprint encoded in
  { msg with
    attributes = attrs @ [ { attr_type = FINGERPRINT; value = Fingerprint fp } ]
  }
;;

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
    let attrs_without_fp =
      List.filter (fun a -> a.attr_type <> FINGERPRINT) msg.attributes
    in
    let msg_without_fp = { msg with attributes = attrs_without_fp } in
    let encoded = encode msg_without_fp in
    (* Adjust length to include FINGERPRINT (8 bytes) *)
    let adjusted_len = get_uint16_be encoded 2 + 8 in
    set_uint16_be encoded 2 adjusted_len;
    let calculated = calculate_fingerprint encoded in
    expected = calculated
;;

(* ============================================
   Pretty Printing
   ============================================ *)

let pp_message fmt msg =
  Format.fprintf
    fmt
    "STUN %s %s@."
    (string_of_method msg.msg_method)
    (string_of_class msg.msg_class);
  Format.fprintf fmt "  Transaction ID: ";
  for i = 0 to 11 do
    Format.fprintf fmt "%02X" (Char.code (Bytes.get msg.transaction_id i))
  done;
  Format.fprintf fmt "@.";
  List.iter
    (fun attr ->
       Format.fprintf fmt "  %s: " (string_of_attr_type attr.attr_type);
       (match attr.value with
        | Mapped_address addr
        | Xor_mapped_address addr
        | Xor_peer_address addr
        | Xor_relayed_address addr -> Format.fprintf fmt "%s:%d" addr.ip addr.port
        | Username s | Software s | Realm s | Nonce s -> Format.fprintf fmt "%S" s
        | Message_integrity _ -> Format.fprintf fmt "<20 bytes>"
        | Fingerprint fp -> Format.fprintf fmt "0x%08lX" fp
        | Error_code { code; reason } -> Format.fprintf fmt "%d %s" code reason
        | Channel_number n -> Format.fprintf fmt "0x%04X" n
        | Lifetime n -> Format.fprintf fmt "%d seconds" n
        | Data_attr b | Reservation_token b ->
          Format.fprintf fmt "<%d bytes>" (Bytes.length b)
        | Requested_transport t ->
          Format.fprintf
            fmt
            "%d (%s)"
            t
            (if t = 17 then "UDP" else if t = 6 then "TCP" else "?")
        | Even_port b -> Format.fprintf fmt "%b" b
        | Dont_fragment -> Format.fprintf fmt "true"
        | Unknown_attr b -> Format.fprintf fmt "<%d bytes>" (Bytes.length b));
       Format.fprintf fmt "@.")
    msg.attributes
;;
