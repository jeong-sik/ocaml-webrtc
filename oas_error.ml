(** Structured error classification for OAS

    @see Oas_error.mli for documentation. *)

type error_class =
  | Transient
  | Protocol
  | Fatal
  | Config
[@@deriving show, eq]

type t =
  { cls : error_class
  ; message : string
  ; module_hint : string
  }
[@@deriving show, eq]

(** Known fatal error prefixes/substrings. *)
let fatal_patterns =
  [ "Association aborted"
  ; "Shutdown timeout"
  ; "Handshake timeout"
  ; "Max retransmits exceeded"
  ; "AES-GCM authentication failed"
  ]
;;

(** Known transient error prefixes/substrings. *)
let transient_patterns = [ "Congestion window full"; "Unexpected HEARTBEAT-ACK" ]

(** Known config/state error prefixes/substrings. *)
let config_patterns =
  [ "requires Established state"
  ; "unexpected state"
  ; "in unexpected state"
  ; "no handshake in progress"
  ; "ACK for unknown channel"
  ]
;;

let string_contains ~sub s =
  let sub_len = String.length sub in
  let s_len = String.length s in
  if sub_len > s_len
  then false
  else (
    let rec check i =
      if i > s_len - sub_len
      then false
      else if String.sub s i sub_len = sub
      then true
      else check (i + 1)
    in
    check 0)
;;

let matches_any patterns msg =
  List.exists (fun pat -> string_contains ~sub:pat msg) patterns
;;

let classify msg =
  if matches_any fatal_patterns msg
  then Fatal
  else if matches_any transient_patterns msg
  then Transient
  else if matches_any config_patterns msg
  then Config
  else Protocol
;;

(** Extract module hint from error messages like "DATA decode: ..." *)
let infer_module msg =
  (* Common prefixes: "DATA decode:", "SACK decode:", "INIT processing:" *)
  match String.index_opt msg ':' with
  | Some i when i < 30 ->
    let prefix = String.sub msg 0 i in
    let prefix = String.trim prefix in
    (* Check it looks like a module hint (uppercase start, no spaces in first word) *)
    if String.length prefix > 0
    then (
      match String.index_opt prefix ' ' with
      | Some sp ->
        let first_word = String.sub prefix 0 sp in
        if
          String.length first_word > 0
          && Char.uppercase_ascii first_word.[0] = first_word.[0]
        then first_word
        else "unknown"
      | None -> if Char.uppercase_ascii prefix.[0] = prefix.[0] then prefix else "unknown")
    else "unknown"
  | _ ->
    (* Try to match known module patterns *)
    if string_contains ~sub:"CRC32c" msg
    then "sctp_core"
    else if string_contains ~sub:"Congestion" msg
    then "sctp_core"
    else if string_contains ~sub:"HEARTBEAT" msg
    then "sctp_heartbeat"
    else if string_contains ~sub:"Shutdown" msg
    then "sctp_core"
    else if string_contains ~sub:"Handshake" msg
    then "dtls"
    else if string_contains ~sub:"DATA_CHANNEL" msg
    then "dcep"
    else if string_contains ~sub:"RTP" msg
    then "media_transport"
    else if string_contains ~sub:"Packet too short" msg
    then "sctp_core"
    else if string_contains ~sub:"Association" msg
    then "sctp_core"
    else "unknown"
;;

let of_string msg = { cls = classify msg; message = msg; module_hint = infer_module msg }

let is_retryable t =
  match t.cls with
  | Transient -> true
  | Protocol | Fatal | Config -> false
;;

let is_fatal t =
  match t.cls with
  | Fatal -> true
  | Transient | Protocol | Config -> false
;;

let to_string t =
  let cls_str =
    match t.cls with
    | Transient -> "TRANSIENT"
    | Protocol -> "PROTOCOL"
    | Fatal -> "FATAL"
    | Config -> "CONFIG"
  in
  Printf.sprintf "[%s] %s: %s" cls_str t.module_hint t.message
;;
