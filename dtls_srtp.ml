(** DTLS-SRTP key extraction (RFC 5764). *)

type key_material =
  { client_key : bytes
  ; server_key : bytes
  ; client_salt : bytes
  ; server_salt : bytes
  }

type role =
  | Client
  | Server

let split_keying_material ~profile keying_material =
  let params = Srtp.params_of_profile profile in
  let key_len = params.cipher_key_len in
  let salt_len = params.cipher_salt_len in
  let expected_len = 2 * (key_len + salt_len) in
  if Bytes.length keying_material <> expected_len
  then Error "Keying material length mismatch"
  else (
    let off = ref 0 in
    let take n =
      let out = Bytes.sub keying_material !off n in
      off := !off + n;
      out
    in
    let client_key = take key_len in
    let server_key = take key_len in
    let client_salt = take salt_len in
    let server_salt = take salt_len in
    Ok { client_key; server_key; client_salt; server_salt })
;;

let export_keying_material ~dtls ~profile =
  let params = Srtp.params_of_profile profile in
  let length = 2 * (params.cipher_key_len + params.cipher_salt_len) in
  match
    Dtls.export_keying_material dtls ~label:"EXTRACTOR-dtls_srtp" ~context:None ~length
  with
  | Error e -> Error e
  | Ok material -> split_keying_material ~profile material
;;

let masters_of_key_material km =
  let client = { Srtp.key = km.client_key; salt = km.client_salt } in
  let server = { Srtp.key = km.server_key; salt = km.server_salt } in
  client, server
;;

let select_role role ~client ~server =
  match role with
  | Client -> client
  | Server -> server
;;

let session_keys_of_dtls ~dtls ~role ~profile ?(key_derivation_rate = 0L) ?(index = 0L) ()
  =
  let material = export_keying_material ~dtls ~profile in
  let masters = Result.map masters_of_key_material material in
  Result.bind masters (fun (client_master, server_master) ->
    let local_master = select_role role ~client:client_master ~server:server_master in
    let remote_master = select_role role ~client:server_master ~server:client_master in
    match
      ( Srtp.derive_session_keys ~profile ~master:local_master ~key_derivation_rate ~index
      , Srtp.derive_session_keys
          ~profile
          ~master:remote_master
          ~key_derivation_rate
          ~index )
    with
    | Ok local_keys, Ok remote_keys -> Ok (local_keys, remote_keys)
    | Error e, _ -> Error e
    | _, Error e -> Error e)
;;
