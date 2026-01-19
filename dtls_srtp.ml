(** DTLS-SRTP key derivation (RFC 5764). *)

type role =
  | Client
  | Server

let key_material_len = function
  | Srtp.AES_128_CM_HMAC_SHA1_80 -> 2 * (16 + 14)

let derive_keying_material ~dtls ~profile =
  let length = key_material_len profile in
  match Dtls.export_keying_material
          dtls
          ~label:"EXTRACTOR-dtls_srtp"
          ~context:None
          ~length
  with
  | Error _ as err -> err
  | Ok material ->
    if Bytes.length material <> length then
      Error "DTLS-SRTP: invalid keying material length"
    else
      let k_len = 16 in
      let s_len = 14 in
      let client_key = Bytes.sub material 0 k_len in
      let server_key = Bytes.sub material k_len k_len in
      let client_salt = Bytes.sub material (2 * k_len) s_len in
      let server_salt = Bytes.sub material (2 * k_len + s_len) s_len in
      Ok (
        { Srtp.master_key = client_key; master_salt = client_salt },
        { Srtp.master_key = server_key; master_salt = server_salt }
      )

let select_role role ~client ~server =
  match role with
  | Client -> client
  | Server -> server
