(** DTLS Record Layer — RFC 6347 record header and AES-GCM record encryption

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

open Dtls_types

let content_type_to_int = Dtls_codec.content_type_to_int
let int_to_content_type = Dtls_codec.int_to_content_type
let dtls_version_major = Dtls_codec.dtls_version_major
let dtls_version_minor = Dtls_codec.dtls_version_minor

(** DTLS record header:
    - content_type: 1 byte
    - version: 2 bytes
    - epoch: 2 bytes
    - sequence_number: 6 bytes
    - length: 2 bytes
    Total: 13 bytes *)
let record_header_size = 13

let build_record_header content_type epoch seq_num length =
  let buf = Bytes.create record_header_size in
  Bytes.set_uint8 buf 0 (content_type_to_int content_type);
  Bytes.set_uint8 buf 1 dtls_version_major;
  Bytes.set_uint8 buf 2 dtls_version_minor;
  Bytes.set_uint16_be buf 3 epoch;
  (* 6-byte sequence number (48-bit) *)
  Bytes.set_uint16_be buf 5 (Int64.to_int (Int64.shift_right seq_num 32));
  Bytes.set_int32_be buf 7 (Int64.to_int32 (Int64.logand seq_num 0xFFFFFFFFL));
  Bytes.set_uint16_be buf 11 length;
  buf
;;

(** {1 AES-GCM Record Encryption/Decryption (RFC 5288 + RFC 6347)} *)

(** Build AAD (Additional Authenticated Data) for AES-GCM
    AAD = epoch (2 bytes) || seq_num (6 bytes) || content_type (1 byte) ||
          version (2 bytes) || length (2 bytes)
    Note: length in AAD is the plaintext length, not ciphertext+tag length *)
let build_aad ~epoch ~seq_num ~content_type ~length =
  let buf = Bytes.create 13 in
  Bytes.set_uint16_be buf 0 epoch;
  (* 6-byte sequence number *)
  Bytes.set_uint16_be buf 2 (Int64.to_int (Int64.shift_right seq_num 32));
  Bytes.set_int32_be buf 4 (Int64.to_int32 (Int64.logand seq_num 0xFFFFFFFFL));
  Bytes.set_uint8 buf 8 (content_type_to_int content_type);
  Bytes.set_uint8 buf 9 dtls_version_major;
  Bytes.set_uint8 buf 10 dtls_version_minor;
  Bytes.set_uint16_be buf 11 length;
  buf
;;

(** Encrypt a DTLS record using AES-GCM (RFC 5288)
    Input: plaintext record payload
    Output: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes)

    The explicit nonce is the sequence number, prepended to the ciphertext.
    Total overhead: 8 (nonce) + 16 (tag) = 24 bytes *)
let encrypt_record ~(t : t) ~content_type ~epoch ~seq_num ~plaintext =
  match t.crypto.client_write_key, t.crypto.client_write_iv with
  | Some write_key, Some write_iv when t.config.is_client ->
    let key = Cstruct.of_bytes write_key in
    let implicit_iv = Cstruct.of_bytes write_iv in
    (* Explicit nonce = sequence number (8 bytes) *)
    let explicit_nonce = Cstruct.create 8 in
    Cstruct.BE.set_uint64 explicit_nonce 0 seq_num;
    (* Build AAD with plaintext length *)
    let aad = build_aad ~epoch ~seq_num ~content_type ~length:(Bytes.length plaintext) in
    let aad_cs = Cstruct.of_bytes aad in
    let plaintext_cs = Cstruct.of_bytes plaintext in
    (* Encrypt: returns ciphertext || tag *)
    let ciphertext_tag =
      Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad:aad_cs
        ~plaintext:plaintext_cs
    in
    (* Output: explicit_nonce || ciphertext || tag *)
    let result = Cstruct.concat [ explicit_nonce; ciphertext_tag ] in
    Result.Ok (Cstruct.to_bytes result)
  | _ when not t.config.is_client ->
    (* Server uses server_write_key/iv for encryption *)
    (match t.crypto.server_write_key, t.crypto.server_write_iv with
     | Some write_key, Some write_iv ->
       let key = Cstruct.of_bytes write_key in
       let implicit_iv = Cstruct.of_bytes write_iv in
       (* Explicit nonce = sequence number (8 bytes) *)
       let explicit_nonce = Cstruct.create 8 in
       Cstruct.BE.set_uint64 explicit_nonce 0 seq_num;
       (* Build AAD with plaintext length *)
       let aad =
         build_aad ~epoch ~seq_num ~content_type ~length:(Bytes.length plaintext)
       in
       let aad_cs = Cstruct.of_bytes aad in
       let plaintext_cs = Cstruct.of_bytes plaintext in
       (* Encrypt: returns ciphertext || tag *)
       let ciphertext_tag =
         Webrtc_crypto.aes_gcm_encrypt
           ~key
           ~implicit_iv
           ~explicit_nonce
           ~aad:aad_cs
           ~plaintext:plaintext_cs
       in
       (* Output: explicit_nonce || ciphertext || tag *)
       let result = Cstruct.concat [ explicit_nonce; ciphertext_tag ] in
       Result.Ok (Cstruct.to_bytes result)
     | _ -> Result.Error "Server encryption keys not available")
  | _ -> Result.Error "Client encryption keys not available"
;;

(** Decrypt a DTLS record using AES-GCM (RFC 5288)
    Input: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes)
    Output: plaintext record payload *)
let decrypt_record ~(t : t) ~content_type ~epoch ~seq_num ~ciphertext_with_nonce =
  let ciphertext_bytes = ciphertext_with_nonce in
  let ciphertext_len = Bytes.length ciphertext_bytes in
  (* Need at least explicit_nonce (8) + tag (16) = 24 bytes *)
  if ciphertext_len < 24
  then Result.Error "Ciphertext too short for AES-GCM"
  else (
    (* Extract explicit nonce (first 8 bytes) *)
    let explicit_nonce = Cstruct.of_bytes (Bytes.sub ciphertext_bytes 0 8) in
    let ciphertext_tag =
      Cstruct.of_bytes (Bytes.sub ciphertext_bytes 8 (ciphertext_len - 8))
    in
    (* Plaintext length = ciphertext - tag (16 bytes) *)
    let plaintext_len = ciphertext_len - 8 - 16 in
    if t.config.is_client
    then (
      (* Client reads using server's write key *)
      match t.crypto.server_write_key, t.crypto.server_write_iv with
      | Some read_key, Some read_iv ->
        let key = Cstruct.of_bytes read_key in
        let implicit_iv = Cstruct.of_bytes read_iv in
        (* Build AAD with plaintext length *)
        let aad = build_aad ~epoch ~seq_num ~content_type ~length:plaintext_len in
        let aad_cs = Cstruct.of_bytes aad in
        (match
           Webrtc_crypto.aes_gcm_decrypt
             ~key
             ~implicit_iv
             ~explicit_nonce
             ~aad:aad_cs
             ~ciphertext_and_tag:ciphertext_tag
         with
         | Ok plaintext -> Result.Ok (Cstruct.to_bytes plaintext)
         | Error e -> Result.Error e)
      | _ -> Result.Error "Decryption keys not available")
    else (
      (* Server reads using client's write key *)
      match t.crypto.client_write_key, t.crypto.client_write_iv with
      | Some read_key, Some read_iv ->
        let key = Cstruct.of_bytes read_key in
        let implicit_iv = Cstruct.of_bytes read_iv in
        let aad = build_aad ~epoch ~seq_num ~content_type ~length:plaintext_len in
        let aad_cs = Cstruct.of_bytes aad in
        (match
           Webrtc_crypto.aes_gcm_decrypt
             ~key
             ~implicit_iv
             ~explicit_nonce
             ~aad:aad_cs
             ~ciphertext_and_tag:ciphertext_tag
         with
         | Ok plaintext -> Result.Ok (Cstruct.to_bytes plaintext)
         | Error e -> Result.Error e)
      | _ -> Result.Error "Decryption keys not available"))
;;

let parse_record_header data =
  if Bytes.length data < record_header_size
  then Result.Error "Record too short"
  else (
    let ct = Bytes.get_uint8 data 0 in
    match int_to_content_type ct with
    | None -> Result.Error (Printf.sprintf "Unknown content type: %d" ct)
    | Some content_type ->
      let _version_major = Bytes.get_uint8 data 1 in
      let _version_minor = Bytes.get_uint8 data 2 in
      let epoch = Bytes.get_uint16_be data 3 in
      let seq_high = Int64.of_int (Bytes.get_uint16_be data 5) in
      let seq_low = Int64.of_int32 (Bytes.get_int32_be data 7) in
      let seq_num =
        Int64.logor (Int64.shift_left seq_high 32) (Int64.logand seq_low 0xFFFFFFFFL)
      in
      let length = Bytes.get_uint16_be data 11 in
      Result.Ok (content_type, epoch, seq_num, length))
;;
