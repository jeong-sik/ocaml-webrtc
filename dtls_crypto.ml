(** DTLS Application-Level Crypto — AES-GCM encrypt/decrypt and key export

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

open Dtls_types

let build_record_header = Dtls_record.build_record_header
let record_header_size = Dtls_record.record_header_size
let build_aad = Dtls_record.build_aad
let parse_record_header = Dtls_record.parse_record_header

(** {1 AES-GCM Constants} *)

let gcm_tag_size = 16
let gcm_explicit_nonce_size = 8

(** Build 12-byte GCM nonce from 4-byte implicit IV + 8-byte explicit nonce *)
let build_gcm_nonce ~implicit_iv ~seq_num =
  let nonce = Bytes.create 12 in
  Bytes.blit implicit_iv 0 nonce 0 4;
  (* Encode sequence number as big-endian 8 bytes *)
  for i = 0 to 7 do
    let shift = (7 - i) * 8 in
    Bytes.set_uint8
      nonce
      (4 + i)
      (Int64.to_int (Int64.shift_right_logical seq_num shift) land 0xff)
  done;
  nonce
;;

(** {1 Data Transfer} *)

let encrypt t data =
  if t.state <> Established
  then Result.Error "Connection not established"
  else (
    (* Get write keys based on role *)
    let write_key_opt, write_iv_opt =
      if t.config.is_client
      then t.crypto.client_write_key, t.crypto.client_write_iv
      else t.crypto.server_write_key, t.crypto.server_write_iv
    in
    match write_key_opt, write_iv_opt with
    | None, _ | _, None ->
      (* Epoch 0: no encryption, return plaintext with header *)
      let record =
        Bytes.cat
          (build_record_header
             ApplicationData
             t.epoch
             t.crypto.write_seq_num
             (Bytes.length data))
          data
      in
      t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
      Result.Ok record
    | Some write_key, Some write_iv ->
      (* Real AES-GCM encryption *)
      let seq_num = t.crypto.write_seq_num in
      let nonce = build_gcm_nonce ~implicit_iv:write_iv ~seq_num in
      let aad =
        build_aad
          ~epoch:t.epoch
          ~seq_num
          ~content_type:ApplicationData
          ~length:(Bytes.length data)
      in
      (* Explicit nonce (8 bytes) to prepend to ciphertext *)
      let explicit_nonce = Bytes.create gcm_explicit_nonce_size in
      for i = 0 to 7 do
        let shift = (7 - i) * 8 in
        Bytes.set_uint8
          explicit_nonce
          i
          (Int64.to_int (Int64.shift_right_logical seq_num shift) land 0xff)
      done;
      (* Encrypt with AES-GCM *)
      let key = Mirage_crypto.AES.GCM.of_secret (Bytes.to_string write_key) in
      let ciphertext_with_tag =
        Mirage_crypto.AES.GCM.authenticate_encrypt
          ~key
          ~nonce:(Bytes.to_string nonce)
          ~adata:(Bytes.to_string aad)
          (Bytes.to_string data)
      in
      (* Record length = explicit_nonce + ciphertext + tag *)
      let encrypted_len = gcm_explicit_nonce_size + String.length ciphertext_with_tag in
      let header = build_record_header ApplicationData t.epoch seq_num encrypted_len in
      let record =
        Bytes.concat
          Bytes.empty
          [ header; explicit_nonce; Bytes.of_string ciphertext_with_tag ]
      in
      t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
      Result.Ok record)
;;

let decrypt t data =
  match parse_record_header data with
  | Result.Error e -> Result.Error e
  | Result.Ok (ApplicationData, epoch, seq_num, length) ->
    if t.state <> Established
    then Result.Error "Connection not established"
    else (
      (* Get read keys based on role (opposite of write) *)
      let read_key_opt, read_iv_opt =
        if t.config.is_client
        then t.crypto.server_write_key, t.crypto.server_write_iv
        else t.crypto.client_write_key, t.crypto.client_write_iv
      in
      match read_key_opt, read_iv_opt with
      | None, _ | _, None ->
        (* Epoch 0: no encryption, return plaintext *)
        let payload = Bytes.sub data record_header_size length in
        t.crypto.read_seq_num <- Int64.add t.crypto.read_seq_num 1L;
        Result.Ok payload
      | Some read_key, Some read_iv ->
        (* Real AES-GCM decryption *)
        if length < gcm_explicit_nonce_size + gcm_tag_size
        then Result.Error "Ciphertext too short"
        else (
          (* Extract explicit nonce *)
          let explicit_nonce =
            Bytes.sub data record_header_size gcm_explicit_nonce_size
          in
          (* Build full nonce *)
          let nonce = Bytes.create 12 in
          Bytes.blit read_iv 0 nonce 0 4;
          Bytes.blit explicit_nonce 0 nonce 4 8;
          (* Extract ciphertext with tag *)
          let ciphertext_start = record_header_size + gcm_explicit_nonce_size in
          let ciphertext_len = length - gcm_explicit_nonce_size in
          let ciphertext_with_tag = Bytes.sub data ciphertext_start ciphertext_len in
          (* Build AAD - length is plaintext length (ciphertext - tag) *)
          let plaintext_len = ciphertext_len - gcm_tag_size in
          let aad =
            build_aad ~epoch ~seq_num ~content_type:ApplicationData ~length:plaintext_len
          in
          (* Decrypt with AES-GCM *)
          let key = Mirage_crypto.AES.GCM.of_secret (Bytes.to_string read_key) in
          match
            Mirage_crypto.AES.GCM.authenticate_decrypt
              ~key
              ~nonce:(Bytes.to_string nonce)
              ~adata:(Bytes.to_string aad)
              (Bytes.to_string ciphertext_with_tag)
          with
          | Some plaintext ->
            t.crypto.read_seq_num <- Int64.add t.crypto.read_seq_num 1L;
            Result.Ok (Bytes.of_string plaintext)
          | None -> Result.Error "Decryption failed - authentication error"))
  | Result.Ok _ -> Result.Error "Not application data"
;;

(** {1 Key Export} *)

let export_keying_material t ~label ~context ~length =
  if t.state <> Established
  then Result.Error "Connection not established"
  else (
    match
      t.handshake.master_secret, t.handshake.client_random, t.handshake.server_random
    with
    | None, _, _ -> Error "No master secret"
    | _, None, _ | _, _, None -> Error "Missing client/server random"
    | Some master_secret, Some client_random, Some server_random ->
      let seed_result =
        match context with
        | None -> Ok (Bytes.cat client_random server_random)
        | Some ctx ->
          if Bytes.length ctx > 0xFFFF
          then Error "Context too large"
          else (
            let len_bytes = Bytes.create 2 in
            Bytes.set_uint16_be len_bytes 0 (Bytes.length ctx);
            Ok (Bytes.concat Bytes.empty [ client_random; server_random; len_bytes; ctx ]))
      in
      (match seed_result with
       | Error e -> Error e
       | Ok seed ->
         let master_cs = Cstruct.of_bytes master_secret in
         let seed_cs = Cstruct.of_bytes seed in
         let out =
           Webrtc_crypto.prf_sha256 ~secret:master_cs ~label ~seed:seed_cs ~length
         in
         Result.Ok (Cstruct.to_bytes out)))
;;
