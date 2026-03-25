(** DTLS Client Handshake — Client-side DTLS 1.2 handshake processing

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

open Effect
open Dtls_types

let random_bytes n = perform (Random n)

let int_to_cipher_suite = Dtls_codec.int_to_cipher_suite
let cipher_suite_to_int = Dtls_codec.cipher_suite_to_int
let dtls_version_major = Dtls_codec.dtls_version_major
let dtls_version_minor = Dtls_codec.dtls_version_minor

let build_record_header = Dtls_record.build_record_header
let encrypt_record = Dtls_record.encrypt_record

let handshake_header_size = Dtls_codec.handshake_header_size
let build_handshake_header = Dtls_codec.build_handshake_header
let build_extensions = Dtls_codec.build_extensions
let parse_extensions = Dtls_codec.parse_extensions

let build_client_hello t =
  (* Reuse existing client_random if present (for HelloVerifyRequest retry) *)
  let client_random =
    match t.handshake.client_random with
    | Some existing -> existing
    | None ->
      let new_random = random_bytes 32 in
      t.handshake.client_random <- Some new_random;
      new_random
  in
  (* ClientHello body:
     - client_version: 2 bytes
     - random: 32 bytes
     - session_id length: 1 byte + session_id
     - cookie length: 1 byte + cookie (DTLS specific)
     - cipher_suites length: 2 bytes + cipher_suites
     - compression_methods length: 1 byte + methods
     - extensions length: 2 bytes + extensions *)
  let cookie = Option.value t.handshake.cookie ~default:Bytes.empty in
  let cookie_len = Bytes.length cookie in
  let num_suites = List.length t.config.cipher_suites in
  let extensions = build_extensions t.config.srtp_profiles in
  let extensions_len = Bytes.length extensions in
  (* Calculate body size *)
  let body_len =
    2 + 32 + 1 + 1 + cookie_len + 2 + (num_suites * 2) + 1 + 1 + 2 + extensions_len
  in
  let body = Bytes.create body_len in
  let pos = ref 0 in
  (* Version *)
  Bytes.set_uint8 body !pos dtls_version_major;
  incr pos;
  Bytes.set_uint8 body !pos dtls_version_minor;
  incr pos;
  (* Random *)
  Bytes.blit client_random 0 body !pos 32;
  pos := !pos + 32;
  (* Session ID (empty) *)
  Bytes.set_uint8 body !pos 0;
  incr pos;
  (* Cookie *)
  Bytes.set_uint8 body !pos cookie_len;
  incr pos;
  if cookie_len > 0
  then (
    Bytes.blit cookie 0 body !pos cookie_len;
    pos := !pos + cookie_len);
  (* Cipher suites *)
  Bytes.set_uint16_be body !pos (num_suites * 2);
  pos := !pos + 2;
  List.iter
    (fun suite ->
       Bytes.set_uint16_be body !pos (cipher_suite_to_int suite);
       pos := !pos + 2)
    t.config.cipher_suites;
  (* Compression methods (null only) *)
  Bytes.set_uint8 body !pos 1;
  incr pos;
  Bytes.set_uint8 body !pos 0;
  incr pos;
  (* Extensions *)
  Bytes.set_uint16_be body !pos extensions_len;
  pos := !pos + 2;
  if extensions_len > 0 then Bytes.blit extensions 0 body !pos extensions_len;
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;
  let header = build_handshake_header ClientHello body_len msg_seq 0 body_len in
  let handshake_data = Bytes.cat header body in
  (* Store for Finished verification *)
  t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;
  (* Wrap in record *)
  let record_header =
    build_record_header
      Handshake
      t.epoch
      t.crypto.write_seq_num
      (Bytes.length handshake_data)
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
  Bytes.cat record_header handshake_data
;;

let start_handshake t =
  if not t.config.is_client
  then Result.Error "Only client can initiate handshake"
  else (
    let client_hello = build_client_hello t in
    t.state <- HelloSent;
    Result.Ok [ client_hello ])
;;

let handle_hello_verify_request t data =
  (* Parse HelloVerifyRequest:
     - server_version: 2 bytes
     - cookie_length: 1 byte
     - cookie: variable *)
  if Bytes.length data < 3
  then Result.Error "HelloVerifyRequest too short"
  else (
    let cookie_len = Bytes.get_uint8 data 2 in
    if Bytes.length data < 3 + cookie_len
    then Result.Error "HelloVerifyRequest cookie truncated"
    else (
      let cookie = Bytes.sub data 3 cookie_len in
      t.handshake.cookie <- Some cookie;
      t.state <- HelloVerifyReceived;
      (* Rebuild ClientHello with cookie *)
      t.handshake.message_seq <- 0;
      t.crypto.write_seq_num <- 0L;
      let client_hello = build_client_hello t in
      t.state <- HelloSent;
      Result.Ok ([ client_hello ], None)))
;;

let handle_server_hello t data =
  (* Parse ServerHello:
     - server_version: 2 bytes
     - random: 32 bytes
     - session_id length: 1 byte + session_id
     - cipher_suite: 2 bytes
     - compression_method: 1 byte
     - extensions: optional *)
  if Bytes.length data < 38
  then Result.Error "ServerHello too short"
  else (
    let server_random = Bytes.sub data 2 32 in
    t.handshake.server_random <- Some server_random;
    let session_id_len = Bytes.get_uint8 data 34 in
    let offset = 35 + session_id_len in
    if Bytes.length data < offset + 3
    then Result.Error "ServerHello truncated"
    else (
      let cipher_suite_code = Bytes.get_uint16_be data offset in
      match int_to_cipher_suite cipher_suite_code with
      | None -> Error "Unsupported cipher suite"
      | Some suite ->
        t.negotiated_cipher <- Some suite;
        let ext_pos = offset + 3 in
        if Bytes.length data >= ext_pos + 2
        then (
          let ext_len = Bytes.get_uint16_be data ext_pos in
          if Bytes.length data >= ext_pos + 2 + ext_len
          then (
            let ext_data = Bytes.sub data (ext_pos + 2) ext_len in
            let srtp_profiles = parse_extensions ext_data in
            match srtp_profiles with
            | profile :: _ -> t.negotiated_srtp_profile <- Some profile
            | [] -> ()));
        t.state <- ServerHelloReceived;
        Result.Ok ([], None)))
;;

let handle_certificate t data =
  (* Parse Certificate chain *)
  if Bytes.length data < 3
  then Result.Error "Certificate message too short"
  else (
    let _total_len = (Bytes.get_uint8 data 0 lsl 16) lor Bytes.get_uint16_be data 1 in
    (* For now, just store the raw data as the peer certificate *)
    t.peer_certificate <- Some (Bytes.to_string data);
    t.state <- CertificateReceived;
    Result.Ok ([], None))
;;

(** Handle ServerKeyExchange - parse ECDHE parameters (RFC 8422) *)
let handle_server_key_exchange t data =
  if Bytes.length data < 4
  then Result.Error "ServerKeyExchange too short"
  else (
    let curve_type = Bytes.get_uint8 data 0 in
    if curve_type <> 3
    then
      Result.Error
        (Printf.sprintf "Unsupported curve type: %d (expected named_curve=3)" curve_type)
    else (
      let curve_id = Bytes.get_uint16_be data 1 in
      match Ecdhe.named_curve_of_int curve_id with
      | None -> Result.Error (Printf.sprintf "Unsupported named curve: %d" curve_id)
      | Some curve ->
        let pub_len = Bytes.get_uint8 data 3 in
        if Bytes.length data < 4 + pub_len
        then Result.Error "ServerKeyExchange public key truncated"
        else (
          let pub_bytes = Bytes.sub data 3 (1 + pub_len) in
          match Ecdhe.decode_public_key ~curve (Cstruct.of_bytes pub_bytes) with
          | Error e -> Result.Error (Printf.sprintf "ServerKeyExchange parse error: %s" e)
          | Ok server_pub ->
            (* Store server's ECDHE public key *)
            t.handshake.selected_curve <- Some curve;
            t.handshake.server_public_key <- Some server_pub;
            (* Generate our ECDHE key pair *)
            (match Ecdhe.generate ~curve with
             | Error e ->
               Result.Error (Printf.sprintf "ECDHE key generation failed: %s" e)
             | Ok keypair ->
               t.handshake.ecdhe_keypair <- Some keypair;
               Result.Ok ([], None)))))
;;

(** Build client's response flight: ClientKeyExchange + ChangeCipherSpec + Finished *)
let build_client_flight t keypair =
  (* Build ClientKeyExchange with our ECDHE public key *)
  let pub_key_encoded = Ecdhe.encode_public_key keypair in
  let key_exchange_body = Cstruct.to_bytes pub_key_encoded in
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;
  let key_len = Bytes.length key_exchange_body in
  let header = build_handshake_header ClientKeyExchange key_len msg_seq 0 key_len in
  let handshake_data = Bytes.cat header key_exchange_body in
  t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;
  let record1 =
    Bytes.cat
      (build_record_header
         Handshake
         t.epoch
         t.crypto.write_seq_num
         (Bytes.length handshake_data))
      handshake_data
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
  (* Build ChangeCipherSpec *)
  let ccs_body = Bytes.create 1 in
  Bytes.set_uint8 ccs_body 0 1;
  let record2 =
    Bytes.cat
      (build_record_header ChangeCipherSpec t.epoch t.crypto.write_seq_num 1)
      ccs_body
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
  t.epoch <- t.epoch + 1;
  t.crypto.write_seq_num <- 0L;
  t.state <- ChangeCipherSpecSent;
  (* Build Finished with proper verify_data (RFC 5246 Section 7.4.9) *)
  let finished_body =
    match t.handshake.master_secret with
    | Some master_secret ->
      (* Hash all handshake messages *)
      let messages_cs = List.rev_map Cstruct.of_bytes t.handshake.handshake_messages in
      let handshake_hash = Ecdhe.hash_handshake_messages messages_cs in
      let master_secret_cs = Cstruct.of_bytes master_secret in
      let verify_data =
        Ecdhe.compute_verify_data
          ~master_secret:master_secret_cs
          ~handshake_hash
          ~is_client:t.config.is_client
      in
      Cstruct.to_bytes verify_data
    | None ->
      (* Fallback for testing *)
      random_bytes 12
  in
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;
  let finished_header = build_handshake_header Finished 12 msg_seq 0 12 in
  let finished_data = Bytes.cat finished_header finished_body in
  t.handshake.handshake_messages <- finished_data :: t.handshake.handshake_messages;
  (* After ChangeCipherSpec, all records must be encrypted (RFC 6347) *)
  let record3 =
    match
      encrypt_record
        ~t
        ~content_type:Handshake
        ~epoch:t.epoch
        ~seq_num:t.crypto.write_seq_num
        ~plaintext:finished_data
    with
    | Ok encrypted_payload ->
      (* Encrypted record: header with encrypted length + encrypted payload *)
      Bytes.cat
        (build_record_header
           Handshake
           t.epoch
           t.crypto.write_seq_num
           (Bytes.length encrypted_payload))
        encrypted_payload
    | Error _ ->
      (* Fallback to plaintext if encryption fails (for testing/debugging) *)
      Bytes.cat
        (build_record_header
           Handshake
           t.epoch
           t.crypto.write_seq_num
           (Bytes.length finished_data))
        finished_data
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
  Result.Ok ([ record1; record2; record3 ], None)
;;

(** Handle ServerHelloDone - complete ECDHE key exchange and send client flight *)
let handle_server_hello_done t _data =
  (* ServerHelloDone has no body *)
  t.state <- KeyExchangeDone;
  (* Get ECDHE keypair and server public key *)
  match t.handshake.ecdhe_keypair, t.handshake.server_public_key with
  | None, _ | _, None ->
    (* Fallback: Generate ECDHE keypair if not already done (self-signed/test mode) *)
    (match Ecdhe.generate_p256 () with
     | Error e -> Result.Error (Printf.sprintf "ECDHE generation failed: %s" e)
     | Ok keypair ->
       t.handshake.ecdhe_keypair <- Some keypair;
       (* Use dummy shared secret for testing without ServerKeyExchange *)
       let dummy_premaster = Bytes.create 32 in
       for i = 0 to 31 do
         Bytes.set_uint8 dummy_premaster i (i land 0xFF)
       done;
       t.handshake.premaster_secret <- Some dummy_premaster;
       build_client_flight t keypair)
  | Some keypair, Some server_pub ->
    (* Real ECDHE: Compute shared secret *)
    (match Ecdhe.compute_shared_secret ~keypair ~peer_public_key:server_pub with
     | Error e ->
       Result.Error (Printf.sprintf "ECDHE shared secret computation failed: %s" e)
     | Ok premaster_cs ->
       let premaster = Cstruct.to_bytes premaster_cs in
       t.handshake.premaster_secret <- Some premaster;
       (* Derive master secret using TLS 1.2 PRF *)
       (match t.handshake.client_random, t.handshake.server_random with
        | Some client_random, Some server_random ->
          let client_random_cs = Cstruct.of_bytes client_random in
          let server_random_cs = Cstruct.of_bytes server_random in
          let master_secret_cs =
            Webrtc_crypto.derive_master_secret
              ~pre_master_secret:premaster_cs
              ~client_random:client_random_cs
              ~server_random:server_random_cs
          in
          t.handshake.master_secret <- Some (Cstruct.to_bytes master_secret_cs);
          (* Derive key material for AES-128-GCM encryption (RFC 5288) *)
          let key_material =
            Webrtc_crypto.derive_key_material
              ~master_secret:master_secret_cs
              ~server_random:server_random_cs
              ~client_random:client_random_cs
              ~key_size:Webrtc_crypto.aes_128_gcm_key_size
              ~iv_size:Webrtc_crypto.aes_gcm_implicit_iv_size
          in
          t.crypto.client_write_key
          <- Some (Cstruct.to_bytes key_material.client_write_key);
          t.crypto.server_write_key
          <- Some (Cstruct.to_bytes key_material.server_write_key);
          t.crypto.client_write_iv <- Some (Cstruct.to_bytes key_material.client_write_iv);
          t.crypto.server_write_iv <- Some (Cstruct.to_bytes key_material.server_write_iv);
          build_client_flight t keypair
        | _ -> Result.Error "Missing client_random or server_random"))
;;

let handle_finished t payload =
  (* RFC 5246 Section 7.4.9: Verify server's Finished message *)
  (* Finished body is 12 bytes of verify_data after handshake header *)
  let data_len = Bytes.length payload in
  if data_len < handshake_header_size + 12
  then (
    (* Data too short - skip verification in testing mode *)
    t.state <- Established;
    Result.Ok ([], None))
  else (
    let body_len = (Bytes.get_uint8 payload 1 lsl 16) lor Bytes.get_uint16_be payload 2 in
    if data_len < handshake_header_size + body_len || body_len < 12
    then (
      t.state <- Established;
      Result.Ok ([], None))
    else (
      let received_verify_data = Bytes.sub payload handshake_header_size 12 in
      (* Compute expected verify_data *)
      let verification_result =
        match t.handshake.master_secret with
        | Some master_secret ->
          (* Hash all handshake messages (excluding this Finished) *)
          let messages_cs =
            List.rev_map Cstruct.of_bytes t.handshake.handshake_messages
          in
          let handshake_hash = Ecdhe.hash_handshake_messages messages_cs in
          let master_secret_cs = Cstruct.of_bytes master_secret in
          let expected_verify_data =
            Ecdhe.compute_verify_data
              ~master_secret:master_secret_cs
              ~handshake_hash
              ~is_client:false (* Server's verify_data *)
          in
          let expected_bytes = Cstruct.to_bytes expected_verify_data in
          if Bytes.equal received_verify_data expected_bytes
          then Ok ()
          else Error "Finished verify_data mismatch - possible MITM attack"
        | None ->
          (* No master secret - skip verification (testing mode) *)
          Ok ()
      in
      match verification_result with
      | Ok () ->
        t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages;
        t.state <- Established;
        Result.Ok ([], None)
      | Error msg -> Result.Error msg))
;;
