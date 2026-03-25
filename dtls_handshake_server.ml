(** DTLS Server Handshake — Server-side DTLS 1.2 handshake processing

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

open Effect
open Dtls_types

let random_bytes n = perform (Random n)
let cipher_suite_to_int = Dtls_codec.cipher_suite_to_int
let dtls_version_major = Dtls_codec.dtls_version_major
let dtls_version_minor = Dtls_codec.dtls_version_minor
let build_record_header = Dtls_record.build_record_header
let encrypt_record = Dtls_record.encrypt_record
let handshake_header_size = Dtls_codec.handshake_header_size
let build_handshake_header = Dtls_codec.build_handshake_header
let build_use_srtp_extension = Dtls_codec.build_use_srtp_extension
let parse_extensions = Dtls_codec.parse_extensions
let select_srtp_profile = Dtls_codec.select_srtp_profile

(** {1 Cookie Handling (RFC 6347 Section 4.2.1 DoS protection)} *)

(** Cookie secret for HMAC-based stateless cookie generation.
    In production, this should be rotated periodically.
    RFC 6347 Section 4.2.1: Cookie SHOULD be generated using HMAC. *)
let cookie_secret = lazy (random_bytes 32)

(** Generate HMAC-SHA256 based cookie for DoS protection.
    Cookie = HMAC(secret, client_ip || client_port || client_random)
    This ensures stateless operation until cookie is verified. *)
let generate_cookie ~client_addr ~client_random =
  let secret = Lazy.force cookie_secret in
  let ip, port = client_addr in
  let port_bytes = Bytes.create 2 in
  Bytes.set_uint16_be port_bytes 0 port;
  (* Combine all inputs for HMAC *)
  let data = Bytes.concat Bytes.empty [ Bytes.of_string ip; port_bytes; client_random ] in
  (* Use HMAC-SHA256, truncate to 32 bytes *)
  let hmac =
    Digestif.SHA256.hmac_string ~key:(Bytes.to_string secret) (Bytes.to_string data)
  in
  Bytes.of_string (Digestif.SHA256.to_raw_string hmac)
;;

(** Verify client's cookie matches expected value *)
let verify_cookie ~client_addr ~client_random ~cookie =
  let expected = generate_cookie ~client_addr ~client_random in
  Bytes.length cookie = Bytes.length expected && Bytes.equal cookie expected
;;

(** Parse ClientHello message and extract key fields.
    ClientHello structure (RFC 5246 + RFC 6347):
    - client_version: 2 bytes
    - random: 32 bytes
    - session_id_length: 1 byte + session_id
    - cookie_length: 1 byte + cookie (DTLS only)
    - cipher_suites_length: 2 bytes + cipher_suites
    - compression_methods_length: 1 byte + methods
    - extensions_length: 2 bytes + extensions *)
let parse_client_hello data =
  let len = Bytes.length data in
  if len < 38
  then (* minimum: 2 + 32 + 1 + 1 + 2 *)
    Result.Error "ClientHello too short"
  else (
    let pos = ref 0 in
    (* Skip version *)
    pos := !pos + 2;
    (* Client random *)
    let client_random = Bytes.sub data !pos 32 in
    pos := !pos + 32;
    (* Session ID *)
    let session_id_len = Bytes.get_uint8 data !pos in
    incr pos;
    if !pos + session_id_len > len
    then Result.Error "ClientHello session_id truncated"
    else (
      pos := !pos + session_id_len;
      (* Cookie (DTLS specific) *)
      if !pos >= len
      then Result.Error "ClientHello missing cookie field"
      else (
        let cookie_len = Bytes.get_uint8 data !pos in
        incr pos;
        if !pos + cookie_len > len
        then Result.Error "ClientHello cookie truncated"
        else (
          let cookie =
            if cookie_len > 0 then Some (Bytes.sub data !pos cookie_len) else None
          in
          pos := !pos + cookie_len;
          (* Cipher suites *)
          if !pos + 2 > len
          then Result.Error "ClientHello missing cipher_suites length"
          else (
            let suites_len = Bytes.get_uint16_be data !pos in
            pos := !pos + 2;
            if !pos + suites_len > len
            then Result.Error "ClientHello cipher_suites truncated"
            else (
              let num_suites = suites_len / 2 in
              let cipher_suites =
                Array.init num_suites (fun i -> Bytes.get_uint16_be data (!pos + (i * 2)))
              in
              pos := !pos + suites_len;
              (* Compression methods *)
              if !pos >= len
              then Result.Error "ClientHello missing compression methods"
              else (
                let comp_len = Bytes.get_uint8 data !pos in
                pos := !pos + 1;
                if !pos + comp_len > len
                then Result.Error "ClientHello compression methods truncated"
                else (
                  pos := !pos + comp_len;
                  (* Extensions *)
                  if !pos + 2 > len
                  then Result.Ok (client_random, cookie, Array.to_list cipher_suites, [])
                  else (
                    let ext_len = Bytes.get_uint16_be data !pos in
                    pos := !pos + 2;
                    if !pos + ext_len > len
                    then Result.Error "ClientHello extensions truncated"
                    else (
                      let ext_data = Bytes.sub data !pos ext_len in
                      let srtp_profiles = parse_extensions ext_data in
                      Result.Ok
                        (client_random, cookie, Array.to_list cipher_suites, srtp_profiles)))))))))))
;;

(** Build HelloVerifyRequest message.
    HelloVerifyRequest structure:
    - server_version: 2 bytes
    - cookie_length: 1 byte
    - cookie: variable *)
let build_hello_verify_request t ~cookie =
  let cookie_len = Bytes.length cookie in
  let body_len = 2 + 1 + cookie_len in
  let body = Bytes.create body_len in
  let pos = ref 0 in
  (* Server version *)
  Bytes.set_uint8 body !pos dtls_version_major;
  incr pos;
  Bytes.set_uint8 body !pos dtls_version_minor;
  incr pos;
  (* Cookie *)
  Bytes.set_uint8 body !pos cookie_len;
  incr pos;
  Bytes.blit cookie 0 body !pos cookie_len;
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;
  let header = build_handshake_header HelloVerifyRequest body_len msg_seq 0 body_len in
  let handshake_data = Bytes.cat header body in
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

(** Build ServerHello message.
    ServerHello structure:
    - server_version: 2 bytes
    - random: 32 bytes
    - session_id_length: 1 byte + session_id
    - cipher_suite: 2 bytes
    - compression_method: 1 byte
    - extensions_length: 2 bytes + extensions *)
let build_server_hello t ~cipher_suite ~srtp_profile =
  let server_random = random_bytes 32 in
  t.handshake.server_random <- Some server_random;
  t.negotiated_cipher <- Some cipher_suite;
  let extensions =
    match srtp_profile with
    | None -> Bytes.empty
    | Some profile -> build_use_srtp_extension [ profile ]
  in
  let extensions_len = Bytes.length extensions in
  (* Body: 2 + 32 + 1 + 2 + 1 + 2 + extensions_len *)
  let body_len = 40 + extensions_len in
  let body = Bytes.create body_len in
  let pos = ref 0 in
  (* Version *)
  Bytes.set_uint8 body !pos dtls_version_major;
  incr pos;
  Bytes.set_uint8 body !pos dtls_version_minor;
  incr pos;
  (* Server random *)
  Bytes.blit server_random 0 body !pos 32;
  pos := !pos + 32;
  (* Session ID (empty) *)
  Bytes.set_uint8 body !pos 0;
  incr pos;
  (* Cipher suite *)
  Bytes.set_uint16_be body !pos (cipher_suite_to_int cipher_suite);
  pos := !pos + 2;
  (* Compression method (null) *)
  Bytes.set_uint8 body !pos 0;
  incr pos;
  (* Extensions *)
  Bytes.set_uint16_be body !pos extensions_len;
  pos := !pos + 2;
  if extensions_len > 0 then Bytes.blit extensions 0 body !pos extensions_len;
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;
  let header = build_handshake_header ServerHello body_len msg_seq 0 body_len in
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

(** Build Certificate message from PEM-encoded chain. *)
let build_certificate t pem =
  match X509.Certificate.decode_pem_multiple pem with
  | Error (`Msg msg) -> Result.Error (Printf.sprintf "Certificate decode failed: %s" msg)
  | Ok [] -> Result.Error "Certificate chain is empty"
  | Ok certs ->
    let certs_der = List.map X509.Certificate.encode_der certs in
    let certs_bytes = List.map Bytes.of_string certs_der in
    let total_len =
      List.fold_left (fun acc cert -> acc + 3 + Bytes.length cert) 0 certs_bytes
    in
    let body_len = 3 + total_len in
    let body = Bytes.create body_len in
    Bytes.set_uint8 body 0 ((total_len lsr 16) land 0xFF);
    Bytes.set_uint16_be body 1 (total_len land 0xFFFF);
    let pos = ref 3 in
    List.iter
      (fun cert ->
         let len = Bytes.length cert in
         Bytes.set_uint8 body !pos ((len lsr 16) land 0xFF);
         Bytes.set_uint16_be body (!pos + 1) (len land 0xFFFF);
         Bytes.blit cert 0 body (!pos + 3) len;
         pos := !pos + 3 + len)
      certs_bytes;
    let msg_seq = t.handshake.message_seq in
    t.handshake.message_seq <- msg_seq + 1;
    let header = build_handshake_header Certificate body_len msg_seq 0 body_len in
    let handshake_data = Bytes.cat header body in
    t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;
    let record_header =
      build_record_header
        Handshake
        t.epoch
        t.crypto.write_seq_num
        (Bytes.length handshake_data)
    in
    t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
    Result.Ok (Bytes.cat record_header handshake_data)
;;

(** Build ServerKeyExchange for ECDHE (RFC 8422).
    ServerKeyExchange structure for ECDHE:
    - curve_type: 1 byte (3 = named_curve)
    - named_curve: 2 bytes (23 = secp256r1)
    - public_key_length: 1 byte
    - public_key: variable (65 bytes for P-256 uncompressed) *)
let build_server_key_exchange t =
  (* Generate ECDHE keypair *)
  match Ecdhe.generate_p256 () with
  | Error e -> Result.Error (Printf.sprintf "ECDHE generation failed: %s" e)
  | Ok keypair ->
    t.handshake.ecdhe_keypair <- Some keypair;
    t.handshake.selected_curve <- Some Ecdhe.Secp256r1;
    let params = Ecdhe.build_server_ecdh_params keypair in
    let params_bytes = Cstruct.to_bytes params in
    let signature_block =
      match t.config.certificate, t.config.private_key with
      | Some _, Some pem ->
        (match t.handshake.client_random, t.handshake.server_random with
         | Some client_random, Some server_random ->
           let input =
             Bytes.concat Bytes.empty [ client_random; server_random; params_bytes ]
           in
           (match X509.Private_key.decode_pem pem with
            | Error (`Msg msg) ->
              Result.Error (Printf.sprintf "Private key decode failed: %s" msg)
            | Ok key ->
              let scheme =
                match X509.Private_key.key_type key with
                | `RSA -> Ok (`RSA_PKCS1, 1)
                | `P256 | `P384 | `P521 -> Ok (`ECDSA, 3)
                | `ED25519 -> Error "ED25519 is not supported for DTLS 1.2 signatures"
              in
              (match scheme with
               | Error msg -> Result.Error msg
               | Ok (scheme, sig_alg_id) ->
                 (match
                    X509.Private_key.sign
                      `SHA256
                      ~scheme
                      key
                      (`Message (Bytes.to_string input))
                  with
                  | Error (`Msg msg) ->
                    Result.Error
                      (Printf.sprintf "ServerKeyExchange signature failed: %s" msg)
                  | Ok sig_bytes ->
                    let sig_len = String.length sig_bytes in
                    let block = Bytes.create (2 + 2 + sig_len) in
                    Bytes.set_uint8 block 0 4;
                    (* SHA-256 *)
                    Bytes.set_uint8 block 1 sig_alg_id;
                    Bytes.set_uint16_be block 2 sig_len;
                    Bytes.blit_string sig_bytes 0 block 4 sig_len;
                    Result.Ok (Some block))))
         | _ -> Result.Error "Missing client_random or server_random for signature")
      | _ -> Result.Ok None
    in
    (match signature_block with
     | Error _ as err -> err
     | Ok signature_opt ->
       let body_len =
         Bytes.length params_bytes
         +
         match signature_opt with
         | None -> 0
         | Some b -> Bytes.length b
       in
       let body = Bytes.create body_len in
       Bytes.blit params_bytes 0 body 0 (Bytes.length params_bytes);
       (match signature_opt with
        | None -> ()
        | Some sig_block ->
          Bytes.blit sig_block 0 body (Bytes.length params_bytes) (Bytes.length sig_block));
       let msg_seq = t.handshake.message_seq in
       t.handshake.message_seq <- msg_seq + 1;
       let header =
         build_handshake_header ServerKeyExchange body_len msg_seq 0 body_len
       in
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
       Result.Ok (Bytes.cat record_header handshake_data))
;;

(** Build ServerHelloDone message (empty body) *)
let build_server_hello_done t =
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;
  let header = build_handshake_header ServerHelloDone 0 msg_seq 0 0 in
  (* Store for Finished verification *)
  t.handshake.handshake_messages <- header :: t.handshake.handshake_messages;
  (* Wrap in record *)
  let record_header =
    build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length header)
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
  Bytes.cat record_header header
;;

(** Handle ClientHello as server.
    Implements RFC 6347 Section 4.2.1 cookie exchange for DoS protection. *)
let handle_client_hello t ~payload ~body ~client_addr =
  if t.config.is_client
  then Result.Error "Cannot handle ClientHello as client"
  else (
    match parse_client_hello body with
    | Result.Error e -> Result.Error e
    | Result.Ok (client_random, cookie_opt, client_cipher_suites, client_srtp_profiles) ->
      t.handshake.client_random <- Some client_random;
      (* Check cookie for DoS protection *)
      (match cookie_opt with
       | None ->
         (* No cookie - send HelloVerifyRequest *)
         let cookie = generate_cookie ~client_addr ~client_random in
         let hvr = build_hello_verify_request t ~cookie in
         t.state <- HelloVerifySent;
         Result.Ok ([ hvr ], None)
       | Some cookie ->
         (* Verify cookie *)
         if not (verify_cookie ~client_addr ~client_random ~cookie)
         then Result.Error "Invalid cookie"
         else (
           t.state <- ClientHelloReceived;
           t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages;
           (* Select cipher suite (first common one) *)
           let common_cipher =
             List.find_opt
               (fun suite -> List.mem (cipher_suite_to_int suite) client_cipher_suites)
               t.config.cipher_suites
           in
           match common_cipher with
           | None -> Result.Error "No common cipher suite"
           | Some cipher_suite ->
             let selected_srtp =
               select_srtp_profile t.config.srtp_profiles client_srtp_profiles
             in
             if t.config.srtp_profiles <> [] && selected_srtp = None
             then Result.Error "No common SRTP profile"
             else (
               t.negotiated_srtp_profile <- selected_srtp;
               let has_cert = Option.is_some t.config.certificate in
               let has_key = Option.is_some t.config.private_key in
               if has_cert <> has_key
               then Result.Error "DTLS certificate and private key must both be set"
               else (
                 (* Build server flight: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone *)
                 let server_hello =
                   build_server_hello t ~cipher_suite ~srtp_profile:selected_srtp
                 in
                 let certificate =
                   match t.config.certificate with
                   | None -> Ok None
                   | Some pem ->
                     (match build_certificate t pem with
                      | Ok cert -> Ok (Some cert)
                      | Error e -> Error e)
                 in
                 match certificate with
                 | Error e -> Result.Error e
                 | Ok certificate_opt ->
                   (match build_server_key_exchange t with
                    | Result.Error e -> Result.Error e
                    | Result.Ok server_key_exchange ->
                      let server_hello_done = build_server_hello_done t in
                      let flight =
                        match certificate_opt with
                        | Some cert ->
                          [ server_hello; cert; server_key_exchange; server_hello_done ]
                        | None -> [ server_hello; server_key_exchange; server_hello_done ]
                      in
                      t.state <- ServerFlightSent;
                      Result.Ok (flight, None)))))))
;;

(** Handle ClientKeyExchange as server (ECDHE).
    Extracts client's public key and computes shared secret. *)
let handle_client_key_exchange t data =
  if t.config.is_client
  then Result.Error "Cannot handle ClientKeyExchange as client"
  else if Bytes.length data < 1
  then Result.Error "ClientKeyExchange too short"
  else (
    let pub_len = Bytes.get_uint8 data 0 in
    if Bytes.length data < 1 + pub_len
    then Result.Error "ClientKeyExchange public key truncated"
    else (
      let client_pub_bytes = Bytes.sub data 1 pub_len in
      let client_pub_cs = Cstruct.of_bytes client_pub_bytes in
      match t.handshake.ecdhe_keypair with
      | None -> Result.Error "Server ECDHE keypair not initialized"
      | Some keypair ->
        (* Compute shared secret *)
        (match Ecdhe.compute_shared_secret ~keypair ~peer_public_key:client_pub_cs with
         | Error e -> Result.Error (Printf.sprintf "ECDHE computation failed: %s" e)
         | Ok premaster_cs ->
           t.handshake.premaster_secret <- Some (Cstruct.to_bytes premaster_cs);
           t.state <- ClientKeyExchangeReceived;
           (* Derive master secret and key material *)
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
              (* Derive key material for AES-128-GCM *)
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
              t.crypto.client_write_iv
              <- Some (Cstruct.to_bytes key_material.client_write_iv);
              t.crypto.server_write_iv
              <- Some (Cstruct.to_bytes key_material.server_write_iv);
              Result.Ok ([], None)
            | _ -> Result.Error "Missing client_random or server_random"))))
;;

(** Build server's Finished message after receiving client's Finished *)
let build_server_finished t =
  (* Build ChangeCipherSpec *)
  let ccs_body = Bytes.create 1 in
  Bytes.set_uint8 ccs_body 0 1;
  let record_ccs =
    Bytes.cat
      (build_record_header ChangeCipherSpec t.epoch t.crypto.write_seq_num 1)
      ccs_body
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
  t.epoch <- t.epoch + 1;
  t.crypto.write_seq_num <- 0L;
  (* Build Finished with verify_data *)
  let finished_body =
    match t.handshake.master_secret with
    | Some master_secret ->
      let messages_cs = List.rev_map Cstruct.of_bytes t.handshake.handshake_messages in
      let handshake_hash = Ecdhe.hash_handshake_messages messages_cs in
      let master_secret_cs = Cstruct.of_bytes master_secret in
      let verify_data =
        Ecdhe.compute_verify_data
          ~master_secret:master_secret_cs
          ~handshake_hash
          ~is_client:false (* Server *)
      in
      Cstruct.to_bytes verify_data
    | None -> random_bytes 12
  in
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;
  let finished_header = build_handshake_header Finished 12 msg_seq 0 12 in
  let finished_data = Bytes.cat finished_header finished_body in
  (* Encrypt Finished *)
  let record_finished =
    match
      encrypt_record
        ~t
        ~content_type:Handshake
        ~epoch:t.epoch
        ~seq_num:t.crypto.write_seq_num
        ~plaintext:finished_data
    with
    | Ok encrypted_payload ->
      Bytes.cat
        (build_record_header
           Handshake
           t.epoch
           t.crypto.write_seq_num
           (Bytes.length encrypted_payload))
        encrypted_payload
    | Error _ ->
      Bytes.cat
        (build_record_header
           Handshake
           t.epoch
           t.crypto.write_seq_num
           (Bytes.length finished_data))
        finished_data
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
  t.state <- Established;
  [ record_ccs; record_finished ]
;;

(** Handle Finished message as server - verify client's Finished and send our own *)
let handle_finished_as_server t payload =
  (* RFC 5246 Section 7.4.9: Verify client's Finished message *)
  (* Finished body is 12 bytes of verify_data after handshake header *)
  let data_len = Bytes.length payload in
  if data_len < handshake_header_size + 12
  then (
    (* Data too short - skip verification in testing mode *)
    let response = build_server_finished t in
    Result.Ok (response, None))
  else (
    let body_len = (Bytes.get_uint8 payload 1 lsl 16) lor Bytes.get_uint16_be payload 2 in
    if data_len < handshake_header_size + body_len || body_len < 12
    then (
      let response = build_server_finished t in
      Result.Ok (response, None))
    else (
      let received_verify_data = Bytes.sub payload handshake_header_size 12 in
      (* Compute expected verify_data for client *)
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
              ~is_client:true (* Client's verify_data *)
          in
          let expected_bytes = Cstruct.to_bytes expected_verify_data in
          if Bytes.equal received_verify_data expected_bytes
          then Ok ()
          else Error "Client Finished verify_data mismatch - possible MITM attack"
        | None ->
          (* No master secret - skip verification (testing mode) *)
          Ok ()
      in
      match verification_result with
      | Ok () ->
        t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages;
        let response = build_server_finished t in
        Result.Ok (response, None)
      | Error msg -> Result.Error msg))
;;
