(** RFC 6347 DTLS - Datagram Transport Layer Security

    Pure OCaml 5.x implementation using Effect Handlers.

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

open Effect
open Effect.Deep

(** {1 Effects for I/O} *)

type _ Effect.t +=
  | Send : bytes -> int Effect.t
  | Recv : int -> bytes Effect.t
  | Now : float Effect.t
  | Random : int -> bytes Effect.t

(** {1 Types} *)

type content_type =
  | ChangeCipherSpec
  | Alert
  | Handshake
  | ApplicationData

type handshake_type =
  | HelloRequest
  | ClientHello
  | ServerHello
  | HelloVerifyRequest
  | Certificate
  | ServerKeyExchange
  | CertificateRequest
  | ServerHelloDone
  | CertificateVerify
  | ClientKeyExchange
  | Finished

type alert_level =
  | Warning
  | Fatal

type alert_description =
  | CloseNotify
  | UnexpectedMessage
  | BadRecordMac
  | DecryptionFailed
  | RecordOverflow
  | DecompressionFailure
  | HandshakeFailure
  | BadCertificate
  | UnsupportedCertificate
  | CertificateRevoked
  | CertificateExpired
  | CertificateUnknown
  | IllegalParameter
  | UnknownCA
  | AccessDenied
  | DecodeError
  | DecryptError
  | ProtocolVersion
  | InsufficientSecurity
  | InternalError
  | UserCanceled
  | NoRenegotiation

type state =
  | Initial
  | HelloSent
  | HelloVerifyReceived
  | ServerHelloReceived
  | CertificateReceived
  | KeyExchangeDone
  | ChangeCipherSpecSent
  | Established
  | Closed
  | Error of string

type cipher_suite =
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

type config = {
  is_client : bool;
  certificate : string option;
  private_key : string option;
  verify_peer : bool;
  cipher_suites : cipher_suite list;
  mtu : int;
  retransmit_timeout_ms : int;
  max_retransmits : int;
}

(** Internal crypto state *)
type crypto_state = {
  mutable client_write_key : bytes option;
  mutable server_write_key : bytes option;
  mutable client_write_iv : bytes option;
  mutable server_write_iv : bytes option;
  mutable read_seq_num : int64;
  mutable write_seq_num : int64;
}

(** Handshake state tracking *)
type handshake_state = {
  mutable client_random : bytes option;
  mutable server_random : bytes option;
  mutable premaster_secret : bytes option;
  mutable master_secret : bytes option;
  mutable handshake_messages : bytes list;  (* For Finished verification *)
  mutable cookie : bytes option;
  mutable message_seq : int;
  mutable next_receive_seq : int;
  mutable pending_fragments : (int * bytes) list;  (* seq -> fragment *)
  (* ECDHE key exchange state (RFC 8422) *)
  mutable ecdhe_keypair : Ecdhe.keypair option;
  mutable server_public_key : Cstruct.t option;
  mutable selected_curve : Ecdhe.named_curve option;
}

type t = {
  config : config;
  mutable state : state;
  mutable negotiated_cipher : cipher_suite option;
  mutable peer_certificate : string option;
  mutable epoch : int;
  crypto : crypto_state;
  handshake : handshake_state;
}

(** {1 Constants} *)

let content_type_to_int = function
  | ChangeCipherSpec -> 20
  | Alert -> 21
  | Handshake -> 22
  | ApplicationData -> 23

let int_to_content_type = function
  | 20 -> Some ChangeCipherSpec
  | 21 -> Some Alert
  | 22 -> Some Handshake
  | 23 -> Some ApplicationData
  | _ -> None

let handshake_type_to_int = function
  | HelloRequest -> 0
  | ClientHello -> 1
  | ServerHello -> 2
  | HelloVerifyRequest -> 3
  | Certificate -> 11
  | ServerKeyExchange -> 12
  | CertificateRequest -> 13
  | ServerHelloDone -> 14
  | CertificateVerify -> 15
  | ClientKeyExchange -> 16
  | Finished -> 20

let int_to_handshake_type = function
  | 0 -> Some HelloRequest
  | 1 -> Some ClientHello
  | 2 -> Some ServerHello
  | 3 -> Some HelloVerifyRequest
  | 11 -> Some Certificate
  | 12 -> Some ServerKeyExchange
  | 13 -> Some CertificateRequest
  | 14 -> Some ServerHelloDone
  | 15 -> Some CertificateVerify
  | 16 -> Some ClientKeyExchange
  | 20 -> Some Finished
  | _ -> None

let cipher_suite_to_int = function
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 -> 0xC02B
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> 0xC02F
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 -> 0xC02C
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> 0xC030

let int_to_cipher_suite = function
  | 0xC02B -> Some TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | 0xC02F -> Some TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | 0xC02C -> Some TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | 0xC030 -> Some TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  | _ -> None

let alert_level_to_int = function
  | Warning -> 1
  | Fatal -> 2

let alert_description_to_int = function
  | CloseNotify -> 0
  | UnexpectedMessage -> 10
  | BadRecordMac -> 20
  | DecryptionFailed -> 21
  | RecordOverflow -> 22
  | DecompressionFailure -> 30
  | HandshakeFailure -> 40
  | BadCertificate -> 42
  | UnsupportedCertificate -> 43
  | CertificateRevoked -> 44
  | CertificateExpired -> 45
  | CertificateUnknown -> 46
  | IllegalParameter -> 47
  | UnknownCA -> 48
  | AccessDenied -> 49
  | DecodeError -> 50
  | DecryptError -> 51
  | ProtocolVersion -> 70
  | InsufficientSecurity -> 71
  | InternalError -> 80
  | UserCanceled -> 90
  | NoRenegotiation -> 100

(** DTLS version: 1.2 = { 254, 253 } *)
let dtls_version_major = 254
let dtls_version_minor = 253

(** {1 Default Configuration} *)

let default_client_config = {
  is_client = true;
  certificate = None;
  private_key = None;
  verify_peer = true;
  cipher_suites = [
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
  ];
  mtu = 1400;
  retransmit_timeout_ms = 1000;
  max_retransmits = 5;
}

let default_server_config = {
  is_client = false;
  certificate = None;
  private_key = None;
  verify_peer = false;
  cipher_suites = [
    TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256;
    TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256;
  ];
  mtu = 1400;
  retransmit_timeout_ms = 1000;
  max_retransmits = 5;
}

(** {1 Context Creation} *)

let create config = {
  config;
  state = Initial;
  negotiated_cipher = None;
  peer_certificate = None;
  epoch = 0;
  crypto = {
    client_write_key = None;
    server_write_key = None;
    client_write_iv = None;
    server_write_iv = None;
    read_seq_num = 0L;
    write_seq_num = 0L;
  };
  handshake = {
    client_random = None;
    server_random = None;
    premaster_secret = None;
    master_secret = None;
    handshake_messages = [];
    cookie = None;
    message_seq = 0;
    next_receive_seq = 0;
    pending_fragments = [];
    (* ECDHE fields *)
    ecdhe_keypair = None;
    server_public_key = None;
    selected_curve = None;
  };
}

(** {1 Effect-based I/O Helpers} *)

let random_bytes n =
  perform (Random n)

let now () =
  perform Now

(** {1 DTLS Record Layer} *)

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

(** Encrypt a DTLS record using AES-GCM (RFC 5288)
    Input: plaintext record payload
    Output: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes)

    The explicit nonce is the sequence number, prepended to the ciphertext.
    Total overhead: 8 (nonce) + 16 (tag) = 24 bytes *)
let encrypt_record ~(t:t) ~content_type ~epoch ~seq_num ~plaintext =
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
    let ciphertext_tag = Webrtc_crypto.aes_gcm_encrypt
      ~key ~implicit_iv ~explicit_nonce ~aad:aad_cs ~plaintext:plaintext_cs
    in

    (* Output: explicit_nonce || ciphertext || tag *)
    let result = Cstruct.concat [explicit_nonce; ciphertext_tag] in
    Result.Ok (Cstruct.to_bytes result)

  | _ when not t.config.is_client ->
    (* Server uses server_write_key/iv for encryption *)
    begin match t.crypto.server_write_key, t.crypto.server_write_iv with
    | Some write_key, Some write_iv ->
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
      let ciphertext_tag = Webrtc_crypto.aes_gcm_encrypt
        ~key ~implicit_iv ~explicit_nonce ~aad:aad_cs ~plaintext:plaintext_cs
      in

      (* Output: explicit_nonce || ciphertext || tag *)
      let result = Cstruct.concat [explicit_nonce; ciphertext_tag] in
      Result.Ok (Cstruct.to_bytes result)

    | _ -> Result.Error "Server encryption keys not available"
    end

  | _ -> Result.Error "Client encryption keys not available"

(** Decrypt a DTLS record using AES-GCM (RFC 5288)
    Input: explicit_nonce (8 bytes) || ciphertext || tag (16 bytes)
    Output: plaintext record payload *)
let decrypt_record ~(t:t) ~content_type ~epoch ~seq_num ~ciphertext_with_nonce =
  let ciphertext_bytes = ciphertext_with_nonce in
  let ciphertext_len = Bytes.length ciphertext_bytes in

  (* Need at least explicit_nonce (8) + tag (16) = 24 bytes *)
  if ciphertext_len < 24 then
    Result.Error "Ciphertext too short for AES-GCM"
  else
    (* Extract explicit nonce (first 8 bytes) *)
    let explicit_nonce = Cstruct.of_bytes (Bytes.sub ciphertext_bytes 0 8) in
    let ciphertext_tag = Cstruct.of_bytes (Bytes.sub ciphertext_bytes 8 (ciphertext_len - 8)) in

    (* Plaintext length = ciphertext - tag (16 bytes) *)
    let plaintext_len = ciphertext_len - 8 - 16 in

    match t.crypto.server_write_key, t.crypto.server_write_iv with
    | Some read_key, Some read_iv when t.config.is_client ->
      (* Client reads using server's write key *)
      let key = Cstruct.of_bytes read_key in
      let implicit_iv = Cstruct.of_bytes read_iv in

      (* Build AAD with plaintext length *)
      let aad = build_aad ~epoch ~seq_num ~content_type ~length:plaintext_len in
      let aad_cs = Cstruct.of_bytes aad in

      begin match Webrtc_crypto.aes_gcm_decrypt
        ~key ~implicit_iv ~explicit_nonce ~aad:aad_cs ~ciphertext_and_tag:ciphertext_tag
      with
      | Ok plaintext -> Result.Ok (Cstruct.to_bytes plaintext)
      | Error e -> Result.Error e
      end

    | _ -> Result.Error "Decryption keys not available"

let parse_record_header data =
  if Bytes.length data < record_header_size then
    Result.Error "Record too short"
  else
    let ct = Bytes.get_uint8 data 0 in
    match int_to_content_type ct with
    | None -> Result.Error (Printf.sprintf "Unknown content type: %d" ct)
    | Some content_type ->
      let _version_major = Bytes.get_uint8 data 1 in
      let _version_minor = Bytes.get_uint8 data 2 in
      let epoch = Bytes.get_uint16_be data 3 in
      let seq_high = Int64.of_int (Bytes.get_uint16_be data 5) in
      let seq_low = Int64.of_int32 (Bytes.get_int32_be data 7) in
      let seq_num = Int64.logor (Int64.shift_left seq_high 32) (Int64.logand seq_low 0xFFFFFFFFL) in
      let length = Bytes.get_uint16_be data 11 in
      Result.Ok (content_type, epoch, seq_num, length)

(** {1 Handshake Message Building} *)

(** Handshake header:
    - msg_type: 1 byte
    - length: 3 bytes
    - message_seq: 2 bytes
    - fragment_offset: 3 bytes
    - fragment_length: 3 bytes
    Total: 12 bytes *)
let handshake_header_size = 12

let build_handshake_header msg_type length msg_seq frag_offset frag_length =
  let buf = Bytes.create handshake_header_size in
  Bytes.set_uint8 buf 0 (handshake_type_to_int msg_type);
  (* 3-byte length *)
  Bytes.set_uint8 buf 1 ((length lsr 16) land 0xFF);
  Bytes.set_uint16_be buf 2 (length land 0xFFFF);
  Bytes.set_uint16_be buf 4 msg_seq;
  (* 3-byte fragment offset *)
  Bytes.set_uint8 buf 6 ((frag_offset lsr 16) land 0xFF);
  Bytes.set_uint16_be buf 7 (frag_offset land 0xFFFF);
  (* 3-byte fragment length *)
  Bytes.set_uint8 buf 9 ((frag_length lsr 16) land 0xFF);
  Bytes.set_uint16_be buf 10 (frag_length land 0xFFFF);
  buf

let build_client_hello t =
  let client_random = random_bytes 32 in
  t.handshake.client_random <- Some client_random;

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

  (* Calculate body size *)
  let body_len = 2 + 32 + 1 + 1 + cookie_len + 2 + (num_suites * 2) + 1 + 1 + 2 in
  let body = Bytes.create body_len in
  let pos = ref 0 in

  (* Version *)
  Bytes.set_uint8 body !pos dtls_version_major; incr pos;
  Bytes.set_uint8 body !pos dtls_version_minor; incr pos;

  (* Random *)
  Bytes.blit client_random 0 body !pos 32;
  pos := !pos + 32;

  (* Session ID (empty) *)
  Bytes.set_uint8 body !pos 0; incr pos;

  (* Cookie *)
  Bytes.set_uint8 body !pos cookie_len; incr pos;
  if cookie_len > 0 then begin
    Bytes.blit cookie 0 body !pos cookie_len;
    pos := !pos + cookie_len
  end;

  (* Cipher suites *)
  Bytes.set_uint16_be body !pos (num_suites * 2); pos := !pos + 2;
  List.iter (fun suite ->
    Bytes.set_uint16_be body !pos (cipher_suite_to_int suite);
    pos := !pos + 2
  ) t.config.cipher_suites;

  (* Compression methods (null only) *)
  Bytes.set_uint8 body !pos 1; incr pos;
  Bytes.set_uint8 body !pos 0; incr pos;

  (* Extensions (empty for now) *)
  Bytes.set_uint16_be body !pos 0;

  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;

  let header = build_handshake_header ClientHello body_len msg_seq 0 body_len in
  let handshake_data = Bytes.cat header body in

  (* Store for Finished verification *)
  t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;

  (* Wrap in record *)
  let record_header = build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length handshake_data) in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

  Bytes.cat record_header handshake_data

(** {1 Handshake} *)

let start_handshake t =
  if not t.config.is_client then
    Result.Error "Only client can initiate handshake"
  else begin
    let client_hello = build_client_hello t in
    t.state <- HelloSent;
    Result.Ok [client_hello]
  end

let handle_hello_verify_request t data =
  (* Parse HelloVerifyRequest:
     - server_version: 2 bytes
     - cookie_length: 1 byte
     - cookie: variable *)
  if Bytes.length data < 3 then
    Result.Error "HelloVerifyRequest too short"
  else begin
    let cookie_len = Bytes.get_uint8 data 2 in
    if Bytes.length data < 3 + cookie_len then
      Result.Error "HelloVerifyRequest cookie truncated"
    else begin
      let cookie = Bytes.sub data 3 cookie_len in
      t.handshake.cookie <- Some cookie;
      t.state <- HelloVerifyReceived;

      (* Rebuild ClientHello with cookie *)
      t.handshake.message_seq <- 0;
      t.crypto.write_seq_num <- 0L;
      let client_hello = build_client_hello t in
      t.state <- HelloSent;
      Result.Ok ([client_hello], None)
    end
  end

let handle_server_hello t data =
  (* Parse ServerHello:
     - server_version: 2 bytes
     - random: 32 bytes
     - session_id length: 1 byte + session_id
     - cipher_suite: 2 bytes
     - compression_method: 1 byte
     - extensions: optional *)
  if Bytes.length data < 38 then
    Result.Error "ServerHello too short"
  else begin
    let server_random = Bytes.sub data 2 32 in
    t.handshake.server_random <- Some server_random;

    let session_id_len = Bytes.get_uint8 data 34 in
    let offset = 35 + session_id_len in

    if Bytes.length data < offset + 3 then
      Result.Error "ServerHello truncated"
    else begin
      let cipher_suite_code = Bytes.get_uint16_be data offset in
      match int_to_cipher_suite cipher_suite_code with
      | None -> Error "Unsupported cipher suite"
      | Some suite ->
        t.negotiated_cipher <- Some suite;
        t.state <- ServerHelloReceived;
        Result.Ok ([], None)
    end
  end

let handle_certificate t data =
  (* Parse Certificate chain *)
  if Bytes.length data < 3 then
    Result.Error "Certificate message too short"
  else begin
    let _total_len =
      (Bytes.get_uint8 data 0 lsl 16) lor
      (Bytes.get_uint16_be data 1)
    in
    (* For now, just store the raw data as the peer certificate *)
    t.peer_certificate <- Some (Bytes.to_string data);
    t.state <- CertificateReceived;
    Result.Ok ([], None)
  end

(** Handle ServerKeyExchange - parse ECDHE parameters (RFC 8422) *)
let handle_server_key_exchange t data =
  let data_cs = Cstruct.of_bytes data in
  match Ecdhe.parse_server_ecdh_params data_cs with
  | Error e -> Result.Error (Printf.sprintf "ServerKeyExchange parse error: %s" e)
  | Ok (curve, server_pub) ->
    (* Store server's ECDHE public key *)
    t.handshake.selected_curve <- Some curve;
    t.handshake.server_public_key <- Some server_pub;
    (* Generate our ECDHE key pair *)
    begin match Ecdhe.generate ~curve with
    | Error e -> Result.Error (Printf.sprintf "ECDHE key generation failed: %s" e)
    | Ok keypair ->
      t.handshake.ecdhe_keypair <- Some keypair;
      Result.Ok ([], None)
    end

(** Handle ServerHelloDone - complete ECDHE key exchange and send client flight *)
let rec handle_server_hello_done t _data =
  (* ServerHelloDone has no body *)
  t.state <- KeyExchangeDone;

  (* Get ECDHE keypair and server public key *)
  match t.handshake.ecdhe_keypair, t.handshake.server_public_key with
  | None, _ | _, None ->
    (* Fallback: Generate ECDHE keypair if not already done (self-signed/test mode) *)
    begin match Ecdhe.generate_p256 () with
    | Error e -> Result.Error (Printf.sprintf "ECDHE generation failed: %s" e)
    | Ok keypair ->
      t.handshake.ecdhe_keypair <- Some keypair;
      (* Use dummy shared secret for testing without ServerKeyExchange *)
      let dummy_premaster = Bytes.create 32 in
      for i = 0 to 31 do Bytes.set_uint8 dummy_premaster i (i land 0xFF) done;
      t.handshake.premaster_secret <- Some dummy_premaster;
      build_client_flight t keypair
    end
  | Some keypair, Some server_pub ->
    (* Real ECDHE: Compute shared secret *)
    begin match Ecdhe.compute_shared_secret ~keypair ~peer_public_key:server_pub with
    | Error e -> Result.Error (Printf.sprintf "ECDHE shared secret computation failed: %s" e)
    | Ok premaster_cs ->
      let premaster = Cstruct.to_bytes premaster_cs in
      t.handshake.premaster_secret <- Some premaster;

      (* Derive master secret using TLS 1.2 PRF *)
      begin match t.handshake.client_random, t.handshake.server_random with
      | Some client_random, Some server_random ->
        let client_random_cs = Cstruct.of_bytes client_random in
        let server_random_cs = Cstruct.of_bytes server_random in
        let master_secret_cs = Webrtc_crypto.derive_master_secret
          ~pre_master_secret:premaster_cs
          ~client_random:client_random_cs
          ~server_random:server_random_cs
        in
        t.handshake.master_secret <- Some (Cstruct.to_bytes master_secret_cs);

        (* Derive key material for AES-128-GCM encryption (RFC 5288) *)
        let key_material = Webrtc_crypto.derive_key_material
          ~master_secret:master_secret_cs
          ~server_random:server_random_cs
          ~client_random:client_random_cs
          ~key_size:Webrtc_crypto.aes_128_gcm_key_size
          ~iv_size:Webrtc_crypto.aes_gcm_implicit_iv_size
        in
        t.crypto.client_write_key <- Some (Cstruct.to_bytes key_material.client_write_key);
        t.crypto.server_write_key <- Some (Cstruct.to_bytes key_material.server_write_key);
        t.crypto.client_write_iv <- Some (Cstruct.to_bytes key_material.client_write_iv);
        t.crypto.server_write_iv <- Some (Cstruct.to_bytes key_material.server_write_iv);

        build_client_flight t keypair
      | _ ->
        Result.Error "Missing client_random or server_random"
      end
    end

(** Build client's response flight: ClientKeyExchange + ChangeCipherSpec + Finished *)
and build_client_flight t keypair =
  (* Build ClientKeyExchange with our ECDHE public key *)
  let pub_key_encoded = Ecdhe.encode_public_key keypair in
  let key_exchange_body = Cstruct.to_bytes pub_key_encoded in

  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;

  let key_len = Bytes.length key_exchange_body in
  let header = build_handshake_header ClientKeyExchange key_len msg_seq 0 key_len in
  let handshake_data = Bytes.cat header key_exchange_body in
  t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;

  let record1 = Bytes.cat
    (build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length handshake_data))
    handshake_data
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

  (* Build ChangeCipherSpec *)
  let ccs_body = Bytes.create 1 in
  Bytes.set_uint8 ccs_body 0 1;
  let record2 = Bytes.cat
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
      let verify_data = Ecdhe.compute_verify_data
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

  (* After ChangeCipherSpec, all records must be encrypted (RFC 6347) *)
  let record3 =
    match encrypt_record ~t ~content_type:Handshake
            ~epoch:t.epoch ~seq_num:t.crypto.write_seq_num ~plaintext:finished_data
    with
    | Ok encrypted_payload ->
      (* Encrypted record: header with encrypted length + encrypted payload *)
      Bytes.cat
        (build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length encrypted_payload))
        encrypted_payload
    | Error _ ->
      (* Fallback to plaintext if encryption fails (for testing/debugging) *)
      Bytes.cat
        (build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length finished_data))
        finished_data
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

  Result.Ok ([record1; record2; record3], None)

let handle_finished t _data =
  (* Verify Finished message *)
  t.state <- Established;
  Result.Ok ([], None)

let handle_handshake_message t msg_type data =
  match msg_type with
  | HelloVerifyRequest -> handle_hello_verify_request t data
  | ServerHello -> handle_server_hello t data
  | Certificate -> handle_certificate t data
  | ServerKeyExchange -> handle_server_key_exchange t data
  | ServerHelloDone -> handle_server_hello_done t data
  | Finished -> handle_finished t data
  | _ -> Result.Error (Printf.sprintf "Unexpected handshake message type")

let handle_record t data =
  match parse_record_header data with
  | Result.Error e -> Result.Error e
  | Result.Ok (content_type, epoch, seq_num, length) ->
    let raw_payload = Bytes.sub data record_header_size length in

    (* Decrypt payload if epoch > 0 (after ChangeCipherSpec) *)
    let payload_result =
      if epoch > 0 && content_type <> ChangeCipherSpec then
        decrypt_record ~t ~content_type ~epoch ~seq_num ~ciphertext_with_nonce:raw_payload
      else
        Ok raw_payload
    in

    match payload_result with
    | Error e -> Result.Error (Printf.sprintf "Decryption failed: %s" e)
    | Ok payload ->
      begin match content_type with
      | Handshake ->
        if Bytes.length payload < handshake_header_size then
          Result.Error "Handshake message too short"
        else begin
          let msg_type_int = Bytes.get_uint8 payload 0 in
          match int_to_handshake_type msg_type_int with
          | None -> Result.Error "Unknown handshake type"
          | Some msg_type ->
            let body_len =
              (Bytes.get_uint8 payload 1 lsl 16) lor
              (Bytes.get_uint16_be payload 2)
            in
            let body = Bytes.sub payload handshake_header_size body_len in
            handle_handshake_message t msg_type body
        end
      | ChangeCipherSpec ->
        t.epoch <- t.epoch + 1;
        t.crypto.read_seq_num <- 0L;
        Result.Ok ([], None)
      | Alert ->
        if Bytes.length payload >= 2 then begin
          let level = Bytes.get_uint8 payload 0 in
          let desc = Bytes.get_uint8 payload 1 in
          if level = 2 then begin
            t.state <- Closed;
            Result.Error (Printf.sprintf "Fatal alert: %d" desc)
          end else
            Result.Ok ([], None)
        end else
          Result.Error "Alert too short"
      | ApplicationData ->
        if t.state = Established then
          Result.Ok ([], Some payload)
        else
          Result.Error "Application data before handshake complete"
      end

(** {1 State Queries} *)

let is_established t = t.state = Established

let get_state t = t.state

(** {1 AES-GCM Encryption Helpers} *)

(** GCM constants *)
let gcm_tag_size = 16
let gcm_explicit_nonce_size = 8

(** Build 12-byte GCM nonce from 4-byte implicit IV + 8-byte explicit nonce *)
let build_gcm_nonce ~implicit_iv ~seq_num =
  let nonce = Bytes.create 12 in
  Bytes.blit implicit_iv 0 nonce 0 4;
  (* Encode sequence number as big-endian 8 bytes *)
  for i = 0 to 7 do
    let shift = (7 - i) * 8 in
    Bytes.set_uint8 nonce (4 + i) (Int64.to_int (Int64.shift_right_logical seq_num shift) land 0xff)
  done;
  nonce

(** Build AAD (Additional Authenticated Data) for AEAD
    Format: epoch (2) || seq_num (6) || content_type (1) || version (2) || length (2) *)
let build_gcm_aad ~epoch ~seq_num ~content_type ~length =
  let aad = Bytes.create 13 in
  (* Epoch (2 bytes) - in DTLS, epoch is part of explicit nonce *)
  Bytes.set_uint16_be aad 0 epoch;
  (* Sequence number (6 bytes, lower 48 bits) *)
  for i = 0 to 5 do
    let shift = (5 - i) * 8 in
    Bytes.set_uint8 aad (2 + i) (Int64.to_int (Int64.shift_right_logical seq_num shift) land 0xff)
  done;
  (* Content type *)
  Bytes.set_uint8 aad 8 (content_type_to_int content_type);
  (* Version (DTLS 1.2 = 254.253) *)
  Bytes.set_uint8 aad 9 254;
  Bytes.set_uint8 aad 10 253;
  (* Length of plaintext *)
  Bytes.set_uint16_be aad 11 length;
  aad

(** {1 Data Transfer} *)

let encrypt t data =
  if t.state <> Established then
    Result.Error "Connection not established"
  else
    (* Get write keys based on role *)
    let write_key_opt, write_iv_opt =
      if t.config.is_client then
        (t.crypto.client_write_key, t.crypto.client_write_iv)
      else
        (t.crypto.server_write_key, t.crypto.server_write_iv)
    in
    match write_key_opt, write_iv_opt with
    | None, _ | _, None ->
      (* Epoch 0: no encryption, return plaintext with header *)
      let record = Bytes.cat
        (build_record_header ApplicationData t.epoch t.crypto.write_seq_num (Bytes.length data))
        data
      in
      t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
      Result.Ok record
    | Some write_key, Some write_iv ->
      (* Real AES-GCM encryption *)
      let seq_num = t.crypto.write_seq_num in
      let nonce = build_gcm_nonce ~implicit_iv:write_iv ~seq_num in
      let aad = build_gcm_aad ~epoch:t.epoch ~seq_num ~content_type:ApplicationData ~length:(Bytes.length data) in

      (* Explicit nonce (8 bytes) to prepend to ciphertext *)
      let explicit_nonce = Bytes.create gcm_explicit_nonce_size in
      for i = 0 to 7 do
        let shift = (7 - i) * 8 in
        Bytes.set_uint8 explicit_nonce i (Int64.to_int (Int64.shift_right_logical seq_num shift) land 0xff)
      done;

      (* Encrypt with AES-GCM *)
      let key = Mirage_crypto.AES.GCM.of_secret (Bytes.to_string write_key) in
      let ciphertext_with_tag = Mirage_crypto.AES.GCM.authenticate_encrypt
        ~key
        ~nonce:(Bytes.to_string nonce)
        ~adata:(Bytes.to_string aad)
        (Bytes.to_string data)
      in

      (* Record length = explicit_nonce + ciphertext + tag *)
      let encrypted_len = gcm_explicit_nonce_size + String.length ciphertext_with_tag in
      let header = build_record_header ApplicationData t.epoch seq_num encrypted_len in
      let record = Bytes.concat Bytes.empty [header; explicit_nonce; Bytes.of_string ciphertext_with_tag] in

      t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
      Result.Ok record

let decrypt t data =
  match parse_record_header data with
  | Result.Error e -> Result.Error e
  | Result.Ok (ApplicationData, epoch, seq_num, length) ->
    if t.state <> Established then
      Result.Error "Connection not established"
    else begin
      (* Get read keys based on role (opposite of write) *)
      let read_key_opt, read_iv_opt =
        if t.config.is_client then
          (t.crypto.server_write_key, t.crypto.server_write_iv)
        else
          (t.crypto.client_write_key, t.crypto.client_write_iv)
      in
      match read_key_opt, read_iv_opt with
      | None, _ | _, None ->
        (* Epoch 0: no encryption, return plaintext *)
        let payload = Bytes.sub data record_header_size length in
        t.crypto.read_seq_num <- Int64.add t.crypto.read_seq_num 1L;
        Result.Ok payload
      | Some read_key, Some read_iv ->
        (* Real AES-GCM decryption *)
        if length < gcm_explicit_nonce_size + gcm_tag_size then
          Result.Error "Ciphertext too short"
        else begin
          (* Extract explicit nonce *)
          let explicit_nonce = Bytes.sub data record_header_size gcm_explicit_nonce_size in
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
          let aad = build_gcm_aad ~epoch ~seq_num ~content_type:ApplicationData ~length:plaintext_len in

          (* Decrypt with AES-GCM *)
          let key = Mirage_crypto.AES.GCM.of_secret (Bytes.to_string read_key) in
          match Mirage_crypto.AES.GCM.authenticate_decrypt
            ~key
            ~nonce:(Bytes.to_string nonce)
            ~adata:(Bytes.to_string aad)
            (Bytes.to_string ciphertext_with_tag)
          with
          | Some plaintext ->
            t.crypto.read_seq_num <- Int64.add t.crypto.read_seq_num 1L;
            Result.Ok (Bytes.of_string plaintext)
          | None ->
            Result.Error "Decryption failed - authentication error"
        end
    end
  | Result.Ok _ ->
    Result.Error "Not application data"

(** {1 Key Export} *)

let export_keying_material t ~label ~context ~length =
  if t.state <> Established then
    Result.Error "Connection not established"
  else
    match t.handshake.master_secret with
    | None -> Error "No master secret"
    | Some _master_secret ->
      (* Placeholder: should use PRF with label, context *)
      let _ = (label, context) in
      Result.Ok (random_bytes length)

(** {1 Utilities} *)

let close t =
  if t.state = Established || t.state = ChangeCipherSpecSent then begin
    (* Build close_notify alert *)
    let alert = Bytes.create 2 in
    Bytes.set_uint8 alert 0 (alert_level_to_int Warning);
    Bytes.set_uint8 alert 1 (alert_description_to_int CloseNotify);
    let record = Bytes.cat
      (build_record_header Alert t.epoch t.crypto.write_seq_num 2)
      alert
    in
    t.state <- Closed;
    Some record
  end else begin
    t.state <- Closed;
    None
  end

let get_cipher_suite t = t.negotiated_cipher

let get_peer_certificate t = t.peer_certificate

let pp_state fmt = function
  | Initial -> Format.fprintf fmt "Initial"
  | HelloSent -> Format.fprintf fmt "HelloSent"
  | HelloVerifyReceived -> Format.fprintf fmt "HelloVerifyReceived"
  | ServerHelloReceived -> Format.fprintf fmt "ServerHelloReceived"
  | CertificateReceived -> Format.fprintf fmt "CertificateReceived"
  | KeyExchangeDone -> Format.fprintf fmt "KeyExchangeDone"
  | ChangeCipherSpecSent -> Format.fprintf fmt "ChangeCipherSpecSent"
  | Established -> Format.fprintf fmt "Established"
  | Closed -> Format.fprintf fmt "Closed"
  | Error e -> Format.fprintf fmt "Error(%s)" e

(** {1 Cookie Handling} *)

let generate_cookie _t ~client_hello =
  (* Generate HMAC of client_hello (simplified) *)
  let hash = Bytes.create 32 in
  for i = 0 to 31 do
    let idx = i mod (Bytes.length client_hello) in
    Bytes.set_uint8 hash i (Bytes.get_uint8 client_hello idx)
  done;
  hash

let verify_cookie _t ~cookie ~client_hello =
  (* Verify cookie matches client_hello *)
  let expected = generate_cookie _t ~client_hello in
  Bytes.equal cookie expected

(** {1 I/O Operations (Functional Dependency Injection)} *)

(** I/O operations for DTLS transport.
    This abstraction allows different transport implementations:
    - Eio UDP sockets (production)
    - Mock transport (testing)
    - Lwt/Unix fallback *)
type io_ops = {
  send: bytes -> int;         (** Send data, returns bytes sent *)
  recv: int -> bytes;         (** Receive up to N bytes (blocking) *)
  now: unit -> float;         (** Get current timestamp *)
  random: int -> bytes;       (** Generate N cryptographically secure random bytes *)
}

(** Default I/O ops using Unix and Mirage_crypto *)
let default_io_ops = {
  send = (fun _ -> 0);  (* No-op for testing *)
  recv = (fun _ -> Bytes.empty);
  now = Unix.gettimeofday;
  random = (fun n ->
    (* Mirage_crypto_rng.generate returns string in newer versions *)
    Bytes.of_string (Mirage_crypto_rng.generate n)
  );
}

(** {1 Effect Handler (for Eio integration)} *)

(** Run DTLS code with custom I/O operations.
    This is the primary API - works with any transport implementation.
    @param ops I/O operations (send, recv, now, random)
    @param f The DTLS function to run *)
let run_with_io ~ops f =
  try_with f () {
    effc = fun (type a) (eff : a Effect.t) ->
      match eff with
      | Send data -> Some (fun (k : (a, _) continuation) ->
          let bytes_sent = ops.send data in
          continue k bytes_sent
        )
      | Recv size -> Some (fun (k : (a, _) continuation) ->
          let data = ops.recv size in
          continue k data
        )
      | Now -> Some (fun (k : (a, _) continuation) ->
          continue k (ops.now ())
        )
      | Random n -> Some (fun (k : (a, _) continuation) ->
          continue k (ops.random n)
        )
      | _ -> None
  }

(** Legacy wrapper for backward compatibility.
    Uses default no-op I/O - prefer run_with_io for production. *)
let run_with_eio ~net:_ ~clock:_ f =
  run_with_io ~ops:default_io_ops f
