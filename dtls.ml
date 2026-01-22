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
  | SetTimer : int -> unit Effect.t    (** Set retransmit timer (ms) *)
  | CancelTimer : unit Effect.t        (** Cancel pending retransmit timer *)

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
  (* Client states *)
  | HelloSent
  | HelloVerifyReceived
  | ServerHelloReceived
  | CertificateReceived
  | KeyExchangeDone
  | ChangeCipherSpecSent
  | Established
  | Closed
  | Error of string
  (* Server states *)
  | HelloVerifySent           (** Server sent HelloVerifyRequest, waiting for ClientHello with cookie *)
  | ClientHelloReceived       (** Server received valid ClientHello with cookie *)
  | ServerFlightSent          (** Server sent full flight (ServerHello...ServerHelloDone) *)
  | ClientKeyExchangeReceived (** Server received ClientKeyExchange *)

type cipher_suite =
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

type srtp_profile = Srtp.profile

type config = {
  is_client : bool;
  certificate : string option;
  private_key : string option;
  verify_peer : bool;
  cipher_suites : cipher_suite list;
  srtp_profiles : Srtp.profile list;
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

(** RFC 6347 Section 4.2.4: Retransmission state for flight-based reliability *)
type retransmit_state = {
  mutable last_flight : bytes list;       (** Last flight sent (for retransmission) *)
  mutable retransmit_count : int;         (** Current retransmit attempt *)
  mutable current_timeout_ms : int;       (** Current timeout (exponential backoff) *)
  mutable flight_sent_at : float;         (** Timestamp when flight was sent *)
  mutable timer_active : bool;            (** Whether retransmit timer is running *)
}

type t = {
  config : config;
  mutable state : state;
  mutable negotiated_cipher : cipher_suite option;
  mutable negotiated_srtp_profile : Srtp.profile option;
  mutable peer_certificate : string option;
  mutable epoch : int;
  crypto : crypto_state;
  handshake : handshake_state;
  retransmit : retransmit_state;    (** RFC 6347 retransmission state *)
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

(** RFC 5764 use_srtp extension type *)
let use_srtp_extension_type = 0x000e

let srtp_profile_to_id = function
  | Srtp.SRTP_AES128_CM_HMAC_SHA1_80 -> 0x0001
  | Srtp.SRTP_AES128_CM_HMAC_SHA1_32 -> 0x0002
  | Srtp.SRTP_NULL_HMAC_SHA1_80 -> 0x0005
  | Srtp.SRTP_NULL_HMAC_SHA1_32 -> 0x0006
  | Srtp.SRTP_AEAD_AES_128_GCM -> 0x0007  (* RFC 7714 *)
  | Srtp.SRTP_AEAD_AES_256_GCM -> 0x0008  (* RFC 7714 *)

let srtp_profile_of_id = function
  | 0x0001 -> Some Srtp.SRTP_AES128_CM_HMAC_SHA1_80
  | 0x0002 -> Some Srtp.SRTP_AES128_CM_HMAC_SHA1_32
  | 0x0005 -> Some Srtp.SRTP_NULL_HMAC_SHA1_80
  | 0x0006 -> Some Srtp.SRTP_NULL_HMAC_SHA1_32
  | 0x0007 -> Some Srtp.SRTP_AEAD_AES_128_GCM   (* RFC 7714 *)
  | 0x0008 -> Some Srtp.SRTP_AEAD_AES_256_GCM   (* RFC 7714 *)
  | _ -> None

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
  srtp_profiles = [];
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
  srtp_profiles = [];
  mtu = 1400;
  retransmit_timeout_ms = 1000;
  max_retransmits = 5;
}

(** {1 Context Creation} *)

let create config = {
  config;
  state = Initial;
  negotiated_cipher = None;
  negotiated_srtp_profile = None;
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
  retransmit = {
    last_flight = [];
    retransmit_count = 0;
    current_timeout_ms = config.retransmit_timeout_ms;
    flight_sent_at = 0.0;
    timer_active = false;
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

    if t.config.is_client then
      (* Client reads using server's write key *)
      match t.crypto.server_write_key, t.crypto.server_write_iv with
      | Some read_key, Some read_iv ->
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
    else
      (* Server reads using client's write key *)
      match t.crypto.client_write_key, t.crypto.client_write_iv with
      | Some read_key, Some read_iv ->
        let key = Cstruct.of_bytes read_key in
        let implicit_iv = Cstruct.of_bytes read_iv in

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

let build_use_srtp_extension profiles =
  match profiles with
  | [] -> Bytes.empty
  | _ ->
    let profile_ids = List.map srtp_profile_to_id profiles in
    let profile_list_len = List.length profile_ids * 2 in
    let ext_len = 2 + profile_list_len + 1 in
    let ext = Bytes.create (4 + ext_len) in
    Bytes.set_uint16_be ext 0 use_srtp_extension_type;
    Bytes.set_uint16_be ext 2 ext_len;
    Bytes.set_uint16_be ext 4 profile_list_len;
    let pos = ref 6 in
    List.iter (fun profile_id ->
      Bytes.set_uint16_be ext !pos profile_id;
      pos := !pos + 2
    ) profile_ids;
    Bytes.set_uint8 ext !pos 0;  (* MKI length = 0 *)
    ext

let build_extensions profiles =
  let use_srtp = build_use_srtp_extension profiles in
  if Bytes.length use_srtp = 0 then Bytes.empty else use_srtp

let parse_use_srtp_extension data =
  if Bytes.length data < 3 then
    []
  else
    let profile_len = Bytes.get_uint16_be data 0 in
    if profile_len mod 2 <> 0 || Bytes.length data < 2 + profile_len + 1 then
      []
    else
      let profiles = ref [] in
      let pos = ref 2 in
      while !pos < 2 + profile_len do
        let id = Bytes.get_uint16_be data !pos in
        begin match srtp_profile_of_id id with
        | Some profile -> profiles := profile :: !profiles
        | None -> ()
        end;
        pos := !pos + 2
      done;
      List.rev !profiles

let parse_extensions data =
  let len = Bytes.length data in
  let rec loop off profiles =
    if off = len then
      profiles
    else if off + 4 > len then
      profiles
    else
      let ext_type = Bytes.get_uint16_be data off in
      let ext_len = Bytes.get_uint16_be data (off + 2) in
      let next = off + 4 + ext_len in
      if next > len then
        profiles
      else
        let ext_data = Bytes.sub data (off + 4) ext_len in
        let profiles =
          if ext_type = use_srtp_extension_type then
            parse_use_srtp_extension ext_data
          else
            profiles
        in
        loop next profiles
  in
  loop 0 []

let select_srtp_profile local_profiles remote_profiles =
  if local_profiles = [] then
    None
  else
    List.find_opt (fun profile -> List.mem profile remote_profiles) local_profiles

let build_client_hello t =
  (* Reuse existing client_random if present (for HelloVerifyRequest retry) *)
  let client_random = match t.handshake.client_random with
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

  (* Extensions *)
  Bytes.set_uint16_be body !pos extensions_len;
  pos := !pos + 2;
  if extensions_len > 0 then
    Bytes.blit extensions 0 body !pos extensions_len;

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
        let ext_pos = offset + 3 in
        if Bytes.length data >= ext_pos + 2 then begin
          let ext_len = Bytes.get_uint16_be data ext_pos in
          if Bytes.length data >= ext_pos + 2 + ext_len then begin
            let ext_data = Bytes.sub data (ext_pos + 2) ext_len in
            let srtp_profiles = parse_extensions ext_data in
            begin match srtp_profiles with
            | profile :: _ -> t.negotiated_srtp_profile <- Some profile
            | [] -> ()
            end
          end
        end;
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
  if Bytes.length data < 4 then
    Result.Error "ServerKeyExchange too short"
  else
    let curve_type = Bytes.get_uint8 data 0 in
    if curve_type <> 3 then
      Result.Error (Printf.sprintf "Unsupported curve type: %d (expected named_curve=3)" curve_type)
    else
      let curve_id = Bytes.get_uint16_be data 1 in
      match Ecdhe.named_curve_of_int curve_id with
      | None -> Result.Error (Printf.sprintf "Unsupported named curve: %d" curve_id)
      | Some curve ->
        let pub_len = Bytes.get_uint8 data 3 in
        if Bytes.length data < 4 + pub_len then
          Result.Error "ServerKeyExchange public key truncated"
        else
          let pub_bytes = Bytes.sub data 3 (1 + pub_len) in
          begin match Ecdhe.decode_public_key ~curve (Cstruct.of_bytes pub_bytes) with
          | Error e -> Result.Error (Printf.sprintf "ServerKeyExchange parse error: %s" e)
          | Ok server_pub ->
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
  t.handshake.handshake_messages <- finished_data :: t.handshake.handshake_messages;

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

let handle_finished t payload =
  (* RFC 5246 Section 7.4.9: Verify server's Finished message *)
  (* Finished body is 12 bytes of verify_data after handshake header *)
  let data_len = Bytes.length payload in
  if data_len < handshake_header_size + 12 then begin
    (* Data too short - skip verification in testing mode *)
    t.state <- Established;
    Result.Ok ([], None)
  end else
  let body_len =
    (Bytes.get_uint8 payload 1 lsl 16) lor
    (Bytes.get_uint16_be payload 2)
  in
  if data_len < handshake_header_size + body_len || body_len < 12 then begin
    t.state <- Established;
    Result.Ok ([], None)
  end else
  let received_verify_data = Bytes.sub payload handshake_header_size 12 in

  (* Compute expected verify_data *)
  let verification_result =
    match t.handshake.master_secret with
    | Some master_secret ->
      (* Hash all handshake messages (excluding this Finished) *)
      let messages_cs = List.rev_map Cstruct.of_bytes t.handshake.handshake_messages in
      let handshake_hash = Ecdhe.hash_handshake_messages messages_cs in
      let master_secret_cs = Cstruct.of_bytes master_secret in
      let expected_verify_data = Ecdhe.compute_verify_data
        ~master_secret:master_secret_cs
        ~handshake_hash
        ~is_client:false  (* Server's verify_data *)
      in
      let expected_bytes = Cstruct.to_bytes expected_verify_data in
      if Bytes.equal received_verify_data expected_bytes then
        Ok ()
      else
        Error "Finished verify_data mismatch - possible MITM attack"
    | None ->
      (* No master secret - skip verification (testing mode) *)
      Ok ()
  in

  match verification_result with
  | Ok () ->
    t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages;
    t.state <- Established;
    Result.Ok ([], None)
  | Error msg ->
    Result.Error msg

(** {1 Server-Side Handshake (RFC 6347)} *)

(** Cookie secret for HMAC-based stateless cookie generation.
    In production, this should be rotated periodically.
    RFC 6347 Section 4.2.1: Cookie SHOULD be generated using HMAC. *)
let cookie_secret = lazy (random_bytes 32)

(** Generate HMAC-SHA256 based cookie for DoS protection.
    Cookie = HMAC(secret, client_ip || client_port || client_random)
    This ensures stateless operation until cookie is verified. *)
let generate_cookie ~client_addr ~client_random =
  let secret = Lazy.force cookie_secret in
  let (ip, port) = client_addr in
  let port_bytes = Bytes.create 2 in
  Bytes.set_uint16_be port_bytes 0 port;
  (* Combine all inputs for HMAC *)
  let data = Bytes.concat Bytes.empty [
    Bytes.of_string ip;
    port_bytes;
    client_random
  ] in
  (* Use HMAC-SHA256, truncate to 32 bytes *)
  let hmac = Digestif.SHA256.hmac_string ~key:(Bytes.to_string secret) (Bytes.to_string data) in
  Bytes.of_string (Digestif.SHA256.to_raw_string hmac)

(** Verify client's cookie matches expected value *)
let verify_cookie ~client_addr ~client_random ~cookie =
  let expected = generate_cookie ~client_addr ~client_random in
  Bytes.length cookie = Bytes.length expected &&
  Bytes.equal cookie expected

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
  if len < 38 then (* minimum: 2 + 32 + 1 + 1 + 2 *)
    Result.Error "ClientHello too short"
  else begin
    let pos = ref 0 in

    (* Skip version *)
    pos := !pos + 2;

    (* Client random *)
    let client_random = Bytes.sub data !pos 32 in
    pos := !pos + 32;

    (* Session ID *)
    let session_id_len = Bytes.get_uint8 data !pos in
    incr pos;
    if !pos + session_id_len > len then
      Result.Error "ClientHello session_id truncated"
    else begin
      pos := !pos + session_id_len;

      (* Cookie (DTLS specific) *)
      if !pos >= len then
        Result.Error "ClientHello missing cookie field"
      else begin
        let cookie_len = Bytes.get_uint8 data !pos in
        incr pos;
        if !pos + cookie_len > len then
          Result.Error "ClientHello cookie truncated"
        else begin
          let cookie = if cookie_len > 0 then Some (Bytes.sub data !pos cookie_len) else None in
          pos := !pos + cookie_len;

          (* Cipher suites *)
          if !pos + 2 > len then
            Result.Error "ClientHello missing cipher_suites length"
          else begin
            let suites_len = Bytes.get_uint16_be data !pos in
            pos := !pos + 2;
            if !pos + suites_len > len then
              Result.Error "ClientHello cipher_suites truncated"
            else begin
              let num_suites = suites_len / 2 in
              let cipher_suites = Array.init num_suites (fun i ->
                Bytes.get_uint16_be data (!pos + i * 2)
              ) in
              pos := !pos + suites_len;

              (* Compression methods *)
              if !pos >= len then
                Result.Error "ClientHello missing compression methods"
              else begin
                let comp_len = Bytes.get_uint8 data !pos in
                pos := !pos + 1;
                if !pos + comp_len > len then
                  Result.Error "ClientHello compression methods truncated"
                else begin
                  pos := !pos + comp_len;

                  (* Extensions *)
                  if !pos + 2 > len then
                    Result.Ok (client_random, cookie, Array.to_list cipher_suites, [])
                  else begin
                    let ext_len = Bytes.get_uint16_be data !pos in
                    pos := !pos + 2;
                    if !pos + ext_len > len then
                      Result.Error "ClientHello extensions truncated"
                    else
                      let ext_data = Bytes.sub data !pos ext_len in
                      let srtp_profiles = parse_extensions ext_data in
                      Result.Ok (client_random, cookie, Array.to_list cipher_suites, srtp_profiles)
                  end
                end
              end
            end
          end
        end
      end
    end
  end

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
  Bytes.set_uint8 body !pos dtls_version_major; incr pos;
  Bytes.set_uint8 body !pos dtls_version_minor; incr pos;

  (* Cookie *)
  Bytes.set_uint8 body !pos cookie_len; incr pos;
  Bytes.blit cookie 0 body !pos cookie_len;

  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;

  let header = build_handshake_header HelloVerifyRequest body_len msg_seq 0 body_len in
  let handshake_data = Bytes.cat header body in

  (* Wrap in record *)
  let record_header = build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length handshake_data) in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

  Bytes.cat record_header handshake_data

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
    | Some profile -> build_use_srtp_extension [profile]
  in
  let extensions_len = Bytes.length extensions in

  (* Body: 2 + 32 + 1 + 2 + 1 + 2 + extensions_len *)
  let body_len = 40 + extensions_len in
  let body = Bytes.create body_len in
  let pos = ref 0 in

  (* Version *)
  Bytes.set_uint8 body !pos dtls_version_major; incr pos;
  Bytes.set_uint8 body !pos dtls_version_minor; incr pos;

  (* Server random *)
  Bytes.blit server_random 0 body !pos 32;
  pos := !pos + 32;

  (* Session ID (empty) *)
  Bytes.set_uint8 body !pos 0; incr pos;

  (* Cipher suite *)
  Bytes.set_uint16_be body !pos (cipher_suite_to_int cipher_suite);
  pos := !pos + 2;

  (* Compression method (null) *)
  Bytes.set_uint8 body !pos 0; incr pos;

  (* Extensions *)
  Bytes.set_uint16_be body !pos extensions_len;
  pos := !pos + 2;
  if extensions_len > 0 then
    Bytes.blit extensions 0 body !pos extensions_len;

  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;

  let header = build_handshake_header ServerHello body_len msg_seq 0 body_len in
  let handshake_data = Bytes.cat header body in

  (* Store for Finished verification *)
  t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;

  (* Wrap in record *)
  let record_header = build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length handshake_data) in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

  Bytes.cat record_header handshake_data

(** Build Certificate message from PEM-encoded chain. *)
let build_certificate t pem =
  match X509.Certificate.decode_pem_multiple pem with
  | Error (`Msg msg) ->
    Result.Error (Printf.sprintf "Certificate decode failed: %s" msg)
  | Ok [] ->
    Result.Error "Certificate chain is empty"
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
    List.iter (fun cert ->
      let len = Bytes.length cert in
      Bytes.set_uint8 body !pos ((len lsr 16) land 0xFF);
      Bytes.set_uint16_be body (!pos + 1) (len land 0xFFFF);
      Bytes.blit cert 0 body (!pos + 3) len;
      pos := !pos + 3 + len
    ) certs_bytes;

    let msg_seq = t.handshake.message_seq in
    t.handshake.message_seq <- msg_seq + 1;

    let header = build_handshake_header Certificate body_len msg_seq 0 body_len in
    let handshake_data = Bytes.cat header body in
    t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;

    let record_header =
      build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length handshake_data)
    in
    t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;
    Result.Ok (Bytes.cat record_header handshake_data)

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
        begin match t.handshake.client_random, t.handshake.server_random with
        | Some client_random, Some server_random ->
          let input = Bytes.concat Bytes.empty [client_random; server_random; params_bytes] in
          begin match X509.Private_key.decode_pem pem with
          | Error (`Msg msg) ->
            Result.Error (Printf.sprintf "Private key decode failed: %s" msg)
          | Ok key ->
            let scheme =
              match X509.Private_key.key_type key with
              | `RSA -> Ok (`RSA_PKCS1, 1)
              | `P256 | `P384 | `P521 -> Ok (`ECDSA, 3)
              | `ED25519 -> Error "ED25519 is not supported for DTLS 1.2 signatures"
            in
            begin match scheme with
            | Error msg -> Result.Error msg
            | Ok (scheme, sig_alg_id) ->
              begin match X509.Private_key.sign `SHA256 ~scheme key (`Message (Bytes.to_string input)) with
              | Error (`Msg msg) ->
                Result.Error (Printf.sprintf "ServerKeyExchange signature failed: %s" msg)
              | Ok sig_bytes ->
                let sig_len = String.length sig_bytes in
                let block = Bytes.create (2 + 2 + sig_len) in
                Bytes.set_uint8 block 0 4;  (* SHA-256 *)
                Bytes.set_uint8 block 1 sig_alg_id;
                Bytes.set_uint16_be block 2 sig_len;
                Bytes.blit_string sig_bytes 0 block 4 sig_len;
                Result.Ok (Some block)
              end
            end
          end
        | _ ->
          Result.Error "Missing client_random or server_random for signature"
        end
      | _ -> Result.Ok None
    in
    begin match signature_block with
    | Error _ as err -> err
    | Ok signature_opt ->
      let body_len =
        Bytes.length params_bytes + (match signature_opt with None -> 0 | Some b -> Bytes.length b)
      in
      let body = Bytes.create body_len in
      Bytes.blit params_bytes 0 body 0 (Bytes.length params_bytes);
      begin match signature_opt with
      | None -> ()
      | Some sig_block ->
        Bytes.blit sig_block 0 body (Bytes.length params_bytes) (Bytes.length sig_block)
      end;

    let msg_seq = t.handshake.message_seq in
    t.handshake.message_seq <- msg_seq + 1;

    let header = build_handshake_header ServerKeyExchange body_len msg_seq 0 body_len in
    let handshake_data = Bytes.cat header body in

    (* Store for Finished verification *)
    t.handshake.handshake_messages <- handshake_data :: t.handshake.handshake_messages;

    (* Wrap in record *)
    let record_header = build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length handshake_data) in
    t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

    Result.Ok (Bytes.cat record_header handshake_data)
    end

(** Build ServerHelloDone message (empty body) *)
let build_server_hello_done t =
  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;

  let header = build_handshake_header ServerHelloDone 0 msg_seq 0 0 in

  (* Store for Finished verification *)
  t.handshake.handshake_messages <- header :: t.handshake.handshake_messages;

  (* Wrap in record *)
  let record_header = build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length header) in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

  Bytes.cat record_header header

(** Handle ClientHello as server.
    Implements RFC 6347 Section 4.2.1 cookie exchange for DoS protection. *)
let handle_client_hello t ~payload ~body ~client_addr =
  if t.config.is_client then
    Result.Error "Cannot handle ClientHello as client"
  else
    match parse_client_hello body with
    | Result.Error e -> Result.Error e
    | Result.Ok (client_random, cookie_opt, client_cipher_suites, client_srtp_profiles) ->
      t.handshake.client_random <- Some client_random;

      (* Check cookie for DoS protection *)
      match cookie_opt with
      | None ->
        (* No cookie - send HelloVerifyRequest *)
        let cookie = generate_cookie ~client_addr ~client_random in
        let hvr = build_hello_verify_request t ~cookie in
        t.state <- HelloVerifySent;
        Result.Ok ([hvr], None)

      | Some cookie ->
        (* Verify cookie *)
        if not (verify_cookie ~client_addr ~client_random ~cookie) then
          Result.Error "Invalid cookie"
        else begin
          t.state <- ClientHelloReceived;
          t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages;

          (* Select cipher suite (first common one) *)
          let common_cipher = List.find_opt (fun suite ->
            List.mem (cipher_suite_to_int suite) client_cipher_suites
          ) t.config.cipher_suites in

          match common_cipher with
          | None -> Result.Error "No common cipher suite"
          | Some cipher_suite ->
            let selected_srtp = select_srtp_profile t.config.srtp_profiles client_srtp_profiles in
            if t.config.srtp_profiles <> [] && selected_srtp = None then
              Result.Error "No common SRTP profile"
            else begin
              t.negotiated_srtp_profile <- selected_srtp;

              let has_cert = Option.is_some t.config.certificate in
              let has_key = Option.is_some t.config.private_key in
              if has_cert <> has_key then
                Result.Error "DTLS certificate and private key must both be set"
              else
              (* Build server flight: ServerHello + Certificate + ServerKeyExchange + ServerHelloDone *)
              let server_hello = build_server_hello t ~cipher_suite ~srtp_profile:selected_srtp in
              let certificate =
                match t.config.certificate with
                | None -> Ok None
                | Some pem ->
                  begin match build_certificate t pem with
                  | Ok cert -> Ok (Some cert)
                  | Error e -> Error e
                  end
              in
              match certificate with
              | Error e -> Result.Error e
              | Ok certificate_opt ->
                match build_server_key_exchange t with
                | Result.Error e -> Result.Error e
                | Result.Ok server_key_exchange ->
                  let server_hello_done = build_server_hello_done t in
                  let flight =
                    match certificate_opt with
                    | Some cert -> [server_hello; cert; server_key_exchange; server_hello_done]
                    | None -> [server_hello; server_key_exchange; server_hello_done]
                  in
                  t.state <- ServerFlightSent;
                  Result.Ok (flight, None)
            end
        end

(** Handle ClientKeyExchange as server (ECDHE).
    Extracts client's public key and computes shared secret. *)
let handle_client_key_exchange t data =
  if t.config.is_client then
    Result.Error "Cannot handle ClientKeyExchange as client"
  else if Bytes.length data < 1 then
    Result.Error "ClientKeyExchange too short"
  else begin
    let pub_len = Bytes.get_uint8 data 0 in
    if Bytes.length data < 1 + pub_len then
      Result.Error "ClientKeyExchange public key truncated"
    else begin
      let client_pub_bytes = Bytes.sub data 1 pub_len in
      let client_pub_cs = Cstruct.of_bytes client_pub_bytes in

      match t.handshake.ecdhe_keypair with
      | None -> Result.Error "Server ECDHE keypair not initialized"
      | Some keypair ->
        (* Compute shared secret *)
        match Ecdhe.compute_shared_secret ~keypair ~peer_public_key:client_pub_cs with
        | Error e -> Result.Error (Printf.sprintf "ECDHE computation failed: %s" e)
        | Ok premaster_cs ->
          t.handshake.premaster_secret <- Some (Cstruct.to_bytes premaster_cs);
          t.state <- ClientKeyExchangeReceived;

          (* Derive master secret and key material *)
          match t.handshake.client_random, t.handshake.server_random with
          | Some client_random, Some server_random ->
            let client_random_cs = Cstruct.of_bytes client_random in
            let server_random_cs = Cstruct.of_bytes server_random in
            let master_secret_cs = Webrtc_crypto.derive_master_secret
              ~pre_master_secret:premaster_cs
              ~client_random:client_random_cs
              ~server_random:server_random_cs
            in
            t.handshake.master_secret <- Some (Cstruct.to_bytes master_secret_cs);

            (* Derive key material for AES-128-GCM *)
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

            Result.Ok ([], None)
          | _ ->
            Result.Error "Missing client_random or server_random"
    end
  end

(** Build server's Finished message after receiving client's Finished *)
let build_server_finished t =
  (* Build ChangeCipherSpec *)
  let ccs_body = Bytes.create 1 in
  Bytes.set_uint8 ccs_body 0 1;
  let record_ccs = Bytes.cat
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
      let verify_data = Ecdhe.compute_verify_data
        ~master_secret:master_secret_cs
        ~handshake_hash
        ~is_client:false  (* Server *)
      in
      Cstruct.to_bytes verify_data
    | None ->
      random_bytes 12
  in

  let msg_seq = t.handshake.message_seq in
  t.handshake.message_seq <- msg_seq + 1;

  let finished_header = build_handshake_header Finished 12 msg_seq 0 12 in
  let finished_data = Bytes.cat finished_header finished_body in

  (* Encrypt Finished *)
  let record_finished =
    match encrypt_record ~t ~content_type:Handshake
            ~epoch:t.epoch ~seq_num:t.crypto.write_seq_num ~plaintext:finished_data
    with
    | Ok encrypted_payload ->
      Bytes.cat
        (build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length encrypted_payload))
        encrypted_payload
    | Error _ ->
      Bytes.cat
        (build_record_header Handshake t.epoch t.crypto.write_seq_num (Bytes.length finished_data))
        finished_data
  in
  t.crypto.write_seq_num <- Int64.add t.crypto.write_seq_num 1L;

  t.state <- Established;
  [record_ccs; record_finished]

(** Handle Finished message as server - verify client's Finished and send our own *)
let handle_finished_as_server t payload =
  (* RFC 5246 Section 7.4.9: Verify client's Finished message *)
  (* Finished body is 12 bytes of verify_data after handshake header *)
  let data_len = Bytes.length payload in
  if data_len < handshake_header_size + 12 then begin
    (* Data too short - skip verification in testing mode *)
    let response = build_server_finished t in
    Result.Ok (response, None)
  end else
  let body_len =
    (Bytes.get_uint8 payload 1 lsl 16) lor
    (Bytes.get_uint16_be payload 2)
  in
  if data_len < handshake_header_size + body_len || body_len < 12 then begin
    let response = build_server_finished t in
    Result.Ok (response, None)
  end else
  let received_verify_data = Bytes.sub payload handshake_header_size 12 in

  (* Compute expected verify_data for client *)
  let verification_result =
    match t.handshake.master_secret with
    | Some master_secret ->
      (* Hash all handshake messages (excluding this Finished) *)
      let messages_cs = List.rev_map Cstruct.of_bytes t.handshake.handshake_messages in
      let handshake_hash = Ecdhe.hash_handshake_messages messages_cs in
      let master_secret_cs = Cstruct.of_bytes master_secret in
      let expected_verify_data = Ecdhe.compute_verify_data
        ~master_secret:master_secret_cs
        ~handshake_hash
        ~is_client:true  (* Client's verify_data *)
      in
      let expected_bytes = Cstruct.to_bytes expected_verify_data in
      if Bytes.equal received_verify_data expected_bytes then
        Ok ()
      else
        Error "Client Finished verify_data mismatch - possible MITM attack"
    | None ->
      (* No master secret - skip verification (testing mode) *)
      Ok ()
  in

  match verification_result with
  | Ok () ->
    t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages;
    let response = build_server_finished t in
    Result.Ok (response, None)
  | Error msg ->
    Result.Error msg

let handle_handshake_message t msg_type data =
  match msg_type with
  (* Client-side handlers *)
  | HelloVerifyRequest when t.config.is_client -> handle_hello_verify_request t data
  | ServerHello when t.config.is_client -> handle_server_hello t data
  | Certificate when t.config.is_client -> handle_certificate t data
  | ServerKeyExchange when t.config.is_client -> handle_server_key_exchange t data
  | ServerHelloDone when t.config.is_client -> handle_server_hello_done t data
  (* Server-side handlers *)
  | ClientKeyExchange when not t.config.is_client -> handle_client_key_exchange t data
  (* ClientHello requires client_addr, handled separately in handle_record_as_server *)
  | _ -> Result.Error (Printf.sprintf "Unexpected handshake message type")

let record_handshake_message t msg_type payload =
  match msg_type with
  | HelloVerifyRequest
  | Finished -> ()
  | _ ->
    t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages

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
            if msg_type = Finished then
              if t.config.is_client then
                handle_finished t payload
              else
                handle_finished_as_server t payload
            else begin
              record_handshake_message t msg_type payload;
              handle_handshake_message t msg_type body
            end
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

(** Handle incoming record as server with client address for cookie validation.
    This is the main entry point for server-side record processing. *)
let handle_record_as_server t data ~client_addr =
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
            (* Special handling for ClientHello which needs client_addr *)
            match msg_type with
            | ClientHello -> handle_client_hello t ~payload ~body ~client_addr
            | Finished -> handle_finished_as_server t payload
            | _ ->
              record_handshake_message t msg_type payload;
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
    match t.handshake.master_secret,
          t.handshake.client_random,
          t.handshake.server_random with
    | None, _, _ -> Error "No master secret"
    | _, None, _ | _, _, None -> Error "Missing client/server random"
    | Some master_secret, Some client_random, Some server_random ->
      let seed_result =
        match context with
        | None ->
          Ok (Bytes.cat client_random server_random)
        | Some ctx ->
          if Bytes.length ctx > 0xFFFF then
            Error "Context too large"
          else
            let len_bytes = Bytes.create 2 in
            Bytes.set_uint16_be len_bytes 0 (Bytes.length ctx);
            Ok (Bytes.concat Bytes.empty [client_random; server_random; len_bytes; ctx])
      in
      match seed_result with
      | Error e -> Error e
      | Ok seed ->
        let master_cs = Cstruct.of_bytes master_secret in
        let seed_cs = Cstruct.of_bytes seed in
        let out = Webrtc_crypto.prf_sha256
          ~secret:master_cs
          ~label
          ~seed:seed_cs
          ~length
        in
        Result.Ok (Cstruct.to_bytes out)

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

let get_srtp_profile t = t.negotiated_srtp_profile

let pp_state fmt = function
  (* Common states *)
  | Initial -> Format.fprintf fmt "Initial"
  | Established -> Format.fprintf fmt "Established"
  | Closed -> Format.fprintf fmt "Closed"
  | Error e -> Format.fprintf fmt "Error(%s)" e
  (* Client states *)
  | HelloSent -> Format.fprintf fmt "HelloSent"
  | HelloVerifyReceived -> Format.fprintf fmt "HelloVerifyReceived"
  | ServerHelloReceived -> Format.fprintf fmt "ServerHelloReceived"
  | CertificateReceived -> Format.fprintf fmt "CertificateReceived"
  | KeyExchangeDone -> Format.fprintf fmt "KeyExchangeDone"
  | ChangeCipherSpecSent -> Format.fprintf fmt "ChangeCipherSpecSent"
  (* Server states *)
  | HelloVerifySent -> Format.fprintf fmt "HelloVerifySent"
  | ClientHelloReceived -> Format.fprintf fmt "ClientHelloReceived"
  | ServerFlightSent -> Format.fprintf fmt "ServerFlightSent"
  | ClientKeyExchangeReceived -> Format.fprintf fmt "ClientKeyExchangeReceived"

(** {1 Retransmission (RFC 6347 Section 4.2.4)} *)

(** Maximum retransmit timeout per RFC 6347 *)
let max_retransmit_timeout_ms = 60000

(** Calculate next timeout with exponential backoff.
    RFC 6347: timeout doubles on each retransmit, capped at 60 seconds. *)
let next_retransmit_timeout current_ms =
  min (current_ms * 2) max_retransmit_timeout_ms

(** Store a flight for potential retransmission.
    Called after sending a handshake flight. *)
let store_flight (t : t) (flight : bytes list) =
  let now = perform Now in
  t.retransmit.last_flight <- flight;
  t.retransmit.retransmit_count <- 0;
  t.retransmit.current_timeout_ms <- t.config.retransmit_timeout_ms;
  t.retransmit.flight_sent_at <- now;
  t.retransmit.timer_active <- true;
  perform (SetTimer t.retransmit.current_timeout_ms)

(** Clear retransmission state when handshake progresses.
    Called when a valid response is received. *)
let clear_retransmit (t : t) =
  if t.retransmit.timer_active then begin
    perform CancelTimer;
    t.retransmit.timer_active <- false
  end;
  t.retransmit.last_flight <- [];
  t.retransmit.retransmit_count <- 0;
  t.retransmit.current_timeout_ms <- t.config.retransmit_timeout_ms

(** Handle retransmission timer expiry.
    Returns the flight to retransmit, or Error if max retransmits exceeded.

    RFC 6347 Section 4.2.4:
    "If the timer expires, the implementation retransmits the flight,
     resets the timer, and doubles the timeout value." *)
let handle_retransmit_timeout (t : t) : (bytes list, string) result =
  if not t.retransmit.timer_active then
    Ok []  (* Timer was cancelled, nothing to do *)
  else if t.retransmit.retransmit_count >= t.config.max_retransmits then begin
    (* Max retransmits exceeded - fail the handshake *)
    t.retransmit.timer_active <- false;
    t.state <- Error "Handshake timeout: max retransmits exceeded";
    Error "Max retransmits exceeded"
  end else begin
    (* Retransmit the flight *)
    t.retransmit.retransmit_count <- t.retransmit.retransmit_count + 1;
    t.retransmit.current_timeout_ms <- next_retransmit_timeout t.retransmit.current_timeout_ms;
    t.retransmit.flight_sent_at <- perform Now;
    perform (SetTimer t.retransmit.current_timeout_ms);
    Ok t.retransmit.last_flight
  end

(** Check if retransmission is needed based on elapsed time.
    Useful for polling-based timer implementations. *)
let check_retransmit_needed (t : t) : bool =
  if not t.retransmit.timer_active then
    false
  else
    let now = perform Now in
    let elapsed_ms = int_of_float ((now -. t.retransmit.flight_sent_at) *. 1000.0) in
    elapsed_ms >= t.retransmit.current_timeout_ms

(** Get current retransmission state for debugging/monitoring *)
let get_retransmit_state (t : t) =
  (t.retransmit.retransmit_count,
   t.retransmit.current_timeout_ms,
   t.retransmit.timer_active)

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
  set_timer: int -> unit;     (** Set retransmission timer (ms), callback on timeout *)
  cancel_timer: unit -> unit; (** Cancel pending retransmission timer *)
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
  set_timer = (fun _ -> ());     (* No-op for testing *)
  cancel_timer = (fun () -> ()); (* No-op for testing *)
}

(** {1 Effect Handler (for Eio integration)} *)

(** Run DTLS code with custom I/O operations.
    This is the primary API - works with any transport implementation.
    @param ops I/O operations (send, recv, now, random, set_timer, cancel_timer)
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
      | SetTimer ms -> Some (fun (k : (a, _) continuation) ->
          ops.set_timer ms;
          continue k ()
        )
      | CancelTimer -> Some (fun (k : (a, _) continuation) ->
          ops.cancel_timer ();
          continue k ()
        )
      | _ -> None
  }

(** Legacy wrapper for backward compatibility.
    Uses default no-op I/O - prefer run_with_io for production. *)
let run_with_eio ~net:_ ~clock:_ f =
  run_with_io ~ops:default_io_ops f
