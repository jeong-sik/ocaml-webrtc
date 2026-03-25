(** RFC 6347 DTLS - Datagram Transport Layer Security

    Pure OCaml 5.x implementation using Effect Handlers.

    This module is the public facade. Protocol logic is split across:
    - Dtls_types: shared types and state definitions
    - Dtls_codec: wire-format encoding/decoding
    - Dtls_record: record-layer framing and per-record AES-GCM
    - Dtls_handshake_client: client-side handshake
    - Dtls_handshake_server: server-side handshake and cookie exchange
    - Dtls_crypto: application-level encrypt/decrypt and key export
    - Dtls_retransmit: flight retransmission with exponential backoff
    - Dtls_io: effect handler bridging DTLS effects to concrete I/O

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

(** {1 Types and Effects -- re-exported from Dtls_types for backward compatibility} *)

include Dtls_types

(** {1 Constants -- delegated to Dtls_codec} *)

let content_type_to_int = Dtls_codec.content_type_to_int
let int_to_content_type = Dtls_codec.int_to_content_type
let handshake_type_to_int = Dtls_codec.handshake_type_to_int
let int_to_handshake_type = Dtls_codec.int_to_handshake_type
let cipher_suite_to_int = Dtls_codec.cipher_suite_to_int
let int_to_cipher_suite = Dtls_codec.int_to_cipher_suite
let alert_level_to_int = Dtls_codec.alert_level_to_int
let alert_description_to_int = Dtls_codec.alert_description_to_int
let dtls_version_major = Dtls_codec.dtls_version_major
let dtls_version_minor = Dtls_codec.dtls_version_minor
let use_srtp_extension_type = Dtls_codec.use_srtp_extension_type
let srtp_profile_to_id = Dtls_codec.srtp_profile_to_id
let srtp_profile_of_id = Dtls_codec.srtp_profile_of_id

(** {1 Record Layer -- delegated to Dtls_record} *)

let record_header_size = Dtls_record.record_header_size
let build_record_header = Dtls_record.build_record_header
let build_aad = Dtls_record.build_aad
let encrypt_record = Dtls_record.encrypt_record
let decrypt_record = Dtls_record.decrypt_record
let parse_record_header = Dtls_record.parse_record_header

(** {1 Handshake Framing -- delegated to Dtls_codec} *)

let handshake_header_size = Dtls_codec.handshake_header_size
let build_handshake_header = Dtls_codec.build_handshake_header

(** {1 Default Configuration} *)

let default_client_config =
  { is_client = true
  ; certificate = None
  ; private_key = None
  ; verify_peer = true
  ; cipher_suites =
      [ TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256; TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ]
  ; srtp_profiles = []
  ; mtu = 1400
  ; retransmit_timeout_ms = 1000
  ; max_retransmits = 5
  }
;;

let default_server_config =
  { is_client = false
  ; certificate = None
  ; private_key = None
  ; verify_peer = false
  ; cipher_suites =
      [ TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256; TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 ]
  ; srtp_profiles = []
  ; mtu = 1400
  ; retransmit_timeout_ms = 1000
  ; max_retransmits = 5
  }
;;

(** {1 Context Creation} *)

let create config =
  { config
  ; state = Initial
  ; negotiated_cipher = None
  ; negotiated_srtp_profile = None
  ; peer_certificate = None
  ; epoch = 0
  ; crypto =
      { client_write_key = None
      ; server_write_key = None
      ; client_write_iv = None
      ; server_write_iv = None
      ; read_seq_num = 0L
      ; write_seq_num = 0L
      }
  ; handshake =
      { client_random = None
      ; server_random = None
      ; premaster_secret = None
      ; master_secret = None
      ; handshake_messages = []
      ; cookie = None
      ; message_seq = 0
      ; next_receive_seq = 0
      ; pending_fragments = []
      ; (* ECDHE fields *)
        ecdhe_keypair = None
      ; server_public_key = None
      ; selected_curve = None
      }
  ; retransmit =
      { last_flight = []
      ; retransmit_count = 0
      ; current_timeout_ms = config.retransmit_timeout_ms
      ; flight_sent_at = 0.0
      ; timer_active = false
      }
  }
;;

(** {1 Client Handshake -- delegated to Dtls_handshake_client} *)

let build_client_hello = Dtls_handshake_client.build_client_hello
let start_handshake = Dtls_handshake_client.start_handshake

(** {1 Server Handshake -- delegated to Dtls_handshake_server} *)

let generate_cookie = Dtls_handshake_server.generate_cookie
let verify_cookie = Dtls_handshake_server.verify_cookie

(** {1 Handshake Message Dispatch} *)

let handle_handshake_message t msg_type data =
  match msg_type with
  (* Client-side handlers *)
  | HelloVerifyRequest when t.config.is_client ->
    Dtls_handshake_client.handle_hello_verify_request t data
  | ServerHello when t.config.is_client ->
    Dtls_handshake_client.handle_server_hello t data
  | Certificate when t.config.is_client ->
    Dtls_handshake_client.handle_certificate t data
  | ServerKeyExchange when t.config.is_client ->
    Dtls_handshake_client.handle_server_key_exchange t data
  | ServerHelloDone when t.config.is_client ->
    Dtls_handshake_client.handle_server_hello_done t data
  (* Server-side handlers *)
  | ClientKeyExchange when not t.config.is_client ->
    Dtls_handshake_server.handle_client_key_exchange t data
  (* ClientHello requires client_addr, handled separately in handle_record_as_server *)
  | _ -> Result.Error (Printf.sprintf "Unexpected handshake message type")
;;

let record_handshake_message t msg_type payload =
  match msg_type with
  | HelloVerifyRequest | Finished -> ()
  | _ -> t.handshake.handshake_messages <- payload :: t.handshake.handshake_messages
;;

(** {1 Record Processing} *)

let handle_record t data =
  match parse_record_header data with
  | Result.Error e -> Result.Error e
  | Result.Ok (content_type, epoch, seq_num, length) ->
    let raw_payload = Bytes.sub data record_header_size length in
    (* Decrypt payload if epoch > 0 (after ChangeCipherSpec) *)
    let payload_result =
      if epoch > 0 && content_type <> ChangeCipherSpec
      then
        decrypt_record ~t ~content_type ~epoch ~seq_num ~ciphertext_with_nonce:raw_payload
      else Ok raw_payload
    in
    (match payload_result with
     | Error e -> Result.Error (Printf.sprintf "Decryption failed: %s" e)
     | Ok payload ->
       (match content_type with
        | Handshake ->
          if Bytes.length payload < handshake_header_size
          then Result.Error "Handshake message too short"
          else (
            let msg_type_int = Bytes.get_uint8 payload 0 in
            match int_to_handshake_type msg_type_int with
            | None -> Result.Error "Unknown handshake type"
            | Some msg_type ->
              let body_len =
                (Bytes.get_uint8 payload 1 lsl 16) lor Bytes.get_uint16_be payload 2
              in
              let body = Bytes.sub payload handshake_header_size body_len in
              if msg_type = Finished
              then
                if t.config.is_client
                then Dtls_handshake_client.handle_finished t payload
                else Dtls_handshake_server.handle_finished_as_server t payload
              else (
                record_handshake_message t msg_type payload;
                handle_handshake_message t msg_type body))
        | ChangeCipherSpec ->
          t.epoch <- t.epoch + 1;
          t.crypto.read_seq_num <- 0L;
          Result.Ok ([], None)
        | Alert ->
          if Bytes.length payload >= 2
          then (
            let level = Bytes.get_uint8 payload 0 in
            let desc = Bytes.get_uint8 payload 1 in
            if level = 2
            then (
              t.state <- Closed;
              Result.Error (Printf.sprintf "Fatal alert: %d" desc))
            else Result.Ok ([], None))
          else Result.Error "Alert too short"
        | ApplicationData ->
          if t.state = Established
          then Result.Ok ([], Some payload)
          else Result.Error "Application data before handshake complete"))
;;

(** Handle incoming record as server with client address for cookie validation.
    This is the main entry point for server-side record processing. *)
let handle_record_as_server t data ~client_addr =
  match parse_record_header data with
  | Result.Error e -> Result.Error e
  | Result.Ok (content_type, epoch, seq_num, length) ->
    let raw_payload = Bytes.sub data record_header_size length in
    (* Decrypt payload if epoch > 0 (after ChangeCipherSpec) *)
    let payload_result =
      if epoch > 0 && content_type <> ChangeCipherSpec
      then
        decrypt_record ~t ~content_type ~epoch ~seq_num ~ciphertext_with_nonce:raw_payload
      else Ok raw_payload
    in
    (match payload_result with
     | Error e -> Result.Error (Printf.sprintf "Decryption failed: %s" e)
     | Ok payload ->
       (match content_type with
        | Handshake ->
          if Bytes.length payload < handshake_header_size
          then Result.Error "Handshake message too short"
          else (
            let msg_type_int = Bytes.get_uint8 payload 0 in
            match int_to_handshake_type msg_type_int with
            | None -> Result.Error "Unknown handshake type"
            | Some msg_type ->
              let body_len =
                (Bytes.get_uint8 payload 1 lsl 16) lor Bytes.get_uint16_be payload 2
              in
              let body = Bytes.sub payload handshake_header_size body_len in
              (* Special handling for ClientHello which needs client_addr *)
              (match msg_type with
               | ClientHello ->
                 Dtls_handshake_server.handle_client_hello t ~payload ~body ~client_addr
               | Finished -> Dtls_handshake_server.handle_finished_as_server t payload
               | _ ->
                 record_handshake_message t msg_type payload;
                 handle_handshake_message t msg_type body))
        | ChangeCipherSpec ->
          t.epoch <- t.epoch + 1;
          t.crypto.read_seq_num <- 0L;
          Result.Ok ([], None)
        | Alert ->
          if Bytes.length payload >= 2
          then (
            let level = Bytes.get_uint8 payload 0 in
            let desc = Bytes.get_uint8 payload 1 in
            if level = 2
            then (
              t.state <- Closed;
              Result.Error (Printf.sprintf "Fatal alert: %d" desc))
            else Result.Ok ([], None))
          else Result.Error "Alert too short"
        | ApplicationData ->
          if t.state = Established
          then Result.Ok ([], Some payload)
          else Result.Error "Application data before handshake complete"))
;;

(** {1 State Queries} *)

let is_established t = t.state = Established
let get_state t = t.state

(** {1 Application Crypto -- delegated to Dtls_crypto} *)

let encrypt = Dtls_crypto.encrypt
let decrypt = Dtls_crypto.decrypt
let export_keying_material = Dtls_crypto.export_keying_material

(** {1 Utilities} *)

let close t =
  if t.state = Established || t.state = ChangeCipherSpecSent
  then (
    (* Build close_notify alert *)
    let alert = Bytes.create 2 in
    Bytes.set_uint8 alert 0 (alert_level_to_int Warning);
    Bytes.set_uint8 alert 1 (alert_description_to_int CloseNotify);
    let record =
      Bytes.cat (build_record_header Alert t.epoch t.crypto.write_seq_num 2) alert
    in
    t.state <- Closed;
    Some record)
  else (
    t.state <- Closed;
    None)
;;

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
;;

(** {1 Retransmission -- delegated to Dtls_retransmit} *)

let store_flight = Dtls_retransmit.store_flight
let clear_retransmit = Dtls_retransmit.clear_retransmit
let handle_retransmit_timeout = Dtls_retransmit.handle_retransmit_timeout
let check_retransmit_needed = Dtls_retransmit.check_retransmit_needed
let get_retransmit_state = Dtls_retransmit.get_retransmit_state

(** {1 I/O Operations -- delegated to Dtls_io} *)

let default_io_ops = Dtls_io.default_io_ops
let run_with_io = Dtls_io.run_with_io
let run_with_eio = Dtls_io.run_with_eio
