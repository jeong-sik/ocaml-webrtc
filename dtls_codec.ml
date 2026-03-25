(** DTLS Protocol Codec — Type conversion tables for DTLS 1.2

    Pure functions mapping DTLS protocol types to/from wire integers.
    Extracted from dtls.ml for modularity.

    @author Second Brain
    @since ocaml-webrtc 0.2.2
*)

open Dtls_types

(** {1 Content Type Codec} *)

let content_type_to_int = function
  | ChangeCipherSpec -> 20
  | Alert -> 21
  | Handshake -> 22
  | ApplicationData -> 23
;;

let int_to_content_type = function
  | 20 -> Some ChangeCipherSpec
  | 21 -> Some Alert
  | 22 -> Some Handshake
  | 23 -> Some ApplicationData
  | _ -> None
;;

(** {1 Handshake Type Codec} *)

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
;;

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
;;

(** {1 Cipher Suite Codec} *)

let cipher_suite_to_int = function
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 -> 0xC02B
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> 0xC02F
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 -> 0xC02C
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> 0xC030
;;

let int_to_cipher_suite = function
  | 0xC02B -> Some TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | 0xC02F -> Some TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | 0xC02C -> Some TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | 0xC030 -> Some TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  | _ -> None
;;

(** {1 Alert Codec} *)

let alert_level_to_int = function
  | Warning -> 1
  | Fatal -> 2
;;

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
;;

(** {1 DTLS Version Constants} *)

let dtls_version_major = 254
let dtls_version_minor = 253

(** {1 SRTP Profile Codec (RFC 5764)} *)

let use_srtp_extension_type = 0x000e

let srtp_profile_to_id = function
  | Srtp.SRTP_AES128_CM_HMAC_SHA1_80 -> 0x0001
  | Srtp.SRTP_AES128_CM_HMAC_SHA1_32 -> 0x0002
  | Srtp.SRTP_NULL_HMAC_SHA1_80 -> 0x0005
  | Srtp.SRTP_NULL_HMAC_SHA1_32 -> 0x0006
  | Srtp.SRTP_AEAD_AES_128_GCM -> 0x0007
  | Srtp.SRTP_AEAD_AES_256_GCM -> 0x0008
;;

let srtp_profile_of_id = function
  | 0x0001 -> Some Srtp.SRTP_AES128_CM_HMAC_SHA1_80
  | 0x0002 -> Some Srtp.SRTP_AES128_CM_HMAC_SHA1_32
  | 0x0005 -> Some Srtp.SRTP_NULL_HMAC_SHA1_80
  | 0x0006 -> Some Srtp.SRTP_NULL_HMAC_SHA1_32
  | 0x0007 -> Some Srtp.SRTP_AEAD_AES_128_GCM
  | 0x0008 -> Some Srtp.SRTP_AEAD_AES_256_GCM
  | _ -> None
;;

(** {1 Handshake Message Framing} *)

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
;;

(** {1 SRTP Extension Codec} *)

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
    List.iter
      (fun profile_id ->
         Bytes.set_uint16_be ext !pos profile_id;
         pos := !pos + 2)
      profile_ids;
    Bytes.set_uint8 ext !pos 0;
    (* MKI length = 0 *)
    ext
;;

let build_extensions profiles =
  let use_srtp = build_use_srtp_extension profiles in
  if Bytes.length use_srtp = 0 then Bytes.empty else use_srtp
;;

let parse_use_srtp_extension data =
  if Bytes.length data < 3
  then []
  else (
    let profile_len = Bytes.get_uint16_be data 0 in
    if profile_len mod 2 <> 0 || Bytes.length data < 2 + profile_len + 1
    then []
    else (
      let profiles = ref [] in
      let pos = ref 2 in
      while !pos < 2 + profile_len do
        let id = Bytes.get_uint16_be data !pos in
        (match srtp_profile_of_id id with
         | Some profile -> profiles := profile :: !profiles
         | None -> ());
        pos := !pos + 2
      done;
      List.rev !profiles))
;;

let parse_extensions data =
  let len = Bytes.length data in
  let rec loop off profiles =
    if off = len
    then profiles
    else if off + 4 > len
    then profiles
    else (
      let ext_type = Bytes.get_uint16_be data off in
      let ext_len = Bytes.get_uint16_be data (off + 2) in
      let next = off + 4 + ext_len in
      if next > len
      then profiles
      else (
        let ext_data = Bytes.sub data (off + 4) ext_len in
        let profiles =
          if ext_type = use_srtp_extension_type
          then parse_use_srtp_extension ext_data
          else profiles
        in
        loop next profiles))
  in
  loop 0 []
;;

let select_srtp_profile local_profiles remote_profiles =
  if local_profiles = []
  then None
  else List.find_opt (fun profile -> List.mem profile remote_profiles) local_profiles
;;
