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
