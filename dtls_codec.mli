(** DTLS Protocol Codec — Type conversion tables for DTLS 1.2

    Pure functions mapping DTLS protocol types to/from wire integers.
    Extracted from dtls.ml for modularity.

    @author Second Brain
    @since ocaml-webrtc 0.2.2
*)

val content_type_to_int : Dtls_types.content_type -> int
val int_to_content_type : int -> Dtls_types.content_type option
val handshake_type_to_int : Dtls_types.handshake_type -> int
val int_to_handshake_type : int -> Dtls_types.handshake_type option
val cipher_suite_to_int : Dtls_types.cipher_suite -> int
val int_to_cipher_suite : int -> Dtls_types.cipher_suite option
val alert_level_to_int : Dtls_types.alert_level -> int
val alert_description_to_int : Dtls_types.alert_description -> int
val dtls_version_major : int
val dtls_version_minor : int
val use_srtp_extension_type : int
val srtp_profile_to_id : Srtp.profile -> int
val srtp_profile_of_id : int -> Srtp.profile option

(** {1 Handshake Message Framing} *)

val handshake_header_size : int

val build_handshake_header
  :  Dtls_types.handshake_type
  -> int
  -> int
  -> int
  -> int
  -> bytes

(** {1 SRTP Extension Codec} *)

val build_use_srtp_extension : Srtp.profile list -> bytes
val build_extensions : Srtp.profile list -> bytes
val parse_use_srtp_extension : bytes -> Srtp.profile list
val parse_extensions : bytes -> Srtp.profile list
val select_srtp_profile : Srtp.profile list -> Srtp.profile list -> Srtp.profile option
