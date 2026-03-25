(** DTLS Application-Level Crypto — AES-GCM encrypt/decrypt and key export

    Provides the public encrypt/decrypt API for established DTLS connections
    and RFC 5705 keying material export (used for DTLS-SRTP).

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

(** GCM authentication tag size in bytes. *)
val gcm_tag_size : int

(** GCM explicit nonce size in bytes. *)
val gcm_explicit_nonce_size : int

(** Build 12-byte GCM nonce from 4-byte implicit IV + 8-byte sequence number. *)
val build_gcm_nonce : implicit_iv:bytes -> seq_num:int64 -> bytes

(** Encrypt application data for sending over an established DTLS connection.
    Returns a complete DTLS record (header + encrypted payload). *)
val encrypt : Dtls_types.t -> bytes -> (bytes, string) result

(** Decrypt a received DTLS ApplicationData record.
    Input is a complete DTLS record (header + encrypted payload). *)
val decrypt : Dtls_types.t -> bytes -> (bytes, string) result

(** Export keying material per RFC 5705.
    Used for DTLS-SRTP key derivation. *)
val export_keying_material
  :  Dtls_types.t
  -> label:string
  -> context:bytes option
  -> length:int
  -> (bytes, string) result
