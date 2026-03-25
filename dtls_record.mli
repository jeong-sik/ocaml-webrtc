(** DTLS Record Layer — RFC 6347 record header and AES-GCM record encryption

    Handles DTLS record framing (13-byte header) and per-record
    AES-GCM encryption/decryption as specified in RFC 5288 + RFC 6347.

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

(** DTLS record header size in bytes (content_type + version + epoch + seq + length). *)
val record_header_size : int

(** Build a 13-byte DTLS record header. *)
val build_record_header
  :  Dtls_types.content_type
  -> int
  -> int64
  -> int
  -> bytes

(** Build Additional Authenticated Data for AES-GCM.
    AAD = epoch || seq_num || content_type || version || plaintext_length. *)
val build_aad
  :  epoch:int
  -> seq_num:int64
  -> content_type:Dtls_types.content_type
  -> length:int
  -> bytes

(** Encrypt a DTLS record payload using AES-GCM (RFC 5288).
    Returns explicit_nonce (8 bytes) || ciphertext || tag (16 bytes). *)
val encrypt_record
  :  t:Dtls_types.t
  -> content_type:Dtls_types.content_type
  -> epoch:int
  -> seq_num:int64
  -> plaintext:bytes
  -> (bytes, string) result

(** Decrypt a DTLS record payload using AES-GCM (RFC 5288).
    Input is explicit_nonce (8 bytes) || ciphertext || tag (16 bytes). *)
val decrypt_record
  :  t:Dtls_types.t
  -> content_type:Dtls_types.content_type
  -> epoch:int
  -> seq_num:int64
  -> ciphertext_with_nonce:bytes
  -> (bytes, string) result

(** Parse a DTLS record header from raw bytes.
    Returns (content_type, epoch, seq_num, payload_length). *)
val parse_record_header
  :  bytes
  -> (Dtls_types.content_type * int * int64 * int, string) result
