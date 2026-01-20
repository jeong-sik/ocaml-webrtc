(** SRTP (RFC 3711) - AES-CM + HMAC-SHA1 core primitives. *)

(** SRTP protection profiles (RFC 5764) *)
type profile =
  | SRTP_AES128_CM_HMAC_SHA1_80
  | SRTP_AES128_CM_HMAC_SHA1_32
  | SRTP_NULL_HMAC_SHA1_80
  | SRTP_NULL_HMAC_SHA1_32

(** Master key material (from DTLS-SRTP exporter). *)
type master = {
  key : bytes;   (** Master key, 16/24/32 bytes for AES-CM *)
  salt : bytes;  (** Master salt, 14 bytes (112 bits) *)
}

(** Derived session keys for SRTP and SRTCP. *)
type session_keys = {
  srtp_encryption_key : bytes;
  srtp_auth_key : bytes;
  srtp_salt_key : bytes;
  srtcp_encryption_key : bytes;
  srtcp_auth_key : bytes;
  srtcp_salt_key : bytes;
}

(** Profile parameters (lengths in bytes). *)
type params = {
  cipher_key_len : int;
  cipher_salt_len : int;
  auth_key_len : int;
  srtp_auth_tag_len : int;
  srtcp_auth_tag_len : int;
}

(** Get parameter lengths for a profile. *)
val params_of_profile : profile -> params

(** Derive a single session key using the AES-CM PRF (RFC 3711 §4.3). *)
val derive_key :
  master:master ->
  label:int ->
  key_derivation_rate:int64 ->
  index:int64 ->
  out_len:int ->
  (bytes, string) result

(** Derive all SRTP/SRTCP session keys. *)
val derive_session_keys :
  profile:profile ->
  master:master ->
  key_derivation_rate:int64 ->
  index:int64 ->
  (session_keys, string) result

(** Build SRTP AES-CM IV (RFC 3711 §4.1.1). *)
val srtp_iv :
  salt:bytes ->
  ssrc:int32 ->
  index:int64 ->
  (bytes, string) result

(** Encrypt/decrypt payload using AES-CM (RFC 3711 §4.1.1). *)
val aes_cm_crypt :
  key:bytes ->
  iv:bytes ->
  payload:bytes ->
  (bytes, string) result

(** Compute SRTP authentication tag (RFC 3711 §4.2.1).
    [packet] should be the RTP header + encrypted payload. *)
val srtp_auth_tag :
  auth_key:bytes ->
  packet:bytes ->
  roc:int32 ->
  tag_len:int ->
  bytes

(** Compute SRTCP authentication tag (RFC 3711 §4.2.1).
    [packet] should include the SRTCP index field (with E bit). *)
val srtcp_auth_tag :
  auth_key:bytes ->
  packet:bytes ->
  tag_len:int ->
  bytes

(** Protect an RTP packet (SRTP).
    [packet] is the RTP header + payload. *)
val protect_rtp :
  profile:profile ->
  keys:session_keys ->
  roc:int32 ->
  packet:bytes ->
  (bytes, string) result

(** Unprotect an SRTP packet.
    Returns the decrypted RTP packet (header + payload). *)
val unprotect_rtp :
  profile:profile ->
  keys:session_keys ->
  roc:int32 ->
  packet:bytes ->
  (bytes, string) result

(** Protect an RTCP packet (SRTCP).
    [index] is the 31-bit SRTCP index. *)
val protect_rtcp :
  profile:profile ->
  keys:session_keys ->
  index:int32 ->
  encrypt:bool ->
  packet:bytes ->
  (bytes, string) result

(** Unprotect an SRTCP packet.
    Returns decrypted RTCP packet and SRTCP index. *)
val unprotect_rtcp :
  profile:profile ->
  keys:session_keys ->
  packet:bytes ->
  (bytes * int32, string) result
