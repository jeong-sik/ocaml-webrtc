(** SRTP/SRTCP (RFC 3711) - Minimal API for protect/unprotect.

    Phase 2A focuses on AES-CTR + HMAC-SHA1-80 profile.
*)

(** SRTP protection profile *)
type profile =
  | AES_128_CM_HMAC_SHA1_80

(** SRTP key material *)
type keying = {
  master_key : bytes;   (** 16 bytes *)
  master_salt : bytes;  (** 14 bytes *)
}

(** SRTP context *)
type context

(** SRTP rollover counter *)
type roc = int32

(** Create an SRTP context. *)
val create :
  profile:profile ->
  keying:keying ->
  ssrc:int32 ->
  context

(** Protect an RTP packet (add auth tag, encrypt payload). *)
val protect_rtp : context -> rtp:bytes -> (bytes, string) result

(** Unprotect an RTP packet (verify auth tag, decrypt payload). *)
val unprotect_rtp : context -> rtp:bytes -> (bytes, string) result

(** Protect an RTCP packet (add SRTCP index + auth tag). *)
val protect_rtcp : context -> rtcp:bytes -> (bytes, string) result

(** Unprotect an RTCP packet (verify auth tag, remove SRTCP index). *)
val unprotect_rtcp : context -> rtcp:bytes -> (bytes, string) result
