(** Minimal SRTP/SRTCP pipeline for a single SSRC. *)

type t

val create
  :  profile:Srtp.profile
  -> local_keys:Srtp.session_keys
  -> remote_keys:Srtp.session_keys
  -> ssrc:int32
  -> payload_type:int
  -> t

val protect_rtp
  :  t
  -> ?marker:bool
  -> timestamp:int32
  -> payload:bytes
  -> unit
  -> (bytes, string) result

val unprotect_rtp : t -> packet:bytes -> (Rtp.packet, string) result

val protect_rtcp
  :  t
  -> ?encrypt:bool
  -> packet:Rtcp.packet
  -> unit
  -> (bytes, string) result

val unprotect_rtcp : t -> packet:bytes -> (Rtcp.packet * int32, string) result
