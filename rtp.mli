(** RTP (RFC 3550) - Minimal header encode/decode for audio media.

    This module provides a small, safe RTP parser/encoder for phase 2A.
    It handles CSRC and header extensions, but leaves payload handling to the caller.
*)

(** RTP header extension *)
type extension = {
  profile : int;  (** 16-bit profile-specific ID *)
  data : bytes;   (** Extension data, length must be multiple of 4 bytes *)
}

(** RTP header *)
type header = {
  version : int;        (** 2-bit version, must be 2 *)
  padding : bool;       (** Padding bit *)
  extension : extension option;  (** Header extension *)
  marker : bool;        (** Marker bit *)
  payload_type : int;   (** 7-bit payload type *)
  sequence : int;       (** 16-bit sequence number *)
  timestamp : int32;    (** 32-bit timestamp *)
  ssrc : int32;         (** 32-bit SSRC *)
  csrc : int32 list;    (** CSRC list (0-15 items) *)
  padding_len : int;    (** Padding length in bytes (0 if none) *)
}

(** RTP packet *)
type packet = {
  header : header;
  payload : bytes;
}

(** Create a default RTP header (version=2). *)
val default_header :
  ?payload_type:int ->
  ?sequence:int ->
  ?timestamp:int32 ->
  ?ssrc:int32 ->
  unit ->
  header

(** Encode an RTP header and payload into bytes. *)
val encode : header -> payload:bytes -> (bytes, string) result

(** Decode an RTP packet from bytes. *)
val decode : bytes -> (packet, string) result

(** Decode only the RTP header without extracting payload.
    Returns (header, header_length) where header_length is the offset to payload.
    Useful for SRTP-GCM where AAD needs exact header bytes. *)
val decode_header : bytes -> (header * int, string) result

(** Increment a 16-bit sequence number with wraparound. *)
val next_sequence : int -> int
