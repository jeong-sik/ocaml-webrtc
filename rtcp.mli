(** RTCP (RFC 3550) - Minimal SR/RR encoding and decoding. *)

(** RTCP packet types *)
type packet_type =
  | SR
  | RR
  | SDES
  | BYE
  | APP
  | RTPFB
  | PSFB
  | XR
  | Unknown of int

(** RTCP report block *)
type report_block = {
  ssrc : int32;
  fraction_lost : int;      (** 8-bit unsigned *)
  cumulative_lost : int32;  (** 24-bit signed *)
  highest_seq : int32;
  jitter : int32;
  last_sr : int32;
  dlsr : int32;
}

(** RTCP sender info *)
type sender_info = {
  ntp_sec : int32;
  ntp_frac : int32;
  rtp_timestamp : int32;
  packet_count : int32;
  octet_count : int32;
}

(** Sender Report *)
type sender_report = {
  ssrc : int32;
  sender_info : sender_info;
  report_blocks : report_block list;
}

(** Receiver Report *)
type receiver_report = {
  ssrc : int32;
  report_blocks : report_block list;
}

(** RTCP packet *)
type packet =
  | Sender_report of sender_report
  | Receiver_report of receiver_report
  | Unknown_packet of packet_type * bytes

(** Encode a single RTCP packet. *)
val encode : packet -> bytes

(** Decode a single RTCP packet from bytes. *)
val decode : bytes -> (packet, string) result

(** Decode a compound RTCP packet into a list. *)
val decode_compound : bytes -> (packet list, string) result
