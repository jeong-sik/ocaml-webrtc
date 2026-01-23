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

(** SDES item type (RFC 3550). *)
type sdes_item_type =
  | CNAME
  | NAME
  | EMAIL
  | PHONE
  | LOC
  | TOOL
  | NOTE
  | PRIV
  | Unknown_item of int

(** SDES item. *)
type sdes_item = {
  item_type : sdes_item_type;
  value : string;
}

(** SDES chunk. *)
type sdes_chunk = {
  ssrc : int32;
  items : sdes_item list;
}

(** BYE packet (RFC 3550 Section 6.6). *)
type bye_packet = {
  ssrcs : int32 list;      (** SSRC/CSRC list (1-31 items) *)
  reason : string option;  (** Optional reason for leaving *)
}

(** APP packet (RFC 3550 Section 6.7). *)
type app_packet = {
  subtype : int;           (** 5-bit subtype *)
  ssrc : int32;            (** SSRC/CSRC *)
  name : string;           (** 4-character ASCII name *)
  data : bytes;            (** Application-dependent data *)
}

(** RTCP packet *)
type packet =
  | Sender_report of sender_report
  | Receiver_report of receiver_report
  | Source_description of sdes_chunk list
  | Bye of bye_packet
  | App of app_packet
  | Unknown_packet of packet_type * bytes

(** Encode a single RTCP packet. *)
val encode : packet -> bytes

(** Decode a single RTCP packet from bytes. *)
val decode : bytes -> (packet, string) result

(** Decode a compound RTCP packet into a list. *)
val decode_compound : bytes -> (packet list, string) result

(** Helper: Create SDES packet with a single CNAME item (RFC 3550 Section 6.5). *)
val make_sdes_cname : ssrc:int32 -> cname:string -> packet

(** Helper: Create BYE packet (RFC 3550 Section 6.6). *)
val make_bye : ?reason:string -> int32 list -> packet

(** Calculate RTCP transmission interval (RFC 3550 Section 6.3).
    @param members Total number of session members
    @param senders Number of senders
    @param rtcp_bw RTCP bandwidth (bytes/sec)
    @param we_sent True if we sent data in current interval
    @param avg_rtcp_size Average size of RTCP packets
    @param initial True for initial delay (halved)
    @return Computed interval in seconds (minimum 5s, or 2.5s if initial) *)
val calculate_rtcp_interval :
  members:int -> senders:int -> rtcp_bw:float ->
  we_sent:bool -> avg_rtcp_size:float -> initial:bool -> float
