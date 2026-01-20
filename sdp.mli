(** RFC 4566 SDP - Session Description Protocol

    Pure OCaml implementation of SDP for WebRTC.

    SDP is used to describe multimedia sessions for the purpose
    of session announcement and session invitation (Offer/Answer).

    Implements:
    - RFC 4566: SDP (core)
    - RFC 8866: SDP (updated, 2021)
    - RFC 5245: ICE attributes
    - RFC 8839: ICE SDP (updated)
    - RFC 8841: SCTP SDP
    - RFC 8832: DataChannel SDP

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

(** {1 Types} *)

(** Network type *)
type net_type = IN  (** Internet *)

(** Address type *)
type addr_type = IP4 | IP6

(** Media type *)
type media_type =
  | Audio
  | Video
  | Application  (** DataChannel *)
  | Text
  | Message

(** Transport protocol *)
type protocol =
  | UDP
  | RTP_AVP
  | RTP_SAVP
  | RTP_SAVPF
  | UDP_TLS_RTP_SAVPF
  | DTLS_SCTP       (** WebRTC DataChannel *)
  | UDP_DTLS_SCTP   (** WebRTC DataChannel (updated) *)

(** Connection data (c=) *)
type connection = {
  net_type : net_type;
  addr_type : addr_type;
  address : string;
  ttl : int option;
  num_addresses : int option;
}

(** Origin (o=) *)
type origin = {
  username : string;
  sess_id : string;
  sess_version : int64;
  net_type : net_type;
  addr_type : addr_type;
  unicast_address : string;
}

(** Bandwidth (b=) *)
type bandwidth = {
  bwtype : string;  (** CT, AS, TIAS, etc. *)
  bandwidth : int;  (** kbps *)
}

(** Timing (t=) *)
type timing = {
  start_time : int64;
  stop_time : int64;
}

(** ICE candidate attribute *)
type ice_candidate = {
  foundation : string;
  component_id : int;
  transport : string;
  priority : int64;
  address : string;
  port : int;
  cand_type : string;  (** host, srflx, prflx, relay *)
  rel_addr : string option;
  rel_port : int option;
  extensions : (string * string) list;
}

(** DTLS fingerprint *)
type fingerprint = {
  hash_func : string;  (** sha-256, sha-384, etc. *)
  fingerprint : string;
}

(** RTP map (a=rtpmap) *)
type rtpmap = {
  payload_type : int;
  encoding_name : string;
  clock_rate : int;
  encoding_params : string option;
}

(** Format parameters (a=fmtp) *)
type fmtp = {
  format : int;
  parameters : string;
}

(** SCTP map for DataChannel (a=sctpmap or a=sctp-port) *)
type sctpmap = {
  port : int;
  protocol : string;  (** webrtc-datachannel *)
  streams : int option;
}

(** Media description (m=) *)
type media = {
  media_type : media_type;
  port : int;
  num_ports : int option;
  protocol : protocol;
  formats : string list;  (** payload types or formats *)

  (* Attributes *)
  connection : connection option;
  bandwidths : bandwidth list;
  rtpmaps : rtpmap list;
  fmtps : fmtp list;
  ice_ufrag : string option;
  ice_pwd : string option;
  ice_options : string list;
  ice_candidates : ice_candidate list;
  fingerprint : fingerprint option;
  setup : string option;  (** actpass, active, passive *)
  mid : string option;
  sctpmap : sctpmap option;
  max_message_size : int option;
  direction : string option;  (** sendrecv, sendonly, recvonly, inactive *)
  other_attrs : (string * string option) list;
}

(** Session description *)
type session = {
  version : int;              (** v= (always 0) *)
  origin : origin;            (** o= *)
  session_name : string;      (** s= *)
  session_info : string option;  (** i= *)
  uri : string option;        (** u= *)
  emails : string list;       (** e= *)
  phones : string list;       (** p= *)
  connection : connection option;  (** c= *)
  bandwidths : bandwidth list;     (** b= *)
  timings : timing list;      (** t= *)
  ice_lite : bool;
  ice_ufrag : string option;
  ice_pwd : string option;
  ice_options : string list;
  fingerprint : fingerprint option;
  groups : (string * string list) list;  (** a=group *)
  msid_semantic : (string * string list) option;
  media : media list;         (** m= sections *)
  other_attrs : (string * string option) list;
}

(** {1 Parsing} *)

(** Parse SDP string to session description *)
val parse : string -> (session, string) result

(** Parse single media section *)
val parse_media : string -> (media, string) result

(** Parse ICE candidate line *)
val parse_candidate : string -> (ice_candidate, string) result

(** {1 Generation} *)

(** Generate SDP string from session description *)
val to_string : session -> string

(** Generate media section string *)
val media_to_string : media -> string

(** Generate ICE candidate attribute line *)
val candidate_to_string : ice_candidate -> string

(** Convert ICE candidate to SDP candidate (relay/srflx/host). *)
val ice_candidate_of_ice : Ice.candidate -> ice_candidate

(** Convert SDP candidate to ICE candidate. *)
val ice_candidate_to_ice : ice_candidate -> (Ice.candidate, string) result

(** {1 Offer/Answer Helpers} *)

(** Create basic offer for DataChannel *)
val create_datachannel_offer :
  ice_ufrag:string ->
  ice_pwd:string ->
  fingerprint:fingerprint ->
  sctp_port:int ->
  session

(** Create answer from offer *)
val create_answer :
  offer:session ->
  ice_ufrag:string ->
  ice_pwd:string ->
  fingerprint:fingerprint ->
  session

(** Add ICE candidate to session *)
val add_candidate : session -> ice_candidate -> media_index:int -> session

(** Add ICE candidate to session after conversion to SDP candidate. *)
val add_candidate_from_ice : session -> Ice.candidate -> media_index:int -> session

(** Get all ICE candidates from session *)
val get_candidates : session -> ice_candidate list

(** {1 Utilities} *)

(** Find media by mid *)
val find_media_by_mid : session -> string -> media option

(** Find media by type *)
val find_media_by_type : session -> media_type -> media option

(** Find media by index *)
val find_media_by_index : session -> int -> media option

(** Resolve ICE credentials with media/session fallback *)
val resolve_ice_credentials : session -> media -> (string * string) option

(** Resolve ICE options with media/session fallback *)
val resolve_ice_options : session -> media -> string list

(** Resolve DTLS fingerprint with media/session fallback *)
val resolve_fingerprint : session -> media -> fingerprint option

(** Resolve SCTP port for DataChannel *)
val resolve_sctp_port : media -> int option

(** Check if session has DataChannel *)
val has_datachannel : session -> bool

(** Pretty-print session *)
val pp_session : Format.formatter -> session -> unit

(** Pretty-print media *)
val pp_media : Format.formatter -> media -> unit
