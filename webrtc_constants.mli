(** WebRTC Protocol Constants

    Centralized constants extracted from RFC specifications.
    Each constant includes its RFC source for traceability. *)

(** {1 STUN/TURN Ports} *)

(** Default STUN port - RFC 5389 Section 18.4 *)
val stun_default_port : int

(** Default TURNS (TLS) port - RFC 5766 Section 12 *)
val turns_default_port : int

(** {1 STUN Protocol} *)

(** STUN magic cookie - RFC 5389 Section 6 *)
val stun_magic_cookie : int32

(** {1 SDP Defaults} *)

(** Default SDP address (wildcard) - RFC 4566 *)
val sdp_default_address : string

(** Default SDP username - RFC 4566 *)
val sdp_default_username : string

(** Default SDP session name - RFC 4566 *)
val sdp_default_session_name : string

(** Default SDP session ID *)
val sdp_default_session_id : string

(** {1 IP Address Classification} *)

(** Link-local address prefix - RFC 3927 *)
val link_local_prefix : string

(** Loopback address prefix - RFC 5735 *)
val loopback_prefix : string

(** {1 Well-known Servers} *)

(** Google public STUN server *)
val google_stun_server : string

(** {1 Buffer Sizes} *)

(** UDP receive buffer size (64KB) *)
val recv_buffer_size : int

(** Ethernet MTU buffer size *)
val mtu_buffer_size : int

(** {1 Network Discovery} *)

(** Google DNS for routing-based local IP discovery *)
val google_dns : string

(** {1 URL Prefixes} *)

(** STUN URL prefix - RFC 7064 *)
val stun_url_prefix : string

(** TURN URL prefix - RFC 7065 *)
val turn_url_prefix : string

(** TURNS (TLS) URL prefix - RFC 7065 *)
val turns_url_prefix : string
