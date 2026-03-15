(** WebRTC Protocol Constants

    Centralized constants extracted from RFC specifications.
    Each constant includes its RFC source for traceability. *)

(** {1 STUN/TURN Ports} *)

(** Default STUN port - RFC 5389 Section 18.4 *)
let stun_default_port = 3478

(** Default TURNS (TLS) port - RFC 5766 Section 12 *)
let turns_default_port = 5349

(** {1 STUN Protocol} *)

(** STUN magic cookie - RFC 5389 Section 6 *)
let stun_magic_cookie = 0x2112A442l

(** {1 SDP Defaults} *)

(** Default SDP address (wildcard) - RFC 4566 *)
let sdp_default_address = "0.0.0.0"

(** Default SDP username - RFC 4566 *)
let sdp_default_username = "-"

(** Default SDP session name - RFC 4566 *)
let sdp_default_session_name = "-"

(** Default SDP session ID *)
let sdp_default_session_id = "0"

(** {1 IP Address Classification} *)

(** Link-local address prefix - RFC 3927 *)
let link_local_prefix = "169.254."

(** Loopback address prefix - RFC 5735 *)
let loopback_prefix = "127."

(** {1 Well-known Servers} *)

(** Google public STUN server *)
let google_stun_server = "stun:stun.l.google.com:19302"

(** {1 Buffer Sizes} *)

(** UDP receive buffer size (64KB) *)
let recv_buffer_size = 65536

(** Ethernet MTU buffer size *)
let mtu_buffer_size = 1500

(** {1 Network Discovery} *)

(** Google DNS for routing-based local IP discovery *)
let google_dns = "8.8.8.8"

(** {1 URL Prefixes} *)

(** STUN URL prefix - RFC 7064 *)
let stun_url_prefix = "stun:"

(** TURN URL prefix - RFC 7065 *)
let turn_url_prefix = "turn:"

(** TURNS (TLS) URL prefix - RFC 7065 *)
let turns_url_prefix = "turns:"
