(** SCTP 4-Way Handshake (RFC 4960 §5)

    Implements connection establishment with state cookie for DoS protection.
    The key security property is that the server remains STATELESS until
    receiving a valid COOKIE-ECHO, preventing SYN flood attacks.

    {1 Handshake Flow}

    {v
    Client                    Server
      |                         |
      |------ INIT ------------>|  (1) Client sends initiate tag, TSN, streams
      |<----- INIT-ACK ---------|  (2) Server replies with cookie (stateless!)
      |------ COOKIE-ECHO ----->|  (3) Client returns the cookie
      |<----- COOKIE-ACK -------|  (4) Connection established
      |                         |
    v}

    @author Second Brain
*)

(** {1 Connection States} *)

(** State machine states (RFC 4960 §4) *)
type state =
  | Closed
  | CookieWait     (** Client: sent INIT, waiting for INIT-ACK *)
  | CookieEchoed   (** Client: sent COOKIE-ECHO, waiting for COOKIE-ACK *)
  | Established    (** Both: connection ready for data transfer *)
  | ShutdownPending
  | ShutdownSent
  | ShutdownReceived
  | ShutdownAckSent

(** {1 Protocol Types} *)

(** INIT chunk parameters (RFC 4960 §3.3.2) *)
type init_params = {
  initiate_tag: int32;          (** Random verification tag *)
  a_rwnd: int32;                (** Advertised receiver window *)
  num_outbound_streams: int;    (** Number of outbound streams (OS) *)
  num_inbound_streams: int;     (** Maximum inbound streams (MIS) *)
  initial_tsn: int32;           (** Initial transmission sequence number *)
}

(** State cookie - encodes all association info for stateless server *)
type state_cookie = {
  creation_time: float;         (** Unix timestamp when cookie was created *)
  lifespan_ms: int;             (** Cookie validity period in milliseconds *)
  peer_vtag: int32;             (** Peer's verification tag from INIT *)
  local_vtag: int32;            (** Our verification tag for INIT-ACK *)
  peer_initial_tsn: int32;      (** Peer's initial TSN *)
  local_initial_tsn: int32;     (** Our initial TSN *)
  peer_rwnd: int32;             (** Peer's receiver window *)
  local_rwnd: int32;            (** Our receiver window *)
  hmac: bytes;                  (** HMAC-SHA256 for integrity verification *)
}

(** Association (connection) state *)
type association = {
  mutable state: state;
  local_vtag: int32;
  peer_vtag: int32;
  local_initial_tsn: int32;
  peer_initial_tsn: int32;
  mutable local_rwnd: int32;
  mutable peer_rwnd: int32;
  num_outbound_streams: int;
  num_inbound_streams: int;
}

(** {1 Chunk Type Constants} *)

val chunk_type_init : int
(** INIT chunk type = 1 *)

val chunk_type_init_ack : int
(** INIT-ACK chunk type = 2 *)

val chunk_type_cookie_echo : int
(** COOKIE-ECHO chunk type = 10 *)

val chunk_type_cookie_ack : int
(** COOKIE-ACK chunk type = 11 *)

(** {1 HMAC Configuration} *)

val default_hmac_secret : string
(** Default HMAC secret - INSECURE, only for development/testing.
    Always set a proper secret for production use! *)

val set_hmac_secret : string -> unit
(** [set_hmac_secret secret] sets the HMAC key for cookie integrity.

    Call this at application startup before any connections.

    @param secret A strong random secret (at least 32 bytes recommended) *)

val init_hmac_secret_from_env : unit -> (bool, string) result
(** [init_hmac_secret_from_env ()] loads HMAC secret from SCTP_HMAC_SECRET
    environment variable.

    @return [Ok true] if successfully loaded, [Ok false] if not set,
            [Error msg] if env var is set but empty *)

(** {1 Random Generation} *)

val random_vtag : unit -> int32
(** Generate random verification tag (RFC 4960 §5.3.1).
    Never returns 0 (reserved value). *)

val random_initial_tsn : unit -> int32
(** Generate random initial TSN. Same algorithm as vtag. *)

(** {1 Cookie Encoding/Decoding} *)

val encode_cookie : state_cookie -> bytes
(** [encode_cookie cookie] encodes a state cookie to wire format.

    Cookie format (68 bytes):
    - Creation time: 8 bytes (IEEE 754 double)
    - Lifespan: 4 bytes
    - Tags and TSNs: 24 bytes
    - HMAC-SHA256: 32 bytes *)

val decode_cookie : bytes -> (state_cookie, string) result
(** [decode_cookie buf] decodes and validates a state cookie.

    Verifies:
    - HMAC integrity
    - Cookie not expired

    @return [Ok cookie] if valid, [Error reason] otherwise *)

(** {1 Chunk Encoding/Decoding} *)

val encode_init_chunk : init_params -> bytes
(** [encode_init_chunk params] encodes an INIT chunk. *)

val encode_init_ack : init_params -> state_cookie -> bytes
(** [encode_init_ack params cookie] encodes an INIT-ACK with embedded cookie. *)

val decode_init : bytes -> (init_params, string) result
(** [decode_init buf] decodes an INIT or INIT-ACK chunk. *)

val encode_cookie_echo : state_cookie -> bytes
(** [encode_cookie_echo cookie] encodes a COOKIE-ECHO chunk. *)

val decode_cookie_echo : bytes -> (state_cookie, string) result
(** [decode_cookie_echo buf] decodes a COOKIE-ECHO chunk and validates cookie. *)

val encode_cookie_ack : unit -> bytes
(** [encode_cookie_ack ()] creates a COOKIE-ACK chunk (4 bytes). *)

(** {1 State Machine Operations} *)

val default_rwnd : int32
(** Default receiver window size (256 KB). *)

val default_streams : int
(** Default number of streams (10). *)

val cookie_lifespan_ms : int
(** Cookie validity period (60 seconds). *)

val client_init : unit -> init_params * bytes * state
(** [client_init ()] initiates client-side handshake.

    Generates random parameters and INIT chunk.

    @return [(params, init_chunk, CookieWait)] *)

val server_process_init : bytes -> (init_params * bytes, string) result
(** [server_process_init init_buf] processes INIT and generates INIT-ACK.

    Server remains STATELESS - all info is encoded in the cookie.

    @return [Ok (local_params, init_ack_chunk)] or error *)

val client_process_init_ack : bytes -> init_params -> (association * bytes, string) result
(** [client_process_init_ack init_ack_buf local_params] processes INIT-ACK.

    Extracts cookie and generates COOKIE-ECHO.

    @return [Ok (association, cookie_echo_chunk)] or error *)

val server_process_cookie_echo : bytes -> (association * bytes, string) result
(** [server_process_cookie_echo cookie_echo_buf] processes COOKIE-ECHO.

    Recreates association from cookie (server was stateless until now!)
    and generates COOKIE-ACK.

    @return [Ok (association, cookie_ack_chunk)] or error *)

val client_process_cookie_ack : bytes -> association -> (association, string) result
(** [client_process_cookie_ack cookie_ack_buf assoc] completes handshake.

    Transitions association to Established state.

    @return [Ok association] or error *)

(** {1 Utilities} *)

val state_to_string : state -> string
(** Convert state to human-readable string. *)

val pp_association : Format.formatter -> association -> unit
(** Pretty-print association for debugging. *)
