(** DTLS Server Handshake — Server-side DTLS 1.2 handshake processing

    Handles stateless cookie exchange (RFC 6347 Section 4.2.1),
    server flight construction, and server Finished verification.

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

(** Generate HMAC-SHA256 based cookie for DoS protection.
    Cookie = HMAC(secret, client_ip || client_port || client_random). *)
val generate_cookie : client_addr:string * int -> client_random:bytes -> bytes

(** Verify client cookie matches expected HMAC value. *)
val verify_cookie
  :  client_addr:string * int
  -> client_random:bytes
  -> cookie:bytes
  -> bool

(** Parse ClientHello message body.
    Returns (client_random, cookie option, cipher_suite codes, srtp_profiles). *)
val parse_client_hello
  :  bytes
  -> (bytes * bytes option * int list * Srtp.profile list, string) result

(** Build HelloVerifyRequest with the given cookie. *)
val build_hello_verify_request : Dtls_types.t -> cookie:bytes -> bytes

(** Build ServerHello message. *)
val build_server_hello
  :  Dtls_types.t
  -> cipher_suite:Dtls_types.cipher_suite
  -> srtp_profile:Srtp.profile option
  -> bytes

(** Build Certificate message from PEM-encoded chain. *)
val build_certificate : Dtls_types.t -> string -> (bytes, string) result

(** Build ServerKeyExchange for ECDHE (RFC 8422). *)
val build_server_key_exchange : Dtls_types.t -> (bytes, string) result

(** Build ServerHelloDone message (empty body). *)
val build_server_hello_done : Dtls_types.t -> bytes

(** Handle ClientHello as server.
    Implements RFC 6347 Section 4.2.1 cookie exchange for DoS protection. *)
val handle_client_hello
  :  Dtls_types.t
  -> payload:bytes
  -> body:bytes
  -> client_addr:string * int
  -> (bytes list * bytes option, string) result

(** Handle ClientKeyExchange as server (ECDHE).
    Extracts client's public key and computes shared secret. *)
val handle_client_key_exchange
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result

(** Build server's ChangeCipherSpec + Finished flight. *)
val build_server_finished : Dtls_types.t -> bytes list

(** Handle Finished message as server - verify client's Finished and send server Finished. *)
val handle_finished_as_server
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result
