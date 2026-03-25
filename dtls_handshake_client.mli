(** DTLS Client Handshake — Client-side DTLS 1.2 handshake processing

    Handles ClientHello construction, server message parsing, ECDHE key exchange,
    and client Finished verification.

    @author Second Brain
    @since ocaml-webrtc 0.2.3
*)

(** Build a ClientHello message wrapped in a DTLS record. *)
val build_client_hello : Dtls_types.t -> bytes

(** Initiate client handshake. Returns the ClientHello record to send. *)
val start_handshake : Dtls_types.t -> (bytes list, string) result

(** Handle HelloVerifyRequest from server. Returns retried ClientHello with cookie. *)
val handle_hello_verify_request
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result

(** Handle ServerHello message. Stores negotiated cipher and SRTP profile. *)
val handle_server_hello
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result

(** Handle Certificate message from server. *)
val handle_certificate
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result

(** Handle ServerKeyExchange (ECDHE parameters per RFC 8422). *)
val handle_server_key_exchange
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result

(** Handle ServerHelloDone. Completes ECDHE and sends client flight
    (ClientKeyExchange + ChangeCipherSpec + Finished). *)
val handle_server_hello_done
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result

(** Handle server's Finished message. Verifies verify_data and transitions to Established. *)
val handle_finished
  :  Dtls_types.t
  -> bytes
  -> (bytes list * bytes option, string) result
