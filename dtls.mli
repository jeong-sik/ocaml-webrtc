(** RFC 6347 DTLS - Datagram Transport Layer Security

    Pure OCaml implementation of DTLS 1.2 for WebRTC.

    DTLS provides TLS-like security for datagram protocols (UDP).
    Used to secure the SCTP connection for WebRTC DataChannels.

    Implements:
    - RFC 6347: DTLS 1.2
    - RFC 5764: DTLS-SRTP (key export only)

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

(** {1 Types} *)

(** DTLS content types *)
type content_type =
  | ChangeCipherSpec  (** 20 *)
  | Alert             (** 21 *)
  | Handshake         (** 22 *)
  | ApplicationData   (** 23 *)

(** Handshake message types *)
type handshake_type =
  | HelloRequest        (** 0 *)
  | ClientHello         (** 1 *)
  | ServerHello         (** 2 *)
  | HelloVerifyRequest  (** 3 - DTLS specific *)
  | Certificate         (** 11 *)
  | ServerKeyExchange   (** 12 *)
  | CertificateRequest  (** 13 *)
  | ServerHelloDone     (** 14 *)
  | CertificateVerify   (** 15 *)
  | ClientKeyExchange   (** 16 *)
  | Finished            (** 20 *)

(** Alert levels *)
type alert_level =
  | Warning   (** 1 *)
  | Fatal     (** 2 *)

(** Alert descriptions *)
type alert_description =
  | CloseNotify
  | UnexpectedMessage
  | BadRecordMac
  | DecryptionFailed
  | RecordOverflow
  | DecompressionFailure
  | HandshakeFailure
  | BadCertificate
  | UnsupportedCertificate
  | CertificateRevoked
  | CertificateExpired
  | CertificateUnknown
  | IllegalParameter
  | UnknownCA
  | AccessDenied
  | DecodeError
  | DecryptError
  | ProtocolVersion
  | InsufficientSecurity
  | InternalError
  | UserCanceled
  | NoRenegotiation

(** DTLS connection state *)
type state =
  | Initial
  (* Client states *)
  | HelloSent
  | HelloVerifyReceived
  | ServerHelloReceived
  | CertificateReceived
  | KeyExchangeDone
  | ChangeCipherSpecSent
  | Established
  | Closed
  | Error of string
  (* Server states *)
  | HelloVerifySent           (** Server sent HelloVerifyRequest *)
  | ClientHelloReceived       (** Server received valid ClientHello with cookie *)
  | ServerFlightSent          (** Server sent ServerHello...ServerHelloDone *)
  | ClientKeyExchangeReceived (** Server received ClientKeyExchange *)

(** Cipher suite *)
type cipher_suite =
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  (** 0xC02B *)
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256    (** 0xC02F *)
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384  (** 0xC02C *)
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384    (** 0xC030 *)

(** DTLS configuration *)
type config = {
  is_client : bool;
  certificate : string option;      (** PEM encoded *)
  private_key : string option;      (** PEM encoded *)
  verify_peer : bool;
  cipher_suites : cipher_suite list;
  mtu : int;                        (** Maximum transmission unit *)
  retransmit_timeout_ms : int;      (** Initial retransmit timeout *)
  max_retransmits : int;
}

(** DTLS context *)
type t

(** {1 Context Creation} *)

(** Default client configuration *)
val default_client_config : config

(** Default server configuration *)
val default_server_config : config

(** Create DTLS context *)
val create : config -> t

(** {1 Handshake} *)

(** Start handshake (client initiates) *)
val start_handshake : t -> (bytes list, string) result

(** Process incoming DTLS record.
    Returns outgoing records to send and any decrypted application data. *)
val handle_record : t -> bytes -> (bytes list * bytes option, string) result

(** Process incoming DTLS record as server with client address.
    The client_addr is needed for stateless cookie validation (DoS protection).
    Use this function for server-side processing instead of handle_record. *)
val handle_record_as_server :
  t -> bytes -> client_addr:(string * int) -> (bytes list * bytes option, string) result

(** Check if handshake is complete *)
val is_established : t -> bool

(** Get current state *)
val get_state : t -> state

(** {1 Data Transfer} *)

(** Encrypt application data for sending *)
val encrypt : t -> bytes -> (bytes, string) result

(** Decrypt received application data *)
val decrypt : t -> bytes -> (bytes, string) result

(** {1 Key Export (for SRTP)} *)

(** Export keying material (RFC 5705).
    Used for DTLS-SRTP key derivation. *)
val export_keying_material : t ->
  label:string ->
  context:bytes option ->
  length:int ->
  (bytes, string) result

(** {1 Utilities} *)

(** Close connection (send close_notify) *)
val close : t -> bytes option

(** Get negotiated cipher suite *)
val get_cipher_suite : t -> cipher_suite option

(** Get peer certificate if available *)
val get_peer_certificate : t -> string option

(** Pretty-print state *)
val pp_state : Format.formatter -> state -> unit

(** {1 Cookie Handling (RFC 6347 Section 4.2.1 DoS protection)} *)

(** Generate HMAC-SHA256 based cookie for HelloVerifyRequest.
    Cookie = HMAC(secret, client_ip || client_port || client_random)
    This is stateless - no connection state needed until cookie verified. *)
val generate_cookie :
  client_addr:(string * int) ->
  client_random:bytes ->
  bytes

(** Verify client cookie matches expected HMAC value *)
val verify_cookie :
  client_addr:(string * int) ->
  client_random:bytes ->
  cookie:bytes ->
  bool

(** {1 Retransmission (RFC 6347 Section 4.2.4)} *)

(** Store a flight for potential retransmission.
    Starts the retransmission timer. *)
val store_flight : t -> bytes list -> unit

(** Clear retransmission state when handshake progresses.
    Cancels any pending timer. *)
val clear_retransmit : t -> unit

(** Handle retransmission timer expiry.
    Returns flight to retransmit, or Error if max retransmits exceeded.

    RFC 6347 Section 4.2.4:
    "If the timer expires, the implementation retransmits the flight,
     resets the timer, and doubles the timeout value." *)
val handle_retransmit_timeout : t -> (bytes list, string) result

(** Check if retransmission is needed based on elapsed time.
    Useful for polling-based timer implementations. *)
val check_retransmit_needed : t -> bool

(** Get current retransmission state.
    Returns (retransmit_count, current_timeout_ms, timer_active). *)
val get_retransmit_state : t -> int * int * bool

(** {1 I/O Operations (Functional Dependency Injection)} *)

(** I/O operations for DTLS transport.
    This abstraction allows different transport implementations:
    - Eio UDP sockets (production)
    - Mock transport (testing)
    - Lwt/Unix fallback *)
type io_ops = {
  send: bytes -> int;         (** Send data, returns bytes sent *)
  recv: int -> bytes;         (** Receive up to N bytes (blocking) *)
  now: unit -> float;         (** Get current timestamp *)
  random: int -> bytes;       (** Generate N cryptographically secure random bytes *)
  set_timer: int -> unit;     (** Set retransmission timer (ms) *)
  cancel_timer: unit -> unit; (** Cancel pending retransmission timer *)
}

(** Default I/O ops using Unix time and Mirage_crypto random.
    send/recv are no-ops - suitable for testing only. *)
val default_io_ops : io_ops

(** {1 Effect Handler} *)

(** Effects used by DTLS for I/O *)
type _ Effect.t +=
  | Send : bytes -> int Effect.t      (** Send data, returns bytes sent *)
  | Recv : int -> bytes Effect.t      (** Receive up to N bytes *)
  | Now : float Effect.t              (** Get current time *)
  | Random : int -> bytes Effect.t    (** Generate N random bytes *)
  | SetTimer : int -> unit Effect.t   (** Set retransmit timer (ms) *)
  | CancelTimer : unit Effect.t       (** Cancel pending retransmit timer *)

(** Run DTLS code with custom I/O operations.
    This is the primary API - works with any transport implementation.

    Example with Eio UDP socket:
    {[
      let ops = {
        send = (fun data -> Udp_socket_eio.send_to socket data remote);
        recv = (fun size ->
          let dgram = Udp_socket_eio.recv socket in
          Bytes.sub dgram.data 0 (min size (Bytes.length dgram.data)));
        now = Unix.gettimeofday;
        random = (fun n -> Cstruct.to_bytes (Mirage_crypto_rng.generate n));
        set_timer = (fun ms -> Eio.Time.sleep clock (float ms /. 1000.0));
        cancel_timer = (fun () -> ());  (* Eio fiber cancellation *)
      } in
      run_with_io ~ops (fun () -> do_handshake conn)
    ]}

    @param ops I/O operations (send, recv, now, random)
    @param f The DTLS function to run *)
val run_with_io : ops:io_ops -> (unit -> 'a) -> 'a

(** Legacy wrapper - uses default no-op I/O.
    For testing only. Use [run_with_io] for production. *)
val run_with_eio : net:'a -> clock:'b -> (unit -> 'c) -> 'c
