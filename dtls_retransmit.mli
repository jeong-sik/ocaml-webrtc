(** DTLS Retransmission — RFC 6347 Section 4.2.4 flight-based reliability

    Implements exponential backoff retransmission for DTLS handshake flights.
    Extracted from dtls.ml for modularity.

    RFC 6347 Section 4.2.4:
    "If the timer expires, the implementation retransmits the flight,
     resets the timer, and doubles the timeout value."

    @author Second Brain
    @since ocaml-webrtc 0.2.2
*)

val max_retransmit_timeout_ms : int
val next_retransmit_timeout : int -> int
val store_flight : Dtls_types.t -> bytes list -> unit
val clear_retransmit : Dtls_types.t -> unit
val handle_retransmit_timeout : Dtls_types.t -> (bytes list, string) result
val check_retransmit_needed : Dtls_types.t -> bool
val get_retransmit_state : Dtls_types.t -> int * int * bool
