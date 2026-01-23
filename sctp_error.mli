(** SCTP ERROR Chunk (RFC 4960 §3.3.10)

    Handles ERROR chunk encoding for protocol error reporting.
    Primary use case: Reporting unrecognized chunk types per RFC 4960 §3.2

    {1 RFC 4960 §3.2 - Unknown Chunk Handling}

    When an SCTP endpoint receives a chunk with an unrecognized type,
    the upper 2 bits of the chunk type determine the action:

    {v
    Bits 6-7  | Action
    ----------|--------------------------------------------------
    00 (0x00-0x3F) | Stop processing, discard packet
    01 (0x40-0x7F) | Stop processing, discard packet, send ERROR
    10 (0x80-0xBF) | Skip this chunk, continue processing
    11 (0xC0-0xFF) | Skip chunk, continue processing, send ERROR
    v}

    @author Second Brain
*)

(** {1 Error Cause Codes (RFC 4960 §3.3.10)} *)

(** 1 - Invalid Stream Identifier *)
val cause_invalid_stream : int

(** 2 - Missing Mandatory Parameter *)
val cause_missing_mandatory_param : int

(** 3 - Stale Cookie Error *)
val cause_stale_cookie : int

(** 4 - Out of Resource *)
val cause_out_of_resource : int

(** 5 - Unresolvable Address *)
val cause_unresolvable_address : int

(** 6 - Unrecognized Chunk Type *)
val cause_unrecognized_chunk : int

(** 7 - Invalid Mandatory Parameter *)
val cause_invalid_mandatory_param : int

(** 8 - Unrecognized Parameters *)
val cause_unrecognized_params : int

(** 9 - No User Data *)
val cause_no_user_data : int

(** 10 - Cookie Received While Shutting Down *)
val cause_cookie_while_shutdown : int

(** 11 - Restart of an Association with New Addresses *)
val cause_restart_with_new_addr : int

(** 12 - User Initiated Abort *)
val cause_user_initiated_abort : int

(** 13 - Protocol Violation *)
val cause_protocol_violation : int

(** ERROR chunk type = 9 *)
val chunk_type_error : int

(** {1 Unknown Chunk Handling} *)

(** Action to take when encountering an unknown chunk type *)
type unknown_chunk_action =
  | StopDiscard (** 00: Stop processing and discard packet *)
  | StopDiscardReport (** 01: Stop, discard, and send ERROR chunk *)
  | SkipContinue (** 10: Skip this chunk, continue processing *)
  | SkipContinueReport (** 11: Skip, continue, and send ERROR chunk *)

(** [action_for_unknown_chunk chunk_type] determines the handling action
    for an unrecognized chunk type based on its upper 2 bits.

    @param chunk_type The chunk type byte (0-255)
    @return The action to take per RFC 4960 §3.2 *)
val action_for_unknown_chunk : int -> unknown_chunk_action

(** [should_report chunk_type] returns true if an ERROR chunk should be
    sent for this unknown chunk type (bit 6 is set). *)
val should_report : int -> bool

(** [should_stop chunk_type] returns true if processing should stop
    after encountering this unknown chunk type (bit 7 is clear). *)
val should_stop : int -> bool

(** Convert action to human-readable string for debugging *)
val string_of_action : unknown_chunk_action -> string

(** {1 ERROR Chunk Encoding} *)

(** [encode_unrecognized_chunk_cause ~unrecognized_chunk] creates an
    "Unrecognized Chunk Type" error cause (RFC 4960 §3.3.10.6).

    The cause includes the full unrecognized chunk for debugging.

    @param unrecognized_chunk The chunk that was not recognized
    @return Encoded error cause with proper padding *)
val encode_unrecognized_chunk_cause : unrecognized_chunk:bytes -> bytes

(** [encode_error_chunk ~causes] creates an ERROR chunk containing
    one or more error causes.

    @param causes List of encoded error causes
    @return Complete ERROR chunk ready to send *)
val encode_error_chunk : causes:bytes list -> bytes

(** [make_unrecognized_chunk_error ~unrecognized_chunk] is a convenience
    function that creates a complete ERROR chunk for an unrecognized
    chunk type.

    Equivalent to:
    {[
      let cause = encode_unrecognized_chunk_cause ~unrecognized_chunk in
      encode_error_chunk ~causes:[cause]
    ]}

    @param unrecognized_chunk The chunk that was not recognized
    @return Complete ERROR chunk ready to send *)
val make_unrecognized_chunk_error : unrecognized_chunk:bytes -> bytes
