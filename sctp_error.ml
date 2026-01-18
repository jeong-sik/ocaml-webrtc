(** SCTP ERROR Chunk (RFC 4960 §3.3.10)

    Handles ERROR chunk encoding for protocol error reporting.
    Primary use case: Reporting unrecognized chunk types per RFC 4960 §3.2

    @author Second Brain
*)

(** Error cause codes - RFC 4960 §3.3.10 *)
let cause_invalid_stream = 1
let cause_missing_mandatory_param = 2
let cause_stale_cookie = 3
let cause_out_of_resource = 4
let cause_unresolvable_address = 5
let cause_unrecognized_chunk = 6
let cause_invalid_mandatory_param = 7
let cause_unrecognized_params = 8
let cause_no_user_data = 9
let cause_cookie_while_shutdown = 10
let cause_restart_with_new_addr = 11
let cause_user_initiated_abort = 12
let cause_protocol_violation = 13

let chunk_type_error = 9

(** RFC 4960 §3.2 - Unknown chunk handling rules based on upper 2 bits

    Bits 6-7 determine how to handle unrecognized chunks:
    - 00: Stop processing, discard packet
    - 01: Stop processing, discard packet, report ERROR
    - 10: Skip chunk, continue processing
    - 11: Skip chunk, continue processing, report ERROR
*)
type unknown_chunk_action =
  | StopDiscard           (** 00: Stop and discard packet *)
  | StopDiscardReport     (** 01: Stop, discard, send ERROR *)
  | SkipContinue          (** 10: Skip this chunk, continue *)
  | SkipContinueReport    (** 11: Skip, continue, send ERROR *)

(** Determine action for unknown chunk type based on upper 2 bits *)
let action_for_unknown_chunk chunk_type =
  match (chunk_type lsr 6) land 0x03 with
  | 0 -> StopDiscard
  | 1 -> StopDiscardReport
  | 2 -> SkipContinue
  | 3 -> SkipContinueReport
  | _ -> SkipContinue  (* Unreachable, but OCaml requires exhaustive match *)

(** Should we report this unknown chunk in an ERROR? *)
let should_report chunk_type =
  match action_for_unknown_chunk chunk_type with
  | StopDiscardReport | SkipContinueReport -> true
  | StopDiscard | SkipContinue -> false

(** Should we stop processing after this unknown chunk? *)
let should_stop chunk_type =
  match action_for_unknown_chunk chunk_type with
  | StopDiscard | StopDiscardReport -> true
  | SkipContinue | SkipContinueReport -> false

(** Encode "Unrecognized Chunk Type" error cause (RFC 4960 §3.3.10.6)

    Format:
    - Cause Code: 2 bytes (6 = Unrecognized Chunk Type)
    - Cause Length: 2 bytes
    - Unrecognized Chunk: Variable (the full chunk that was not recognized)
*)
let encode_unrecognized_chunk_cause ~unrecognized_chunk =
  let chunk_len = Bytes.length unrecognized_chunk in
  let cause_len = 4 + chunk_len in  (* 4 = code + length fields *)
  let padded_len = (cause_len + 3) land (lnot 3) in
  let buf = Bytes.make padded_len '\x00' in

  (* Cause Code: 6 *)
  Bytes.set_uint16_be buf 0 cause_unrecognized_chunk;
  (* Cause Length *)
  Bytes.set_uint16_be buf 2 cause_len;
  (* Unrecognized Chunk *)
  Bytes.blit unrecognized_chunk 0 buf 4 chunk_len;

  buf

(** Encode ERROR chunk (RFC 4960 §3.3.10)

    Format:
    - Type: 1 byte (9)
    - Chunk Flags: 1 byte (0)
    - Chunk Length: 2 bytes
    - One or more Error Causes
*)
let encode_error_chunk ~causes =
  (* Calculate total causes length *)
  let causes_len = List.fold_left (fun acc c -> acc + Bytes.length c) 0 causes in
  let chunk_len = 4 + causes_len in  (* 4 = chunk header *)
  let padded_len = (chunk_len + 3) land (lnot 3) in
  let buf = Bytes.make padded_len '\x00' in

  (* Chunk Type: ERROR (9) *)
  Bytes.set_uint8 buf 0 chunk_type_error;
  (* Chunk Flags: 0 *)
  Bytes.set_uint8 buf 1 0;
  (* Chunk Length *)
  Bytes.set_uint16_be buf 2 chunk_len;

  (* Copy causes *)
  let offset = ref 4 in
  List.iter (fun cause ->
    let len = Bytes.length cause in
    Bytes.blit cause 0 buf !offset len;
    offset := !offset + len
  ) causes;

  buf

(** Create ERROR chunk for unrecognized chunk type

    Convenience function that combines encode_unrecognized_chunk_cause
    and encode_error_chunk into a single call.
*)
let make_unrecognized_chunk_error ~unrecognized_chunk =
  let cause = encode_unrecognized_chunk_cause ~unrecognized_chunk in
  encode_error_chunk ~causes:[cause]

(** String representation of unknown chunk action *)
let string_of_action = function
  | StopDiscard -> "stop-discard"
  | StopDiscardReport -> "stop-discard-report"
  | SkipContinue -> "skip-continue"
  | SkipContinueReport -> "skip-continue-report"
