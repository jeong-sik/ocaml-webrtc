(** Fault injection utilities for Sans-IO SCTP testing

    Provides tools for injecting faults into the Sctp_core state machine:
    - Packet corruption (bit flips, truncation, garbage bytes)
    - Timer manipulation (out-of-order, premature expiry)
    - Malformed packet construction

    Since Sctp_core is Sans-IO, fault injection is straightforward:
    just construct invalid inputs and feed them to [handle].

    @since 0.3.0
*)

open Webrtc

(** {1 Packet Corruption} *)

(** [corrupt_bytes ~pos ~value data] returns a copy with byte at [pos]
    replaced by [value].  Returns the original if [pos] is out of bounds. *)
let corrupt_byte ~pos ~value data =
  let len = Bytes.length data in
  if pos < 0 || pos >= len then data
  else begin
    let copy = Bytes.copy data in
    Bytes.set_uint8 copy pos value;
    copy
  end

(** [flip_bit ~pos ~bit data] returns a copy with bit [bit] (0-7) at
    byte [pos] flipped. *)
let flip_bit ~pos ~bit data =
  let len = Bytes.length data in
  if pos < 0 || pos >= len || bit < 0 || bit > 7 then data
  else begin
    let copy = Bytes.copy data in
    let orig = Bytes.get_uint8 copy pos in
    Bytes.set_uint8 copy pos (orig lxor (1 lsl bit));
    copy
  end

(** [truncate_packet ~len data] returns the first [len] bytes.
    Returns [data] unchanged if [len >= Bytes.length data]. *)
let truncate_packet ~len data =
  let actual = Bytes.length data in
  if len >= actual then data
  else Bytes.sub data 0 len

(** [garbage_packet ~len] returns [len] bytes of deterministic pseudo-random
    garbage (seeded for reproducibility). *)
let garbage_packet ~len =
  let buf = Bytes.create len in
  for i = 0 to len - 1 do
    Bytes.set_uint8 buf i ((i * 7 + 13) mod 256)
  done;
  buf

(** [zero_checksum data] zeroes out bytes 8-11 (SCTP CRC32c field). *)
let zero_checksum data =
  let len = Bytes.length data in
  if len < 12 then data
  else begin
    let copy = Bytes.copy data in
    Bytes.set_int32_be copy 8 0l;
    copy
  end

(** {1 Malformed Packet Construction} *)

(** [too_short_header] returns a 3-byte buffer (valid SCTP header is 12+). *)
let too_short_header () =
  Bytes.of_string "\x13\x88\x13\x88"  (* ports only, no vtag/checksum *)
  |> truncate_packet ~len:3

(** [valid_header ~src_port ~dst_port ~vtag] builds a minimal 12-byte
    SCTP common header (checksum zeroed, caller must CRC if needed). *)
let valid_header ?(src_port = 5000) ?(dst_port = 5000) ?(vtag = 0l) () =
  let buf = Bytes.make 12 '\x00' in
  Bytes.set_uint16_be buf 0 src_port;
  Bytes.set_uint16_be buf 2 dst_port;
  Bytes.set_int32_be buf 4 vtag;
  (* CRC32c at 8-11 left as zero *)
  buf

(** {1 Timer Manipulation} *)

(** [fire_all_timers t] fires each timer type once and collects outputs. *)
let fire_all_timers t =
  let timers = Sctp_core.[T3Rtx; DelayedAck; Heartbeat; Shutdown] in
  List.concat_map (fun timer ->
    Sctp_core.handle t (Sctp_core.TimerFired timer)
  ) timers

(** [fire_timers_reversed t] fires timers in reverse order. *)
let fire_timers_reversed t =
  let timers = Sctp_core.[Shutdown; Heartbeat; DelayedAck; T3Rtx] in
  List.concat_map (fun timer ->
    Sctp_core.handle t (Sctp_core.TimerFired timer)
  ) timers

(** {1 Output Classification} *)

(** [has_error outputs] returns true if any output is Error. *)
let has_error outputs =
  List.exists (fun o ->
    match o with
    | Sctp_core.Error _ -> true
    | _ -> false
  ) outputs

(** [errors_of outputs] extracts error messages. *)
let errors_of outputs =
  List.filter_map (fun o ->
    match o with
    | Sctp_core.Error msg -> Some msg
    | _ -> None
  ) outputs

(** [has_crash outputs] returns true if the function raised an exception.
    (For use with try/with wrappers.) *)
let did_not_crash f =
  match f () with
  | _ -> true
  | exception _ -> false
