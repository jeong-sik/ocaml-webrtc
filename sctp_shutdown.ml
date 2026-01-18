(** SCTP Shutdown - RFC 4960 Section 9

    Graceful connection termination ensuring all data is delivered.

    Shutdown flow (3-way):
    {v
    Initiator                 Peer
      |                         |
      |------ SHUTDOWN -------->|  (1) Cumulative TSN ACK point
      |<----- SHUTDOWN-ACK -----|  (2) Acknowledgment
      |------ SHUTDOWN-COMPLETE>|  (3) Final confirmation
      |                         |
    v}

    Unlike TCP's 4-way close (FIN/ACK each direction), SCTP doesn't have
    half-close. SHUTDOWN means "I have no more data AND I want to close".

    Note: If there's still data to send, use SHUTDOWN-PENDING state first.

    @author Second Brain
    @since RFC 4960 compliance
*)

(** {1 Types} *)

(** Shutdown chunk - RFC 4960 Section 3.3.8 *)
type shutdown = {
  cumulative_tsn_ack: int32;  (* Last TSN received *)
}

(** Shutdown state *)
type state =
  | Active                    (* Normal operation *)
  | ShutdownPending           (* User requested close, draining queue *)
  | ShutdownSent              (* SHUTDOWN sent, waiting for ACK *)
  | ShutdownReceived          (* SHUTDOWN received from peer *)
  | ShutdownAckSent           (* SHUTDOWN-ACK sent, waiting for COMPLETE *)
  | Closed                    (* Association terminated *)

let state_to_string = function
  | Active -> "ACTIVE"
  | ShutdownPending -> "SHUTDOWN-PENDING"
  | ShutdownSent -> "SHUTDOWN-SENT"
  | ShutdownReceived -> "SHUTDOWN-RECEIVED"
  | ShutdownAckSent -> "SHUTDOWN-ACK-SENT"
  | Closed -> "CLOSED"

(** Shutdown state tracker *)
type t = {
  mutable state: state;
  mutable shutdown_sent_time: float option;
  mutable retransmit_count: int;
  max_retransmits: int;
  mutable peer_cumulative_tsn: int32 option;
}

(** {1 Chunk Types} *)

let chunk_type_shutdown = 7
let chunk_type_shutdown_ack = 8
let chunk_type_shutdown_complete = 14

(** {1 Creation} *)

let create ?(max_retransmits = 5) () = {
  state = Active;
  shutdown_sent_time = None;
  retransmit_count = 0;
  max_retransmits;
  peer_cumulative_tsn = None;
}

(** {1 Encoding/Decoding} *)

(** Encode SHUTDOWN chunk *)
let encode_shutdown shutdown =
  (* Chunk: Type(1) + Flags(1) + Length(2) + Cumulative TSN(4) = 8 bytes *)
  let buf = Bytes.create 8 in
  Bytes.set buf 0 (Char.chr chunk_type_shutdown);
  Bytes.set buf 1 (Char.chr 0);
  Bytes.set_int16_be buf 2 8;
  Bytes.set_int32_be buf 4 shutdown.cumulative_tsn_ack;
  buf

(** Decode SHUTDOWN chunk *)
let decode_shutdown buf =
  if Bytes.length buf < 8 then
    Error "SHUTDOWN chunk too short"
  else begin
    let chunk_type = Char.code (Bytes.get buf 0) in
    if chunk_type <> chunk_type_shutdown then
      Error "Not a SHUTDOWN chunk"
    else
      Ok { cumulative_tsn_ack = Bytes.get_int32_be buf 4 }
  end

(** Encode SHUTDOWN-ACK chunk *)
let encode_shutdown_ack () =
  (* Just header, no body *)
  let buf = Bytes.create 4 in
  Bytes.set buf 0 (Char.chr chunk_type_shutdown_ack);
  Bytes.set buf 1 (Char.chr 0);
  Bytes.set_int16_be buf 2 4;
  buf

(** Decode SHUTDOWN-ACK chunk *)
let decode_shutdown_ack buf =
  if Bytes.length buf < 4 then
    Error "SHUTDOWN-ACK chunk too short"
  else begin
    let chunk_type = Char.code (Bytes.get buf 0) in
    if chunk_type <> chunk_type_shutdown_ack then
      Error "Not a SHUTDOWN-ACK chunk"
    else
      Ok ()
  end

(** Encode SHUTDOWN-COMPLETE chunk *)
let encode_shutdown_complete ~t_bit =
  (* T-bit: set if no TCB destroyed (association was already gone) *)
  let buf = Bytes.create 4 in
  Bytes.set buf 0 (Char.chr chunk_type_shutdown_complete);
  Bytes.set buf 1 (Char.chr (if t_bit then 1 else 0));
  Bytes.set_int16_be buf 2 4;
  buf

(** Decode SHUTDOWN-COMPLETE chunk *)
let decode_shutdown_complete buf =
  if Bytes.length buf < 4 then
    Error "SHUTDOWN-COMPLETE chunk too short"
  else begin
    let chunk_type = Char.code (Bytes.get buf 0) in
    if chunk_type <> chunk_type_shutdown_complete then
      Error "Not a SHUTDOWN-COMPLETE chunk"
    else begin
      let flags = Char.code (Bytes.get buf 1) in
      let t_bit = (flags land 1) = 1 in
      Ok t_bit
    end
  end

(** {1 State Machine} *)

(** Initiator: Start shutdown process *)
let initiate_shutdown t ~cumulative_tsn =
  match t.state with
  | Active ->
    t.state <- ShutdownSent;
    t.shutdown_sent_time <- Some (Unix.gettimeofday ());
    t.retransmit_count <- 0;
    let shutdown = { cumulative_tsn_ack = cumulative_tsn } in
    Ok (encode_shutdown shutdown)
  | ShutdownPending ->
    (* Queue drained, now send SHUTDOWN *)
    t.state <- ShutdownSent;
    t.shutdown_sent_time <- Some (Unix.gettimeofday ());
    let shutdown = { cumulative_tsn_ack = cumulative_tsn } in
    Ok (encode_shutdown shutdown)
  | _ ->
    Error (Printf.sprintf "Cannot initiate shutdown in state %s"
             (state_to_string t.state))

(** Receiver: Process incoming SHUTDOWN *)
let process_shutdown t buf =
  match decode_shutdown buf with
  | Error e -> Error e
  | Ok shutdown ->
    begin match t.state with
    | Active | ShutdownPending ->
      t.state <- ShutdownReceived;
      t.peer_cumulative_tsn <- Some shutdown.cumulative_tsn_ack;
      (* Send SHUTDOWN-ACK *)
      Ok (encode_shutdown_ack ())
    | ShutdownSent ->
      (* Simultaneous shutdown - both sides shutting down *)
      t.state <- ShutdownAckSent;
      t.peer_cumulative_tsn <- Some shutdown.cumulative_tsn_ack;
      Ok (encode_shutdown_ack ())
    | _ ->
      Error (Printf.sprintf "Unexpected SHUTDOWN in state %s"
               (state_to_string t.state))
    end

(** Initiator: Process incoming SHUTDOWN-ACK *)
let process_shutdown_ack t buf =
  match decode_shutdown_ack buf with
  | Error e -> Error e
  | Ok () ->
    begin match t.state with
    | ShutdownSent ->
      t.state <- Closed;
      (* Send SHUTDOWN-COMPLETE *)
      Ok (encode_shutdown_complete ~t_bit:false)
    | ShutdownAckSent ->
      t.state <- Closed;
      Ok (encode_shutdown_complete ~t_bit:false)
    | _ ->
      Error (Printf.sprintf "Unexpected SHUTDOWN-ACK in state %s"
               (state_to_string t.state))
    end

(** Receiver: Process incoming SHUTDOWN-COMPLETE *)
let process_shutdown_complete t buf =
  match decode_shutdown_complete buf with
  | Error e -> Error e
  | Ok _t_bit ->
    begin match t.state with
    | ShutdownReceived | ShutdownAckSent ->
      t.state <- Closed;
      Ok ()
    | _ ->
      Error (Printf.sprintf "Unexpected SHUTDOWN-COMPLETE in state %s"
               (state_to_string t.state))
    end

(** Check if shutdown timed out (need retransmit) *)
let needs_retransmit t ~rto =
  match t.state, t.shutdown_sent_time with
  | ShutdownSent, Some sent_time ->
    let now = Unix.gettimeofday () in
    let elapsed = now -. sent_time in
    elapsed > rto && t.retransmit_count < t.max_retransmits
  | _ -> false

(** Retransmit SHUTDOWN *)
let retransmit_shutdown t ~cumulative_tsn =
  if t.retransmit_count >= t.max_retransmits then begin
    t.state <- Closed;
    Error "Max shutdown retransmits exceeded"
  end else begin
    t.retransmit_count <- t.retransmit_count + 1;
    t.shutdown_sent_time <- Some (Unix.gettimeofday ());
    let shutdown = { cumulative_tsn_ack = cumulative_tsn } in
    Ok (encode_shutdown shutdown)
  end

(** {1 Queries} *)

let is_closed t = t.state = Closed

let is_shutting_down t =
  match t.state with
  | ShutdownPending | ShutdownSent | ShutdownReceived | ShutdownAckSent -> true
  | _ -> false

let can_send_data t =
  match t.state with
  | Active -> true
  | _ -> false

let pp fmt t =
  Format.fprintf fmt "Shutdown{state=%s, retransmits=%d/%d}"
    (state_to_string t.state) t.retransmit_count t.max_retransmits
