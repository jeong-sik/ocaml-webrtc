(** SCTP HEARTBEAT - RFC 4960 Section 8.3

    HEARTBEAT serves multiple purposes:
    1. Path verification - ensure remote endpoint is reachable
    2. RTT measurement - calculate round-trip time for RTO
    3. Keep-alive - prevent NAT/firewall timeout

    Protocol:
    {v
    Sender                    Receiver
      |                         |
      |------ HEARTBEAT ------->|  (timestamp + random info)
      |<----- HEARTBEAT-ACK ----|  (echo back unchanged)
      |                         |
    v}

    @author Second Brain
    @since RFC 4960 compliance
*)

(** {1 Types} *)

(** HEARTBEAT information - RFC 4960 Section 3.3.5 *)
type heartbeat_info = {
  timestamp: float;             (* Send time for RTT calculation *)
  random_nonce: int32;          (* Random value to detect spoofing *)
  path_id: int;                 (* Which path this HB is for (multihoming) *)
}

(** Heartbeat state tracker *)
type t = {
  mutable last_heartbeat_sent: float option;
  mutable last_heartbeat_acked: float option;
  mutable pending_heartbeat: heartbeat_info option;
  mutable consecutive_failures: int;
  interval_ms: int;             (* How often to send HBs *)
  max_failures: int;            (* Failures before declaring path down *)
}

(** {1 Chunk Types} *)

let chunk_type_heartbeat = 4
let chunk_type_heartbeat_ack = 5

(** {1 Creation} *)

(** Create heartbeat state tracker
    @param interval_ms Heartbeat interval (default 30000ms = 30s)
    @param max_failures Max consecutive failures before path down (default 5) *)
let create ?(interval_ms = 30000) ?(max_failures = 5) () = {
  last_heartbeat_sent = None;
  last_heartbeat_acked = None;
  pending_heartbeat = None;
  consecutive_failures = 0;
  interval_ms;
  max_failures;
}

(** {1 Encoding/Decoding} *)

(** Encode heartbeat info to bytes *)
let encode_heartbeat_info info =
  (* Format: timestamp(8) + nonce(4) + path_id(4) = 16 bytes *)
  let buf = Bytes.create 16 in
  let time_bits = Int64.bits_of_float info.timestamp in
  for i = 0 to 7 do
    Bytes.set buf i (Char.chr (Int64.to_int (Int64.shift_right_logical time_bits (i * 8)) land 0xFF))
  done;
  Bytes.set_int32_be buf 8 info.random_nonce;
  Bytes.set_int32_be buf 12 (Int32.of_int info.path_id);
  buf

(** Decode heartbeat info from bytes *)
let decode_heartbeat_info buf =
  if Bytes.length buf < 16 then
    Error "Heartbeat info too short"
  else begin
    let time_bits = ref 0L in
    for i = 0 to 7 do
      time_bits := Int64.logor !time_bits
        (Int64.shift_left (Int64.of_int (Char.code (Bytes.get buf i))) (i * 8))
    done;
    let timestamp = Int64.float_of_bits !time_bits in
    let random_nonce = Bytes.get_int32_be buf 8 in
    let path_id = Int32.to_int (Bytes.get_int32_be buf 12) in
    Ok { timestamp; random_nonce; path_id }
  end

(** Encode HEARTBEAT chunk *)
let encode_heartbeat info =
  let info_buf = encode_heartbeat_info info in
  (* Chunk header (4) + Heartbeat Info TLV header (4) + info (16) = 24 bytes *)
  let buf = Bytes.create 24 in

  (* Chunk header *)
  Bytes.set buf 0 (Char.chr chunk_type_heartbeat);
  Bytes.set buf 1 (Char.chr 0);  (* flags *)
  Bytes.set_int16_be buf 2 24;   (* length *)

  (* Heartbeat Info parameter: Type = 1, Length = 20 *)
  Bytes.set_int16_be buf 4 1;    (* Parameter type: Heartbeat Info *)
  Bytes.set_int16_be buf 6 20;   (* Parameter length: 4 + 16 *)
  Bytes.blit info_buf 0 buf 8 16;

  buf

(** Decode HEARTBEAT chunk *)
let decode_heartbeat buf =
  if Bytes.length buf < 24 then
    Error "HEARTBEAT chunk too short"
  else begin
    let chunk_type = Char.code (Bytes.get buf 0) in
    if chunk_type <> chunk_type_heartbeat then
      Error "Not a HEARTBEAT chunk"
    else
      (* Extract info from parameter *)
      let info_buf = Bytes.sub buf 8 16 in
      decode_heartbeat_info info_buf
  end

(** Encode HEARTBEAT-ACK chunk - simply echoes back the info *)
let encode_heartbeat_ack info =
  let info_buf = encode_heartbeat_info info in
  let buf = Bytes.create 24 in

  Bytes.set buf 0 (Char.chr chunk_type_heartbeat_ack);
  Bytes.set buf 1 (Char.chr 0);
  Bytes.set_int16_be buf 2 24;

  Bytes.set_int16_be buf 4 1;
  Bytes.set_int16_be buf 6 20;
  Bytes.blit info_buf 0 buf 8 16;

  buf

(** Decode HEARTBEAT-ACK chunk *)
let decode_heartbeat_ack buf =
  if Bytes.length buf < 24 then
    Error "HEARTBEAT-ACK chunk too short"
  else begin
    let chunk_type = Char.code (Bytes.get buf 0) in
    if chunk_type <> chunk_type_heartbeat_ack then
      Error "Not a HEARTBEAT-ACK chunk"
    else
      let info_buf = Bytes.sub buf 8 16 in
      decode_heartbeat_info info_buf
  end

(** {1 State Machine} *)

(** Check if it's time to send a heartbeat *)
let should_send_heartbeat t =
  let now = Unix.gettimeofday () in
  match t.last_heartbeat_sent with
  | None -> true  (* Never sent, should start *)
  | Some last ->
    let elapsed_ms = (now -. last) *. 1000.0 in
    elapsed_ms >= float_of_int t.interval_ms && t.pending_heartbeat = None

(** Generate and send heartbeat *)
let generate_heartbeat t ~path_id =
  let now = Unix.gettimeofday () in
  let info = {
    timestamp = now;
    random_nonce = Random.int32 0x7FFFFFFFl;
    path_id;
  } in
  t.last_heartbeat_sent <- Some now;
  t.pending_heartbeat <- Some info;
  encode_heartbeat info

(** Process incoming HEARTBEAT and generate ACK *)
let process_heartbeat buf =
  match decode_heartbeat buf with
  | Error e -> Error e
  | Ok info ->
    (* Echo back unchanged - receiver doesn't interpret, just reflects *)
    Ok (encode_heartbeat_ack info)

(** Process incoming HEARTBEAT-ACK *)
let process_heartbeat_ack t buf =
  match decode_heartbeat_ack buf with
  | Error e -> Error e
  | Ok info ->
    (* Verify this is response to our pending heartbeat *)
    match t.pending_heartbeat with
    | None -> Error "Unexpected HEARTBEAT-ACK"
    | Some pending ->
      if info.random_nonce <> pending.random_nonce then
        Error "HEARTBEAT-ACK nonce mismatch"
      else begin
        let now = Unix.gettimeofday () in
        let rtt = now -. info.timestamp in
        t.last_heartbeat_acked <- Some now;
        t.pending_heartbeat <- None;
        t.consecutive_failures <- 0;
        Ok rtt  (* Return RTT for RTO calculation *)
      end

(** Handle heartbeat timeout (no ACK received) *)
let handle_timeout t =
  match t.pending_heartbeat with
  | None -> ()
  | Some _ ->
    t.consecutive_failures <- t.consecutive_failures + 1;
    t.pending_heartbeat <- None

(** Check if path is considered down *)
let is_path_down t =
  t.consecutive_failures >= t.max_failures

(** Get consecutive failure count *)
let failure_count t = t.consecutive_failures

(** {1 RTT Integration} *)

(** Update RTO based on heartbeat RTT measurement - RFC 4960 Section 6.3.1 *)
let update_rto ~current_srtt ~current_rttvar ~measured_rtt =
  let alpha = 0.125 in  (* 1/8 *)
  let beta = 0.25 in    (* 1/4 *)

  if current_srtt = 0.0 then begin
    (* First measurement *)
    let srtt = measured_rtt in
    let rttvar = measured_rtt /. 2.0 in
    let rto = srtt +. 4.0 *. rttvar in
    (srtt, rttvar, rto)
  end else begin
    (* Subsequent measurements *)
    let rttvar = (1.0 -. beta) *. current_rttvar +.
                 beta *. abs_float (current_srtt -. measured_rtt) in
    let srtt = (1.0 -. alpha) *. current_srtt +. alpha *. measured_rtt in
    let rto = srtt +. 4.0 *. rttvar in
    (srtt, rttvar, rto)
  end

(** {1 Utility} *)

let pp_heartbeat_info fmt info =
  Format.fprintf fmt "HB{ts=%.3f, nonce=%ld, path=%d}"
    info.timestamp info.random_nonce info.path_id

let pp fmt t =
  let pending = match t.pending_heartbeat with
    | None -> "none"
    | Some info -> Printf.sprintf "nonce=%ld" info.random_nonce
  in
  Format.fprintf fmt "Heartbeat{failures=%d/%d, pending=%s}"
    t.consecutive_failures t.max_failures pending
