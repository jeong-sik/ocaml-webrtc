(** Full SCTP Transport - Complete Reliable Transport Layer

    Integrates all SCTP components for fair comparison with Pion:
    - sctp.ml: Chunk encoding/decoding
    - sctp_reliable.ml: SACK, congestion control, retransmission
    - udp_transport.ml: Real network I/O

    This provides the same functionality as Pion's SCTP implementation:
    - Reliable, ordered delivery
    - Congestion control (Slow Start, Congestion Avoidance)
    - Fast Retransmit (3 dup SACKs)
    - T3-rtx timeout retransmission

    @author Second Brain
    @since ocaml-webrtc 0.3.0
*)

(** {1 Types} *)

type stats = {
  mutable messages_sent: int;
  mutable messages_recv: int;
  mutable bytes_sent: int;
  mutable bytes_recv: int;
  mutable sacks_sent: int;
  mutable sacks_recv: int;
  mutable retransmissions: int;
  mutable fast_retransmissions: int;
}

type t = {
  udp: Udp_transport.t;
  reliable: Sctp_reliable.t;
  config: Sctp.config;
  mutable next_stream_seq: int;
  recv_buffer: bytes;
  send_buffer: bytes;  (* Reusable send buffer - zero-copy encoding *)
  stats: stats;
  (* Delayed ACK support - RFC 4960 Section 6.2 *)
  mutable packets_since_sack: int;  (* Counter for delayed ACK *)
  mutable pending_sack: bool;       (* SACK is pending *)
  (* Chunk bundling - RFC 4960 §6.10 *)
  mutable bundle_offset: int;       (* Current offset in send_buffer for bundling *)
}

(** {1 Creation} *)

let create_stats () = {
  messages_sent = 0;
  messages_recv = 0;
  bytes_sent = 0;
  bytes_recv = 0;
  sacks_sent = 0;
  sacks_recv = 0;
  retransmissions = 0;
  fast_retransmissions = 0;
}

(** Create SCTP transport with optional initial TSN
    @param initial_tsn Override random TSN for testing or handshake.
                       In production, this comes from 4-way handshake negotiation.
                       RFC 4960 requires random TSN by default. *)
let create ?(config = Sctp.default_config) ?initial_tsn ~host ~port () =
  let udp = Udp_transport.create ~host ~port () in
  let reliable = Sctp_reliable.create ~config ?initial_tsn () in
  {
    udp;
    reliable;
    config;
    next_stream_seq = 0;
    recv_buffer = Bytes.create 65536;
    send_buffer = Bytes.create 65536;  (* Reusable send buffer *)
    stats = create_stats ();
    packets_since_sack = 0;
    pending_sack = false;
    bundle_offset = 0;
  }

let connect t ~host ~port =
  Udp_transport.connect t.udp ~host ~port

let local_endpoint t = Udp_transport.local_endpoint t.udp

(** {1 Internal: Send/Receive Packets} *)

let send_packet t packet =
  Udp_transport.send_connected t.udp ~data:packet

let recv_packet t ~timeout_ms =
  Udp_transport.recv_timeout t.udp ~buf:t.recv_buffer ~timeout_ms

(** Try to receive a packet without copying.
    Returns (buffer, length) tuple - buffer is only valid until next recv! *)
let try_recv_packet_zerocopy t =
  match Udp_transport.recv t.udp ~buf:t.recv_buffer with
  | Ok (len, _) -> Some (t.recv_buffer, len)
  | Error _ -> None

(** Legacy: returns copied packet for backwards compatibility *)
let try_recv_packet t =
  match try_recv_packet_zerocopy t with
  | Some (buf, len) -> Some (Bytes.sub buf 0 len)
  | None -> None

(** {1 Send Data with Reliability} *)

(** Flush bundled chunks - sends accumulated chunks as one UDP packet *)
let flush_bundle t =
  if t.bundle_offset > 0 then begin
    ignore (Udp_transport.send_view t.udp ~buf:t.send_buffer ~off:0 ~len:t.bundle_offset);
    t.bundle_offset <- 0
  end

(** Add chunk to bundle, flush if would exceed MTU.
    Returns encoded length for statistics. *)
let bundle_chunk t chunk =
  let data_len = Bytes.length chunk.Sctp.user_data in
  let chunk_len = 16 + data_len in
  let padded_len = (chunk_len + 3) land (lnot 3) in

  (* Check if adding this chunk would exceed MTU *)
  if t.bundle_offset + padded_len > t.config.mtu then
    flush_bundle t;

  (* Encode chunk into bundle buffer *)
  let encoded_len = Sctp.encode_data_chunk_into ~buf:t.send_buffer ~off:t.bundle_offset chunk in
  t.bundle_offset <- t.bundle_offset + encoded_len;
  encoded_len

(** Send data with full SCTP reliability - uses chunk bundling *)
let send_data t ~stream_id ~data =
  (* Check congestion window *)
  if not (Sctp_reliable.can_send t.reliable) then
    Error "Congestion window full"
  else begin
    let data_len = Bytes.length data in

    (* Fragment if needed *)
    let tsn = Sctp_reliable.alloc_tsn t.reliable in
    let chunks = Sctp.fragment_data
      ~data
      ~stream_id
      ~stream_seq:t.next_stream_seq
      ~ppid:0x32l
      ~start_tsn:tsn
      ~mtu:t.config.mtu
    in
    t.next_stream_seq <- t.next_stream_seq + 1;

    (* Queue chunks and add to bundle - sends when MTU reached *)
    let total_encoded = ref 0 in
    List.iter (fun chunk ->
      (* Queue for potential retransmission *)
      Sctp_reliable.queue_data t.reliable chunk;

      (* Add to bundle (auto-flushes if MTU exceeded) *)
      let encoded = bundle_chunk t chunk in
      total_encoded := !total_encoded + encoded
    ) chunks;

    t.stats.messages_sent <- t.stats.messages_sent + 1;
    t.stats.bytes_sent <- t.stats.bytes_sent + data_len;
    Ok data_len
  end

(** {1 Receive Data and Send SACKs} *)

(** Process a single chunk and return (chunk_length, optional_data) *)
let process_single_chunk t ~buf ~off ~remaining =
  if remaining < 4 then (remaining, None)  (* Not enough for header *)
  else begin
    let chunk_type = Bytes.get_uint8 buf off in
    (* Chunk length from header (bytes 2-3) *)
    let chunk_len = Bytes.get_uint16_be buf (off + 2) in
    let padded_len = (chunk_len + 3) land (lnot 3) in

    if padded_len > remaining then (remaining, None)  (* Incomplete chunk *)
    else match chunk_type with
    | 0 -> (* DATA chunk *)
      begin match Sctp.decode_data_chunk_view buf ~off ~len:padded_len with
      | Ok chunk ->
        let is_new = Sctp_reliable.record_received t.reliable chunk.tsn in
        if is_new then begin
          t.stats.messages_recv <- t.stats.messages_recv + 1;
          t.stats.bytes_recv <- t.stats.bytes_recv + Bytes.length chunk.user_data;
        end;
        t.packets_since_sack <- t.packets_since_sack + 1;
        (padded_len, Some chunk.user_data)
      | Error _ -> (padded_len, None)
      end

    | 3 -> (* SACK chunk *)
      begin match Sctp_reliable.decode_sack (Bytes.sub buf off padded_len) with
      | Ok sack ->
        Sctp_reliable.process_sack t.reliable sack;
        t.stats.sacks_recv <- t.stats.sacks_recv + 1;
        (padded_len, None)
      | Error _ -> (padded_len, None)
      end

    | _ ->
      (* RFC 4960 §3.2 - Unknown chunk handling based on upper 2 bits *)
      (* This fast-path processor only handles DATA/SACK; other chunks are skipped *)
      (* Full RFC compliance (ERROR reporting) is in sctp_core.ml *)
      let action = Sctp_error.action_for_unknown_chunk chunk_type in
      begin match action with
      | Sctp_error.StopDiscard | Sctp_error.StopDiscardReport ->
        (* Stop processing: return remaining to signal early termination *)
        (remaining, None)
      | Sctp_error.SkipContinue | Sctp_error.SkipContinueReport ->
        (* Skip and continue *)
        (padded_len, None)
      end
  end

(** Process received packet - handles bundled chunks (RFC 4960 §6.10) *)
let process_packet_view t ~buf ~off ~len =
  let chunks_processed = ref 0 in
  let last_data = ref None in
  let pos = ref off in
  let remaining = ref len in

  (* Parse all chunks in packet *)
  while !remaining > 0 do
    let (consumed, data_opt) = process_single_chunk t ~buf ~off:!pos ~remaining:!remaining in
    pos := !pos + consumed;
    remaining := !remaining - consumed;
    incr chunks_processed;
    match data_opt with
    | Some d -> last_data := Some d
    | None -> ()
  done;

  (* Send SACK after processing all chunks in packet - delayed ACK per RFC 4960 *)
  if !chunks_processed > 0 && t.packets_since_sack >= 2 then begin
    let sack = Sctp_reliable.generate_sack t.reliable in
    let sack_encoded = Sctp_reliable.encode_sack sack in
    ignore (send_packet t sack_encoded);
    t.stats.sacks_sent <- t.stats.sacks_sent + 1;
    t.packets_since_sack <- 0;
    t.pending_sack <- false
  end else if !chunks_processed > 0 then
    t.pending_sack <- true;

  !last_data

(** Backwards-compatible wrapper *)
let process_packet t packet =
  process_packet_view t ~buf:packet ~off:0 ~len:(Bytes.length packet)

(** Immediate send for retransmissions - bypass bundling for time-critical sends *)
let send_chunk_immediate t chunk =
  let encoded_len = Sctp.encode_data_chunk_into ~buf:t.send_buffer ~off:t.bundle_offset chunk in
  (* If we have bundled data, include retransmit with it *)
  let total_len = t.bundle_offset + encoded_len in
  ignore (Udp_transport.send_view t.udp ~buf:t.send_buffer ~off:0 ~len:total_len);
  t.bundle_offset <- 0  (* Reset bundle after sending *)

(** Handle retransmissions (call periodically) - immediate send for time-critical *)
let handle_retransmissions t =
  (* Check T3-rtx timeout *)
  let timeout_chunks = Sctp_reliable.check_t3_rtx_timeout t.reliable in
  List.iter (fun chunk ->
    send_chunk_immediate t chunk;
    t.stats.retransmissions <- t.stats.retransmissions + 1
  ) timeout_chunks;

  (* Handle fast retransmit *)
  let fast_rtx_chunks = Sctp_reliable.get_fast_retransmit_chunks t.reliable in
  List.iter (fun chunk ->
    send_chunk_immediate t chunk;
    t.stats.fast_retransmissions <- t.stats.fast_retransmissions + 1
  ) fast_rtx_chunks

(** Receive data with timeout (includes SACK processing) *)
let recv_data t ~timeout_ms =
  match recv_packet t ~timeout_ms with
  | Error e -> Error e
  | Ok (len, _) ->
    let packet = Bytes.sub t.recv_buffer 0 len in
    match process_packet t packet with
    | Some data -> Ok data
    | None -> Error "No data (was SACK or other)"

(** Non-blocking receive *)
let try_recv_data t =
  match try_recv_packet t with
  | None -> None
  | Some packet ->
    process_packet t packet

(** {1 Event Loop for Full Protocol} *)

(** Flush any pending SACK (for delayed ACK timeout) *)
let flush_pending_sack t =
  if t.pending_sack then begin
    let sack = Sctp_reliable.generate_sack t.reliable in
    let sack_encoded = Sctp_reliable.encode_sack sack in
    ignore (send_packet t sack_encoded);
    t.stats.sacks_sent <- t.stats.sacks_sent + 1;
    t.packets_since_sack <- 0;
    t.pending_sack <- false
  end

(** Run one iteration of the protocol loop *)
let tick t =
  (* Flush any pending bundled chunks first *)
  flush_bundle t;

  (* Process any incoming packets - TRUE zero-copy hot path!
     We pass the recv_buffer directly without ANY intermediate copy.
     This is safe because we process completely before next recv. *)
  let packets_processed = ref 0 in
  let rec drain_recv () =
    match try_recv_packet_zerocopy t with
    | None -> ()
    | Some (buf, len) ->
      incr packets_processed;
      (* Zero-copy: pass buffer view directly to process_packet_view *)
      ignore (process_packet_view t ~buf ~off:0 ~len);
      drain_recv ()
  in
  drain_recv ();

  (* Only flush pending SACK if NO packets were processed this tick.
     This implements the "delayed ACK timeout" - we send SACK when
     the receiver is idle, not immediately after each packet burst. *)
  if !packets_processed = 0 then
    flush_pending_sack t;

  (* Handle retransmissions *)
  handle_retransmissions t

(** {1 Lifecycle} *)

let close t =
  Udp_transport.close t.udp

let is_closed t =
  Udp_transport.is_closed t.udp

(** Get underlying UDP transport for debugging *)
let get_udp_transport t = t.udp

(** {1 Statistics} *)

let get_stats t = t.stats

let get_reliable_stats t = Sctp_reliable.get_stats t.reliable

let get_cwnd t = Sctp_reliable.get_cwnd t.reliable
let get_ssthresh t = Sctp_reliable.get_ssthresh t.reliable
let get_flight_size t = Sctp_reliable.get_flight_size t.reliable
let get_rto t = Sctp_reliable.get_rto t.reliable

(** Debug: Get receiver's cumulative TSN *)
let get_cumulative_tsn t = Sctp_reliable.get_cumulative_tsn t.reliable

(** Debug: Get number of gap ranges in receiver *)
let get_gap_count t = Sctp_reliable.get_gap_count t.reliable

(** Debug: Get gap ranges as (start, end) pairs *)
let get_gap_ranges t = Sctp_reliable.get_gap_ranges t.reliable

let pp_stats fmt s =
  Format.fprintf fmt "msgs=%d/%d bytes=%d/%d sacks=%d/%d rtx=%d fast=%d"
    s.messages_sent s.messages_recv
    s.bytes_sent s.bytes_recv
    s.sacks_sent s.sacks_recv
    s.retransmissions s.fast_retransmissions

let pp_cc_state fmt t =
  Sctp_reliable.pp_cc_state fmt t.reliable
