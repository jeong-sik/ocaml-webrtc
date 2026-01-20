(** Sans-IO SCTP State Machine - Pure Protocol Logic

    Implements RFC 4960 SCTP as a pure state machine with no I/O.
    Follows the Sans-IO pattern from str0m (Rust WebRTC):
    - Input: Events from the outside world
    - Output: Actions for the I/O layer to execute
    - State: Pure, deterministic state transitions

    This architecture enables:
    - Unit testing without mocking
    - Deterministic behavior
    - Memory efficiency (str0m: 10MB for 1000 connections)

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** {1 Timer Types} *)

type timer_id =
  | T3Rtx           (** Retransmission timeout (RFC 4960 §6.3) *)
  | DelayedAck      (** Delayed acknowledgment (RFC 4960 §6.2) *)
  | Heartbeat       (** Path heartbeat (RFC 4960 §8.3) *)
  | Shutdown        (** Shutdown timer *)

(** {1 Input Events} *)

type input =
  | PacketReceived of bytes                 (** Incoming UDP packet *)
  | TimerFired of timer_id                  (** A timer expired *)
  | UserSend of { stream_id: int; data: bytes }  (** App wants to send *)
  | UserResetStreams of { stream_ids: int list } (** Request stream reset (RFC 6525) *)
  | UserClose                               (** App requests shutdown *)

(** {1 Output Actions} *)

type output =
  | SendPacket of bytes                     (** Send this UDP packet *)
  | DeliverData of { stream_id: int; data: bytes }  (** Deliver to app *)
  | SetTimer of { timer: timer_id; delay_ms: float }  (** Set a timer *)
  | CancelTimer of timer_id                 (** Cancel a timer *)
  | ConnectionEstablished                   (** Notify app: connected *)
  | ConnectionClosed                        (** Notify app: closed *)
  | Error of string                         (** Notify app: error *)

(** {1 Connection State} *)

type conn_state =
  | Closed
  | CookieWait      (** Sent INIT, waiting for INIT-ACK *)
  | CookieEchoed    (** Sent COOKIE-ECHO, waiting for COOKIE-ACK *)
  | Established
  | ShutdownPending (** App requested close, draining *)
  | ShutdownSent    (** Sent SHUTDOWN, waiting for SHUTDOWN-ACK *)
  | ShutdownReceived
  | ShutdownAckSent

(** {1 Statistics - Mutable Counters}

    Using mutable ints for maximum single-threaded performance.
    For future Domain-parallel RX, use domain-local mutable stats
    with periodic aggregation rather than Atomics on the hot path.

    Design decision: Atomics add ~18% overhead (memory barriers on every
    packet). Domain-local counters achieve parallelism without this cost.
*)

(** Internal mutable stats for efficient single-threaded updates.
    Note: For Domain-parallel RX (future), use domain-local mutable stats
    with periodic aggregation rather than Atomics on the hot path. *)
type mutable_stats = {
  mutable ms_messages_sent: int;
  mutable ms_messages_recv: int;
  mutable ms_bytes_sent: int;
  mutable ms_bytes_recv: int;
  mutable ms_sacks_sent: int;
  mutable ms_sacks_recv: int;
  mutable ms_retransmissions: int;
  mutable ms_fast_retransmissions: int;
}

(** External stats snapshot for API compatibility.
    Immutable copy returned to callers. *)
type stats = {
  messages_sent: int;
  messages_recv: int;
  bytes_sent: int;
  bytes_recv: int;
  sacks_sent: int;
  sacks_recv: int;
  retransmissions: int;
  fast_retransmissions: int;
}

(** {1 Security Warnings} *)

(** Track if checksum bypass warning was shown (warn once) *)
let checksum_bypass_warned = ref false

(** {1 Core State} *)

type reset_target =
  | Reset_incoming
  | Reset_outgoing

type pending_reset = {
  request_seq: int32;
  last_tsn: int32;
  streams: int list;
  target: reset_target;
}

type t = {
  (* Connection *)
  mutable conn_state: conn_state;
  mutable my_vtag: int32;         (** Our verification tag *)
  mutable peer_vtag: int32;       (** Peer's verification tag *)

  (* Handshake state (RFC 4960 §5 4-way handshake) *)
  mutable handshake_params: Sctp_handshake.init_params option;

  (* Reliability layer - delegates to existing sctp_reliable *)
  reliable: Sctp_reliable.t;
  config: Sctp.config;

  (* Stream sequencing *)
  mutable stream_seq_out: (int, int) Hashtbl.t;
  mutable stream_seq_in: (int, int) Hashtbl.t;
  mutable reconfig_request_seq: int32;
  mutable pending_outgoing_resets: (int32, int list) Hashtbl.t;
  mutable pending_incoming_resets: (int32, pending_reset) Hashtbl.t;

  (* Delayed ACK state (RFC 4960 §6.2) *)
  mutable packets_since_sack: int;
  mutable pending_sack: bool;

  (* Heartbeat state (RFC 4960 §8.3) *)
  heartbeat: Sctp_heartbeat.t;

  (* Chunk bundling (RFC 4960 §6.10) *)
  bundler: Sctp_bundling.t;
  src_port: int;
  dst_port: int;

  (* Statistics *)
  stats: mutable_stats;

  (* Current time for deterministic testing *)
  mutable now: float;

  (* Batch output gathering (webrtc-rs pattern) *)
  mutable pending_outputs: output list;  (** Non-SendPacket outputs *)
  mutable pending_sack_chunk: bytes option;  (** SACK to bundle with next DATA *)
}

(** {1 Creation} *)

let create_stats () : mutable_stats = {
  ms_messages_sent = 0;
  ms_messages_recv = 0;
  ms_bytes_sent = 0;
  ms_bytes_recv = 0;
  ms_sacks_sent = 0;
  ms_sacks_recv = 0;
  ms_retransmissions = 0;
  ms_fast_retransmissions = 0;
}

(** Take an immutable snapshot of mutable stats *)
let snapshot_stats (s : mutable_stats) : stats = {
  messages_sent = s.ms_messages_sent;
  messages_recv = s.ms_messages_recv;
  bytes_sent = s.ms_bytes_sent;
  bytes_recv = s.ms_bytes_recv;
  sacks_sent = s.ms_sacks_sent;
  sacks_recv = s.ms_sacks_recv;
  retransmissions = s.ms_retransmissions;
  fast_retransmissions = s.ms_fast_retransmissions;
}

(** Create a new SCTP state machine.
    @param config SCTP configuration
    @param initial_tsn Override random TSN for testing
    @param my_vtag Our verification tag (random in production)
    @param peer_vtag Peer's verification tag (from handshake)
    @param src_port Source port for bundled packets
    @param dst_port Destination port for bundled packets *)
let create
    ?(config = Sctp.default_config)
    ?initial_tsn
    ?(my_vtag = Random.int32 0x7FFFFFFFl)
    ?(peer_vtag = 0l)
    ?(src_port = 5000)
    ?(dst_port = 5000)
    () =
  {
    conn_state = Closed;
    my_vtag;
    peer_vtag;
    handshake_params = None;
    reliable = Sctp_reliable.create ~config ?initial_tsn ();
    config;
    stream_seq_out = Hashtbl.create 16;
    stream_seq_in = Hashtbl.create 16;
    reconfig_request_seq = 1l;
    pending_outgoing_resets = Hashtbl.create 8;
    pending_incoming_resets = Hashtbl.create 8;
    packets_since_sack = 0;
    pending_sack = false;
    heartbeat = Sctp_heartbeat.create ();
    bundler = Sctp_bundling.create ~mtu:config.mtu ();
    src_port;
    dst_port;
    stats = create_stats ();
    now = 0.0;
    pending_outputs = [];
    pending_sack_chunk = None;
  }

(** {1 Internal Helpers} *)

(** Get next stream sequence number for a stream *)
let next_stream_seq t stream_id =
  let current = match Hashtbl.find_opt t.stream_seq_out stream_id with
    | Some v -> v
    | None -> 0
  in
  Hashtbl.replace t.stream_seq_out stream_id (current + 1);
  current

(** Track incoming stream sequence number (best-effort) *)
let record_stream_seq_in t stream_id stream_seq =
  Hashtbl.replace t.stream_seq_in stream_id (stream_seq + 1)

(** Reset stream sequence number (RFC 6525) *)
let reset_stream_seq_out t stream_id =
  Hashtbl.replace t.stream_seq_out stream_id 0

let reset_stream_seq_in t stream_id =
  Hashtbl.replace t.stream_seq_in stream_id 0

let apply_stream_reset t target streams =
  let reset =
    match target with
    | Reset_incoming -> reset_stream_seq_in
    | Reset_outgoing -> reset_stream_seq_out
  in
  List.iter (reset t) streams

let reconfig_ready t last_tsn =
  let cumulative = Sctp_reliable.get_cumulative_tsn t.reliable in
  Sctp_reliable.tsn_le last_tsn cumulative

let build_reconfig_response request_seq result =
  Sctp_reconfig.Reconfig_response { response_seq = request_seq; result }

let schedule_pending_reset t target request_seq last_tsn streams =
  Hashtbl.replace t.pending_incoming_resets request_seq {
    request_seq;
    last_tsn;
    streams;
    target;
  }

(** Build RE-CONFIG packet with given parameters *)
let build_reconfig_packet t params =
  let raw = Sctp_reconfig.to_raw_chunk params in
  let packet = Sctp.encode_packet {
    Sctp.header = {
      source_port = t.src_port;
      dest_port = t.dst_port;
      verification_tag = t.peer_vtag;
      checksum = 0l;
    };
    chunks = [raw];
  } in
  packet

(** Process RE-CONFIG parameters and build responses when needed *)
let process_reconfig_params t params =
  let responses = ref [] in
  List.iter (function
    | Sctp_reconfig.Outgoing_ssn_reset { request_seq; streams; last_tsn; _ } ->
      if reconfig_ready t last_tsn then begin
        apply_stream_reset t Reset_incoming streams;
        responses := build_reconfig_response request_seq Sctp_reconfig.result_success :: !responses
      end else begin
        schedule_pending_reset t Reset_incoming request_seq last_tsn streams;
        responses := build_reconfig_response request_seq Sctp_reconfig.result_in_progress :: !responses
      end
    | Sctp_reconfig.Incoming_ssn_reset { request_seq; streams; last_tsn; _ } ->
      if reconfig_ready t last_tsn then begin
        apply_stream_reset t Reset_outgoing streams;
        responses := build_reconfig_response request_seq Sctp_reconfig.result_success :: !responses
      end else begin
        schedule_pending_reset t Reset_outgoing request_seq last_tsn streams;
        responses := build_reconfig_response request_seq Sctp_reconfig.result_in_progress :: !responses
      end
    | Sctp_reconfig.Add_outgoing_streams { request_seq; _ } ->
      responses := build_reconfig_response request_seq Sctp_reconfig.result_success :: !responses
    | Sctp_reconfig.Add_incoming_streams { request_seq; _ } ->
      responses := build_reconfig_response request_seq Sctp_reconfig.result_success :: !responses
    | Sctp_reconfig.Reconfig_response { response_seq; result } ->
      begin match Hashtbl.find_opt t.pending_outgoing_resets response_seq with
      | None -> ()
      | Some streams ->
        if result = Sctp_reconfig.result_success then begin
          apply_stream_reset t Reset_outgoing streams;
          Hashtbl.remove t.pending_outgoing_resets response_seq
        end else if result <> Sctp_reconfig.result_in_progress then
          Hashtbl.remove t.pending_outgoing_resets response_seq
      end
    | Sctp_reconfig.Unknown _ ->
      ()
  ) params;
  match List.rev !responses with
  | [] -> []
  | resp_params ->
    let packet = build_reconfig_packet t resp_params in
    [SendPacket packet]

let flush_pending_reconfigs t =
  let ready = ref [] in
  Hashtbl.iter (fun _ pending ->
    if reconfig_ready t pending.last_tsn then
      ready := pending :: !ready
  ) t.pending_incoming_resets;
  match List.rev !ready with
  | [] -> []
  | pendings ->
    let responses = ref [] in
    List.iter (fun pending ->
      apply_stream_reset t pending.target pending.streams;
      Hashtbl.remove t.pending_incoming_resets pending.request_seq;
      responses := build_reconfig_response pending.request_seq Sctp_reconfig.result_success :: !responses
    ) pendings;
    let packet = build_reconfig_packet t (List.rev !responses) in
    [SendPacket packet]

(** Process a DATA chunk, return output actions *)
let process_data_chunk t chunk =
  let is_new = Sctp_reliable.record_received t.reliable chunk.Sctp.tsn in
  let outputs = ref [] in

  if is_new then begin
    (* Only count unique messages *)
    t.stats.ms_messages_recv <- t.stats.ms_messages_recv + 1;
    t.stats.ms_bytes_recv <- t.stats.ms_bytes_recv + Bytes.length chunk.Sctp.user_data;

    (* Track incoming stream sequence for resets *)
    record_stream_seq_in t chunk.Sctp.stream_id chunk.Sctp.stream_seq;

    (* Deliver to application *)
    outputs := DeliverData {
      stream_id = chunk.Sctp.stream_id;
      data = chunk.Sctp.user_data;
    } :: !outputs
  end;

  (* Delayed ACK - RFC 4960 §6.2 *)
  t.packets_since_sack <- t.packets_since_sack + 1;
  if t.packets_since_sack >= 2 then begin
    (* Generate SACK for batch bundling (webrtc-rs pattern) *)
    let sack = Sctp_reliable.generate_sack t.reliable in
    let sack_encoded = Sctp_reliable.encode_sack sack in
    (* Store for bundling with next outgoing DATA instead of immediate send *)
    t.pending_sack_chunk <- Some sack_encoded;
    t.stats.ms_sacks_sent <- t.stats.ms_sacks_sent + 1;
    t.packets_since_sack <- 0;
    t.pending_sack <- false
  end else begin
    t.pending_sack <- true;
    (* Set delayed ACK timer (200ms max per RFC 4960) *)
    outputs := SetTimer { timer = DelayedAck; delay_ms = 200.0 } :: !outputs
  end;

  (* Apply any pending stream resets once last_tsn is satisfied *)
  let pending_outputs = flush_pending_reconfigs t in
  outputs := List.rev_append pending_outputs !outputs;

  List.rev !outputs

(** Process a SACK chunk *)
let process_sack_chunk t sack =
  Sctp_reliable.process_sack t.reliable sack;
  t.stats.ms_sacks_recv <- t.stats.ms_sacks_recv + 1;

  let outputs = ref [] in

  (* Cancel T3-rtx if all data acknowledged *)
  if Sctp_reliable.all_acked t.reliable then
    outputs := CancelTimer T3Rtx :: !outputs;

  (* RFC 4960 §9.2: If ShutdownPending and all data acked, send SHUTDOWN *)
  if t.conn_state = ShutdownPending && Sctp_reliable.get_flight_size t.reliable = 0 then begin
    t.conn_state <- ShutdownSent;
    let cumulative_tsn = Sctp_reliable.get_cumulative_tsn t.reliable in
    let shutdown_chunk = Sctp_shutdown.encode_shutdown { cumulative_tsn_ack = cumulative_tsn } in
    let rto = Sctp_reliable.get_rto t.reliable in
    outputs := SetTimer { timer = Shutdown; delay_ms = rto *. 1000.0 } :: !outputs;
    outputs := SendPacket shutdown_chunk :: !outputs
  end;

  List.rev !outputs

(** Process a single chunk at given offset, return (outputs, next_offset) *)
let process_single_chunk t packet offset =
  let packet_len = Bytes.length packet in
  if offset + 4 > packet_len then
    ([], packet_len)  (* Not enough for chunk header *)
  else begin
    let chunk_type = Bytes.get packet offset |> Char.code in
    let chunk_flags = Bytes.get packet (offset + 1) |> Char.code in
    let chunk_len = Bytes.get_uint16_be packet (offset + 2) in
    let padded_len = (chunk_len + 3) land (lnot 3) in  (* 4-byte alignment *)

    (* Extract chunk bytes *)
    let chunk_data =
      if offset + chunk_len <= packet_len then
        Bytes.sub packet offset chunk_len
      else
        Bytes.sub packet offset (packet_len - offset)
    in

    let outputs = match chunk_type with
    | 0 -> (* DATA chunk *)
      begin match Sctp.decode_data_chunk chunk_data with
      | Ok chunk -> process_data_chunk t chunk
      | Error e -> [Error ("DATA decode: " ^ e)]
      end

    | 3 -> (* SACK chunk *)
      begin match Sctp_reliable.decode_sack chunk_data with
      | Ok sack -> process_sack_chunk t sack
      | Error e -> [Error ("SACK decode: " ^ e)]
      end

    | 1 -> (* INIT - we're server - RFC 4960 §5.1 *)
      begin match Sctp_handshake.server_process_init chunk_data with
      | Ok (_local_params, init_ack) ->
        (* Server remains STATELESS - cookie holds all state *)
        let bundle = { Sctp_bundling.chunks = [init_ack]; total_size = Bytes.length init_ack } in
        let packet = Sctp_bundling.assemble_packet
          ~vtag:0l  (* INIT-ACK also uses vtag=0 until cookie verified *)
          ~src_port:t.src_port
          ~dst_port:t.dst_port
          bundle
        in
        [SendPacket packet]
      | Error e -> [Error ("INIT processing: " ^ e)]
      end

    | 2 -> (* INIT-ACK - we're client - RFC 4960 §5.1 *)
      begin match t.handshake_params with
      | None -> [Error "Received INIT-ACK but no handshake in progress"]
      | Some local_params ->
        begin match Sctp_handshake.client_process_init_ack chunk_data local_params with
        | Ok (assoc, cookie_echo) ->
          (* Update our state with association info *)
          t.peer_vtag <- assoc.Sctp_handshake.peer_vtag;
          t.conn_state <- CookieEchoed;
          let bundle = { Sctp_bundling.chunks = [cookie_echo]; total_size = Bytes.length cookie_echo } in
          let packet = Sctp_bundling.assemble_packet
            ~vtag:t.peer_vtag
            ~src_port:t.src_port
            ~dst_port:t.dst_port
            bundle
          in
          [SendPacket packet]
        | Error e -> [Error ("INIT-ACK processing: " ^ e)]
        end
      end

    | 10 -> (* COOKIE-ECHO - we're server - RFC 4960 §5.1 *)
      begin match Sctp_handshake.server_process_cookie_echo chunk_data with
      | Ok (assoc, cookie_ack) ->
        (* Server creates association state from cookie *)
        t.my_vtag <- assoc.Sctp_handshake.local_vtag;
        t.peer_vtag <- assoc.Sctp_handshake.peer_vtag;
        t.conn_state <- Established;
        let bundle = { Sctp_bundling.chunks = [cookie_ack]; total_size = Bytes.length cookie_ack } in
        let packet = Sctp_bundling.assemble_packet
          ~vtag:t.peer_vtag
          ~src_port:t.src_port
          ~dst_port:t.dst_port
          bundle
        in
        [SendPacket packet; ConnectionEstablished]
      | Error e -> [Error ("COOKIE-ECHO processing: " ^ e)]
      end

    | 11 -> (* COOKIE-ACK - we're client - RFC 4960 §5.1 *)
      if t.conn_state = CookieEchoed then begin
        t.conn_state <- Established;
        [ConnectionEstablished]
      end else
        [Error "Received COOKIE-ACK in unexpected state"]

    | 4 -> (* HEARTBEAT *)
      begin match Sctp_heartbeat.process_heartbeat chunk_data with
      | Ok ack_packet -> [SendPacket ack_packet]
      | Error _ -> []
      end

    | 5 -> (* HEARTBEAT-ACK *)
      []

    | 6 -> (* ABORT - RFC 4960 §9.1 *)
      (* Peer is aborting the association - immediate termination *)
      t.conn_state <- Closed;
      let t_bit = (Char.code (Bytes.get chunk_data 1) land 1) = 1 in
      (* Extract error causes if present *)
      let error_msg =
        if Bytes.length chunk_data > 4 then
          Printf.sprintf "Association aborted by peer (T-bit=%b, %d error cause bytes)"
            t_bit (Bytes.length chunk_data - 4)
        else
          Printf.sprintf "Association aborted by peer (T-bit=%b)" t_bit
      in
      [Error error_msg; ConnectionClosed]

    | 9 -> (* ERROR - RFC 4960 §3.3.10 *)
      (* Peer is reporting an error condition - don't abort, just log *)
      let num_causes = (Bytes.length chunk_data - 4) / 4 in
      let error_msg = Printf.sprintf "Peer reported %d error cause(s)" num_causes in
      [Error error_msg]

    | 7 -> (* SHUTDOWN - RFC 4960 §9.2 *)
      begin match Sctp_shutdown.decode_shutdown chunk_data with
      | Ok _shutdown ->
        t.conn_state <- ShutdownReceived;
        (* Send SHUTDOWN-ACK in response *)
        let ack = Sctp_shutdown.encode_shutdown_ack () in
        t.conn_state <- ShutdownAckSent;
        [SendPacket ack]
      | Error _ -> []
      end

    | 8 -> (* SHUTDOWN-ACK - RFC 4960 §9.2 *)
      begin match Sctp_shutdown.decode_shutdown_ack chunk_data with
      | Ok () ->
        (* Send SHUTDOWN-COMPLETE to finalize *)
        let complete = Sctp_shutdown.encode_shutdown_complete ~t_bit:false in
        t.conn_state <- Closed;
        [SendPacket complete; CancelTimer Shutdown; ConnectionClosed]
      | Error _ -> []
      end

    | 14 -> (* SHUTDOWN-COMPLETE - RFC 4960 §9.2 *)
      begin match Sctp_shutdown.decode_shutdown_complete chunk_data with
      | Ok _t_bit ->
        t.conn_state <- Closed;
        [CancelTimer Shutdown; ConnectionClosed]
      | Error _ -> []
      end

    | chunk_type_id when chunk_type_id = Sctp.int_of_chunk_type Sctp.RE_CONFIG ->
      let value_len = max 0 (Bytes.length chunk_data - 4) in
      let chunk_value = Bytes.sub chunk_data 4 value_len in
      let raw = { Sctp.chunk_type; chunk_flags; chunk_length = chunk_len; chunk_value } in
      (match Sctp_reconfig.of_raw_chunk raw with
      | Ok params -> process_reconfig_params t params
      | Error e -> [Error ("RE-CONFIG decode: " ^ e)])

    | _ ->
      (* RFC 4960 §3.2 - Handle unknown chunk based on upper 2 bits *)
      let action = Sctp_error.action_for_unknown_chunk chunk_type in
      begin match action with
      | Sctp_error.StopDiscard ->
        (* 00: Stop processing this packet, discard silently *)
        (* Note: Caller should check for StopProcessing output *)
        [Error (Printf.sprintf "Unknown chunk type %d (action=stop-discard)" chunk_type)]
      | Sctp_error.StopDiscardReport ->
        (* 01: Stop processing, send ERROR with unrecognized chunk *)
        let error_chunk = Sctp_error.make_unrecognized_chunk_error ~unrecognized_chunk:chunk_data in
        [SendPacket error_chunk; Error (Printf.sprintf "Unknown chunk type %d (action=stop-report)" chunk_type)]
      | Sctp_error.SkipContinue ->
        (* 10: Skip this chunk, continue processing (most common) *)
        []
      | Sctp_error.SkipContinueReport ->
        (* 11: Skip, continue, but report in ERROR chunk *)
        let error_chunk = Sctp_error.make_unrecognized_chunk_error ~unrecognized_chunk:chunk_data in
        [SendPacket error_chunk]
      end
    in
    (outputs, offset + padded_len)
  end

(** Process incoming SCTP packet (RFC 4960 compliant)
    Packet format: Common Header (12 bytes) + Chunks
    Common Header: src_port(2) + dst_port(2) + vtag(4) + checksum(4) *)
let process_packet t packet =
  let packet_len = Bytes.length packet in

  (* Check for legacy chunk-only format (backward compatibility) *)
  if packet_len >= 4 && packet_len < 12 then begin
    (* Too small for SCTP header, assume chunk-only format *)
    let (outputs, _) = process_single_chunk t packet 0 in
    outputs
  end
  else if packet_len < 12 then
    [Error "Packet too short for SCTP header"]
  else begin
    (* Check if this looks like an SCTP header or a raw chunk *)
    let first_byte = Bytes.get packet 0 |> Char.code in

    (* Heuristic: if first byte is a valid chunk type (0-14), it's likely chunk-only.
       If it looks like a port number byte (typically > 14 for WebRTC), it's SCTP header. *)
    if first_byte <= 14 && packet_len < 100 then begin
      (* Likely chunk-only format for backward compatibility *)
      let (outputs, _) = process_single_chunk t packet 0 in
      outputs
    end
    else begin
      (* Parse SCTP Common Header (RFC 4960 §3.1) *)
      let _src_port = Bytes.get_uint16_be packet 0 in
      let _dst_port = Bytes.get_uint16_be packet 2 in
      let vtag = Bytes.get_int32_be packet 4 in
      let received_checksum = Bytes.get_int32_be packet 8 in

      (* Verify Verification Tag (RFC 4960 §8.5)
         Accept packets with:
         - vtag = peer_vtag (normal data packets, COOKIE-ECHO)
         - vtag = my_vtag (responses to us: COOKIE-ACK, some INIT-ACK)
         - vtag = 0 (INIT packets)
         - peer_vtag = 0 (handshake in progress, not yet learned peer's vtag) *)
      let vtag_valid =
        vtag = t.peer_vtag ||       (* Normal data *)
        vtag = t.my_vtag ||         (* Responses addressed to us *)
        vtag = 0l ||                (* INIT has vtag=0 *)
        t.peer_vtag = 0l            (* Handshake: peer_vtag not yet set *)
      in
      if not vtag_valid then
        [Error (Printf.sprintf "Vtag mismatch: got %ld, peer=%ld, my=%ld" vtag t.peer_vtag t.my_vtag)]
      else begin
        (* Verify CRC32c checksum (RFC 4960 Appendix B) - In-place, no copy *)
        let verify_checksum =
          if t.config.skip_checksum_validation then begin
            (* TESTING ONLY: Skip checksum validation - warn once *)
            if not !checksum_bypass_warned then begin
              Printf.eprintf "[SECURITY WARNING] Checksum validation disabled - TESTING ONLY!\n%!";
              checksum_bypass_warned := true
            end;
            true
          end
          else begin
            (* Save original checksum, zero it, calculate, restore *)
            Bytes.set_int32_be packet 8 0l;
            let calculated = Webrtc_common.crc32c packet in
            Bytes.set_int32_be packet 8 received_checksum;  (* Restore *)
            calculated = received_checksum
          end
        in
        if not verify_checksum then
          [Error (Printf.sprintf "CRC32c mismatch")]
        else begin
          (* Process all chunks starting at offset 12 *)
          let rec process_chunks offset acc =
            if offset >= packet_len then
              List.rev acc
            else
              let (outputs, next_offset) = process_single_chunk t packet offset in
              process_chunks next_offset (List.rev_append outputs acc)
          in
          process_chunks 12 []
        end
      end
    end
  end

(** Flush pending bundle to a SendPacket output *)
let flush_bundle t =
  match Sctp_bundling.flush t.bundler with
  | Some bundle ->
    let packet = Sctp_bundling.assemble_packet
      ~vtag:t.peer_vtag
      ~src_port:t.src_port
      ~dst_port:t.dst_port
      bundle
    in
    [SendPacket packet]
  | None -> []

(** Queue user data for sending - with chunk bundling (RFC 4960 §6.10)
    Now includes SACK bundling for batch efficiency (webrtc-rs pattern) *)
let queue_user_data t ~stream_id ~data =
  if not (Sctp_reliable.can_send t.reliable) then
    [Error "Congestion window full"]
  else begin
    let outputs = ref [] in
    let data_len = Bytes.length data in

    (* Bundle pending SACK with DATA - reduces packet count *)
    begin match t.pending_sack_chunk with
    | Some sack_chunk ->
      ignore (Sctp_bundling.add_chunk t.bundler sack_chunk);
      t.pending_sack_chunk <- None
    | None -> ()
    end;

    (* Fragment if needed *)
    let tsn = Sctp_reliable.alloc_tsn t.reliable in
    let stream_seq = next_stream_seq t stream_id in
    let chunks = Sctp.fragment_data
      ~data
      ~stream_id
      ~stream_seq
      ~ppid:0x32l
      ~start_tsn:tsn
      ~mtu:t.config.mtu
    in

    (* Queue and bundle each chunk *)
    List.iter (fun chunk ->
      Sctp_reliable.queue_data t.reliable chunk;
      let encoded = Sctp.encode_data_chunk chunk in

      (* Add to bundler - flush if full *)
      match Sctp_bundling.add_chunk t.bundler encoded with
      | Some bundle ->
        (* Bundle is full, assemble and send *)
        let packet = Sctp_bundling.assemble_packet
          ~vtag:t.peer_vtag
          ~src_port:t.src_port
          ~dst_port:t.dst_port
          bundle
        in
        outputs := SendPacket packet :: !outputs
      | None -> ()  (* Chunk added, waiting for more *)
    ) chunks;

    t.stats.ms_messages_sent <- t.stats.ms_messages_sent + 1;
    t.stats.ms_bytes_sent <- t.stats.ms_bytes_sent + data_len;

    (* Flush any remaining bundled chunks *)
    let flush_outputs = flush_bundle t in
    outputs := List.rev_append flush_outputs !outputs;

    (* Set T3-rtx timer if not already running *)
    let rto = Sctp_reliable.get_rto t.reliable in
    outputs := SetTimer { timer = T3Rtx; delay_ms = rto *. 1000.0 } :: !outputs;

    List.rev !outputs
  end

(** Handle T3-rtx timeout - retransmit unacked data *)
let handle_t3_rtx_timeout t =
  let chunks = Sctp_reliable.check_t3_rtx_timeout t.reliable in
  let outputs = ref [] in

  List.iter (fun chunk ->
    let encoded = Sctp.encode_data_chunk chunk in
    outputs := SendPacket encoded :: !outputs;
    t.stats.ms_retransmissions <- t.stats.ms_retransmissions + 1
  ) chunks;

  (* Reset T3-rtx timer *)
  if List.length chunks > 0 then begin
    let rto = Sctp_reliable.get_rto t.reliable in
    outputs := SetTimer { timer = T3Rtx; delay_ms = rto *. 1000.0 } :: !outputs
  end;

  List.rev !outputs

(** Handle delayed ACK timeout - flush pending SACK *)
let handle_delayed_ack_timeout t =
  if t.pending_sack then begin
    let sack = Sctp_reliable.generate_sack t.reliable in
    let sack_encoded = Sctp_reliable.encode_sack sack in
    t.stats.ms_sacks_sent <- t.stats.ms_sacks_sent + 1;
    t.packets_since_sack <- 0;
    t.pending_sack <- false;
    [SendPacket sack_encoded]
  end else
    []

(** Handle heartbeat timeout - send heartbeat *)
let handle_heartbeat_timeout t =
  let encoded = Sctp_heartbeat.generate_heartbeat t.heartbeat ~path_id:0 in
  [
    SendPacket encoded;
    SetTimer { timer = Heartbeat; delay_ms = 30000.0 }  (* 30s interval *)
  ]

(** {1 Batch Output Gathering (webrtc-rs pattern)} *)

(** Flush all pending transmissions - call after processing multiple inputs.
    This implements the webrtc-rs "poll_transmit" pattern for batch efficiency.

    Benefits:
    - Reduces syscall overhead (fewer send() calls)
    - Bundles SACK with DATA when possible
    - Minimizes packet count on wire

    @return List of SendPacket outputs ready to transmit *)
let poll_transmit t =
  let outputs = ref [] in

  (* Flush pending SACK if not bundled with DATA *)
  begin match t.pending_sack_chunk with
  | Some sack_chunk ->
    (* No outgoing DATA to bundle with - send SACK alone *)
    let packet = Sctp_bundling.assemble_packet
      ~vtag:t.peer_vtag
      ~src_port:t.src_port
      ~dst_port:t.dst_port
      { Sctp_bundling.chunks = [sack_chunk]; total_size = Bytes.length sack_chunk + 12 }
    in
    outputs := SendPacket packet :: !outputs;
    t.pending_sack_chunk <- None
  | None -> ()
  end;

  (* Flush any pending bundled chunks *)
  begin match Sctp_bundling.flush t.bundler with
  | Some bundle ->
    let packet = Sctp_bundling.assemble_packet
      ~vtag:t.peer_vtag
      ~src_port:t.src_port
      ~dst_port:t.dst_port
      bundle
    in
    outputs := SendPacket packet :: !outputs
  | None -> ()
  end;

  List.rev !outputs

(** Check if there are pending transmissions
    @return true if poll_transmit would return non-empty list *)
let has_pending_transmit t =
  t.pending_sack_chunk <> None ||
  Sctp_bundling.pending_count t.bundler > 0

(** {1 Main State Machine} *)

(** The core Sans-IO function: process input, return outputs.
    This is a pure function with no side effects.

    @param t Current state (will be mutated)
    @param input Event to process
    @return List of output actions for I/O layer *)
let handle t input =
  match input with
  | PacketReceived packet ->
    process_packet t packet

  | TimerFired timer ->
    begin match timer with
    | T3Rtx -> handle_t3_rtx_timeout t
    | DelayedAck -> handle_delayed_ack_timeout t
    | Heartbeat -> handle_heartbeat_timeout t
    | Shutdown -> [Error "Shutdown timeout"]
    end

  | UserSend { stream_id; data } ->
    queue_user_data t ~stream_id ~data

  | UserResetStreams { stream_ids } ->
    if t.conn_state <> Established then
      [Error "RE-CONFIG requires Established state"]
    else
      let request_seq = t.reconfig_request_seq in
      t.reconfig_request_seq <- Int32.succ t.reconfig_request_seq;
      let last_tsn = Sctp_reliable.get_last_sent_tsn t.reliable in
      Hashtbl.replace t.pending_outgoing_resets request_seq stream_ids;
      let param = Sctp_reconfig.Outgoing_ssn_reset {
        request_seq;
        response_seq = 0l;
        last_tsn;
        streams = stream_ids;
      } in
      let packet = build_reconfig_packet t [param] in
      [SendPacket packet]

  | UserClose ->
    (* RFC 4960 §9.2: Graceful Shutdown *)
    if Sctp_reliable.get_flight_size t.reliable = 0 then begin
      (* No outstanding data - send SHUTDOWN immediately *)
      t.conn_state <- ShutdownSent;
      let cumulative_tsn = Sctp_reliable.get_cumulative_tsn t.reliable in
      let shutdown_chunk = Sctp_shutdown.encode_shutdown { cumulative_tsn_ack = cumulative_tsn } in
      let rto = Sctp_reliable.get_rto t.reliable in
      [SendPacket shutdown_chunk; SetTimer { timer = Shutdown; delay_ms = rto *. 1000.0 }]
    end else begin
      (* Data still in flight - enter pending state, wait for ACKs *)
      t.conn_state <- ShutdownPending;
      []
    end

(** {1 State Queries} *)

let get_conn_state t = t.conn_state
(** Get stats as a snapshot with regular int fields.
    This is preferred for external access - provides consistent view. *)
let get_stats t = snapshot_stats t.stats

(** Get raw atomic stats (for internal use or advanced scenarios) *)
let get_stats_raw t = t.stats
let is_established t = t.conn_state = Established
let can_send t = Sctp_reliable.can_send t.reliable

(** {1 Connection Initiation} *)

(** Initiate SCTP association (client side).

    RFC 4960 §5: Sends INIT chunk to start 4-way handshake.
    1. Build and send INIT chunk with our parameters
    2. Transition to CookieWait state
    3. Wait for INIT-ACK (processed in handle())

    @return SendPacket with INIT chunk wrapped in SCTP header *)
let initiate t =
  (* RFC 4960 §5.1: Generate INIT with random vtag and TSN *)
  let (params, init_chunk, _state) = Sctp_handshake.client_init () in

  (* Store our params for processing INIT-ACK later *)
  t.handshake_params <- Some params;
  t.my_vtag <- params.Sctp_handshake.initiate_tag;
  t.conn_state <- CookieWait;

  (* Wrap INIT chunk in SCTP packet header *)
  let bundle = { Sctp_bundling.chunks = [init_chunk]; total_size = Bytes.length init_chunk } in
  let packet = Sctp_bundling.assemble_packet
    ~vtag:0l  (* INIT uses vtag=0 - RFC 4960 §8.5.1 *)
    ~src_port:t.src_port
    ~dst_port:t.dst_port
    bundle
  in
  [SendPacket packet]

(** Initiate (legacy) - Direct Established for testing compatibility *)
let initiate_direct t =
  t.conn_state <- Established;
  [ConnectionEstablished]

(** Get congestion control state *)
let get_cwnd t = Sctp_reliable.get_cwnd t.reliable
let get_ssthresh t = Sctp_reliable.get_ssthresh t.reliable
let get_flight_size t = Sctp_reliable.get_flight_size t.reliable
let get_rto t = Sctp_reliable.get_rto t.reliable

(** {1 Time Management for Testing} *)

(** Set current time (for deterministic testing) *)
let set_now t now = t.now <- now

(** Get current time *)
let get_now t = t.now

(** {1 Pretty Printing} *)

let string_of_timer = function
  | T3Rtx -> "T3Rtx"
  | DelayedAck -> "DelayedAck"
  | Heartbeat -> "Heartbeat"
  | Shutdown -> "Shutdown"

let string_of_conn_state = function
  | Closed -> "Closed"
  | CookieWait -> "CookieWait"
  | CookieEchoed -> "CookieEchoed"
  | Established -> "Established"
  | ShutdownPending -> "ShutdownPending"
  | ShutdownSent -> "ShutdownSent"
  | ShutdownReceived -> "ShutdownReceived"
  | ShutdownAckSent -> "ShutdownAckSent"

let pp_output fmt = function
  | SendPacket p -> Format.fprintf fmt "SendPacket(%d bytes)" (Bytes.length p)
  | DeliverData { stream_id; data } ->
    Format.fprintf fmt "DeliverData(stream=%d, %d bytes)" stream_id (Bytes.length data)
  | SetTimer { timer; delay_ms } ->
    Format.fprintf fmt "SetTimer(%s, %.1fms)" (string_of_timer timer) delay_ms
  | CancelTimer timer ->
    Format.fprintf fmt "CancelTimer(%s)" (string_of_timer timer)
  | ConnectionEstablished -> Format.fprintf fmt "ConnectionEstablished"
  | ConnectionClosed -> Format.fprintf fmt "ConnectionClosed"
  | Error e -> Format.fprintf fmt "Error(%s)" e

(** Pretty print mutable stats (for debugging) *)
let pp_mutable_stats fmt (s : mutable_stats) =
  Format.fprintf fmt "msgs=%d/%d bytes=%d/%d sacks=%d/%d rtx=%d fast=%d"
    s.ms_messages_sent s.ms_messages_recv
    s.ms_bytes_sent s.ms_bytes_recv
    s.ms_sacks_sent s.ms_sacks_recv
    s.ms_retransmissions s.ms_fast_retransmissions

(** Pretty print stats snapshot *)
let pp_stats fmt (s : stats) =
  Format.fprintf fmt "msgs=%d/%d bytes=%d/%d sacks=%d/%d rtx=%d fast=%d"
    s.messages_sent s.messages_recv
    s.bytes_sent s.bytes_recv
    s.sacks_sent s.sacks_recv
    s.retransmissions s.fast_retransmissions
