(** ICE-DTLS-SCTP Transport - Full WebRTC DataChannel Stack

    Complete WebRTC DataChannel implementation with NAT traversal:
    {v
    ┌─────────────────────────────────────────┐
    │           Application (DataChannel)     │
    ├─────────────────────────────────────────┤
    │           DCEP (Channel Setup)          │
    ├─────────────────────────────────────────┤
    │           SCTP (Reliable Transport)     │
    ├─────────────────────────────────────────┤
    │           DTLS (Encryption)             │
    ├─────────────────────────────────────────┤
    │     >>>  ICE (NAT Traversal)  <<<       │  ← This module adds
    ├─────────────────────────────────────────┤
    │           UDP (Network)                 │
    └─────────────────────────────────────────┘
    v}

    Flow:
    - ICE gathers candidates and performs connectivity checks
    - Once nominated pair is established, DTLS handshake begins
    - After DTLS is established, SCTP association starts
    - DataChannels are created via DCEP

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

(** {1 Connection State} *)

type transport_state =
  | Disconnected
  | GatheringCandidates
  | ConnectingICE
  | HandshakingDTLS
  | AssociatingSCTP
  | Connected
  | Closed
  | Error of string

let string_of_state = function
  | Disconnected -> "Disconnected"
  | GatheringCandidates -> "GatheringCandidates"
  | ConnectingICE -> "ConnectingICE"
  | HandshakingDTLS -> "HandshakingDTLS"
  | AssociatingSCTP -> "AssociatingSCTP"
  | Connected -> "Connected"
  | Closed -> "Closed"
  | Error e -> Printf.sprintf "Error(%s)" e

(** {1 Configuration} *)

type config = {
  mtu: int;                          (** Max transmission unit *)
  sctp_port: int;                    (** SCTP port (default: 5000) *)
  is_controlling: bool;              (** ICE controlling role *)
  ice_servers: Ice.ice_server list;  (** STUN/TURN servers *)
  fingerprint: string option;        (** Expected peer certificate fingerprint *)
}

let default_config = {
  mtu = 1200;  (* Conservative for DTLS overhead *)
  sctp_port = 5000;
  is_controlling = true;
  ice_servers = [];
  fingerprint = None;
}

(** {1 Transport State} *)

type t = {
  config: config;
  ice: Ice.agent;                     (** ICE state machine *)
  dtls: Dtls.t;                       (** DTLS state machine *)
  sctp: Sctp_core.t;                  (** SCTP state machine *)
  dcep: Dcep.t;                       (** DataChannel establishment *)

  mutable state: transport_state;
  recv_buffer: bytes;

  (* SCTP handshake state *)
  mutable sctp_init_params: Sctp_handshake.init_params option;
  mutable sctp_association: Sctp_handshake.association option;

  (* Callbacks *)
  mutable on_local_candidate: (Ice.candidate -> unit) option;
  mutable on_channel_open: (int -> string -> unit) option;
  mutable on_channel_data: (int -> bytes -> unit) option;
  mutable on_channel_close: (int -> unit) option;
  mutable on_state_change: (transport_state -> unit) option;
  mutable on_error: (string -> unit) option;
}

(** {1 Creation} *)

let create ?(config = default_config) () =
  let ice_config = {
    Ice.default_config with
    role = if config.is_controlling then Ice.Controlling else Ice.Controlled;
    ice_servers = config.ice_servers;
  } in
  let ice = Ice.create ice_config in

  let dtls_config =
    if config.is_controlling then Dtls.default_client_config
    else Dtls.default_server_config
  in
  let dtls = Dtls.create dtls_config in
  let sctp = Sctp_core.create ~config:Sctp.default_config () in
  let dcep = Dcep.create ~is_client:config.is_controlling in
  {
    config;
    ice;
    dtls;
    sctp;
    dcep;
    state = Disconnected;
    recv_buffer = Bytes.create 65536;
    sctp_init_params = None;
    sctp_association = None;
    on_local_candidate = None;
    on_channel_open = None;
    on_channel_data = None;
    on_channel_close = None;
    on_state_change = None;
    on_error = None;
  }

(** {1 Callback Registration} *)

let on_local_candidate t f = t.on_local_candidate <- Some f
let on_channel_open t f = t.on_channel_open <- Some f
let on_channel_data t f = t.on_channel_data <- Some f
let on_channel_close t f = t.on_channel_close <- Some f
let on_state_change t f = t.on_state_change <- Some f
let on_error t f = t.on_error <- Some f

(** {1 State Transitions} *)

let set_state t new_state =
  if t.state <> new_state then begin
    t.state <- new_state;
    match t.on_state_change with
    | Some f -> f new_state
    | None -> ()
  end

let set_error t msg =
  set_state t (Error msg);
  match t.on_error with
  | Some f -> f msg
  | None -> ()

(** {1 ICE Candidate Handling} *)

(** Get local ICE credentials *)
let get_local_ufrag t = t.ice.Ice.local_ufrag
let get_local_pwd t = t.ice.Ice.local_pwd

(** Get local candidates *)
let get_local_candidates t = Ice.get_local_candidates t.ice

(** Add remote ICE candidate *)
let add_remote_candidate t candidate =
  Ice.add_remote_candidate t.ice candidate

(** Set remote ICE credentials *)
let set_remote_credentials t ~ufrag ~pwd =
  t.ice.Ice.remote_ufrag <- ufrag;
  t.ice.Ice.remote_pwd <- pwd

(** {1 ICE Gathering} *)

(** Start ICE candidate gathering *)
let gather_candidates t =
  set_state t GatheringCandidates;

  (* Set up candidate callback *)
  Ice.on_candidate t.ice (fun candidate ->
    match t.on_local_candidate with
    | Some f -> f candidate
    | None -> ()
  );

  (* Gather host candidates synchronously *)
  Ice.gather_candidates t.ice

(** {1 Send/Receive through ICE} *)

(** Send data through the nominated ICE pair *)
let send_through_ice t data =
  match Ice.get_nominated_pair t.ice with
  | Some pair ->
    (* Send to the remote address of the nominated pair *)
    let remote = pair.Ice.remote in
    let (host, port) = (remote.Ice.address, remote.Ice.port) in
    (* For now, use a simple UDP send - in production this would go through
       the ICE agent's socket management *)
    let sock = Lwt_unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    let addr = Unix.ADDR_INET (Unix.inet_addr_of_string host, port) in
    ignore (Lwt_unix.sendto sock data 0 (Bytes.length data) [] addr);
    Lwt_unix.close sock |> ignore;
    Ok (Bytes.length data)
  | None ->
    Error "No nominated ICE pair"

(** {1 DTLS Processing} *)

(** Send DTLS records through ICE *)
let send_dtls_records t records =
  List.iter (fun record ->
    match send_through_ice t record with
    | Ok _ -> ()
    | Error e -> Printf.eprintf "[ICE-DTLS] Send failed: %s\n%!" e
  ) records

(** Process incoming DTLS record *)
let rec process_dtls_record t data =
  (* Use server handler if we're the server *)
  let result =
    if t.config.is_controlling then
      Dtls.handle_record t.dtls data
    else
      (* Server needs client address for cookie validation *)
      match Ice.get_nominated_pair t.ice with
      | Some pair ->
        let remote = pair.Ice.remote in
        Dtls.handle_record_as_server t.dtls data
          ~client_addr:(remote.Ice.address, remote.Ice.port)
      | None ->
        Dtls.handle_record t.dtls data  (* Fallback *)
  in

  match result with
  | Ok (response_records, app_data_opt) ->
    (* Send any response records through ICE *)
    send_dtls_records t response_records;

    (* Store flight for retransmission if needed *)
    if response_records <> [] then
      Dtls.store_flight t.dtls response_records;

    (* Check if handshake completed *)
    if Dtls.is_established t.dtls && t.state = HandshakingDTLS then begin
      set_state t AssociatingSCTP;
      (* Start SCTP association *)
      start_sctp_association t
    end;

    (* Process application data if any *)
    begin match app_data_opt with
    | Some plaintext -> process_sctp_packet t plaintext
    | None -> ()
    end

  | Error e ->
    Printf.eprintf "[ICE-DTLS] Record processing error: %s\n%!" e;
    set_error t e

(** {1 SCTP Processing} *)

(** Helper to send SCTP packet through DTLS/ICE *)
and send_sctp_packet t packet =
  match Dtls.encrypt t.dtls packet with
  | Ok encrypted ->
    ignore (send_through_ice t encrypted)
  | Error e ->
    Printf.eprintf "[ICE-DTLS-SCTP] Encrypt error: %s\n%!" e

(** Start SCTP association after DTLS is established *)
and start_sctp_association t =
  if t.config.is_controlling then begin
    (* Client: Send INIT to start 4-way handshake *)
    let (params, init_chunk, _state) = Sctp_handshake.client_init () in
    t.sctp_init_params <- Some params;
    send_sctp_packet t init_chunk
  end
  (* Server: Wait for INIT from client *)

(** Process decrypted SCTP packet - handles both handshake and data *)
and process_sctp_packet t packet =
  (* Check if this is a handshake chunk by examining chunk type *)
  if Bytes.length packet >= 13 then begin
    let chunk_type = Char.code (Bytes.get packet 12) in
    match chunk_type with
    | 1 when not t.config.is_controlling ->
      (* INIT received - we're server *)
      begin match Sctp_handshake.server_process_init packet with
      | Ok (_local_params, init_ack) ->
        send_sctp_packet t init_ack
      | Error e ->
        Printf.eprintf "[SCTP] INIT processing error: %s\n%!" e;
        set_error t ("SCTP INIT: " ^ e)
      end

    | 2 when t.config.is_controlling ->
      (* INIT-ACK received - we're client *)
      begin match t.sctp_init_params with
      | Some local_params ->
        begin match Sctp_handshake.client_process_init_ack packet local_params with
        | Ok (assoc, cookie_echo) ->
          t.sctp_association <- Some assoc;
          send_sctp_packet t cookie_echo
        | Error e ->
          Printf.eprintf "[SCTP] INIT-ACK processing error: %s\n%!" e;
          set_error t ("SCTP INIT-ACK: " ^ e)
        end
      | None ->
        Printf.eprintf "[SCTP] Received INIT-ACK but no init_params stored\n%!"
      end

    | 10 when not t.config.is_controlling ->
      (* COOKIE-ECHO received - we're server *)
      begin match Sctp_handshake.server_process_cookie_echo packet with
      | Ok (assoc, cookie_ack) ->
        t.sctp_association <- Some assoc;
        send_sctp_packet t cookie_ack;
        (* Server-side: connection established after sending COOKIE-ACK *)
        set_state t Connected
      | Error e ->
        Printf.eprintf "[SCTP] COOKIE-ECHO processing error: %s\n%!" e;
        set_error t ("SCTP COOKIE-ECHO: " ^ e)
      end

    | 11 when t.config.is_controlling ->
      (* COOKIE-ACK received - we're client, handshake complete! *)
      begin match t.sctp_association with
      | Some assoc ->
        begin match Sctp_handshake.client_process_cookie_ack packet assoc with
        | Ok updated_assoc ->
          t.sctp_association <- Some updated_assoc;
          (* Client-side: connection established after receiving COOKIE-ACK *)
          set_state t Connected
        | Error e ->
          Printf.eprintf "[SCTP] COOKIE-ACK processing error: %s\n%!" e;
          set_error t ("SCTP COOKIE-ACK: " ^ e)
        end
      | None ->
        Printf.eprintf "[SCTP] Received COOKIE-ACK but no association stored\n%!"
      end

    | _ ->
      (* Data chunk or other - pass to Sctp_core *)
      let outputs = Sctp_core.handle t.sctp (Sctp_core.PacketReceived packet) in
      process_sctp_outputs t outputs
  end
  else begin
    (* Packet too short, try Sctp_core anyway *)
    let outputs = Sctp_core.handle t.sctp (Sctp_core.PacketReceived packet) in
    process_sctp_outputs t outputs
  end

(** Process SCTP outputs after state machine step *)
and process_sctp_outputs t outputs =
  List.iter (fun output ->
    match output with
    | Sctp_core.SendPacket packet ->
      (* Encrypt with DTLS before sending through ICE *)
      begin match Dtls.encrypt t.dtls packet with
      | Ok encrypted ->
        ignore (send_through_ice t encrypted)
      | Error e ->
        Printf.eprintf "[ICE-DTLS-SCTP] Encrypt error: %s\n%!" e
      end

    | Sctp_core.DeliverData { stream_id; data } ->
      process_sctp_data t ~stream_id data

    | Sctp_core.ConnectionEstablished ->
      (* Full stack is now connected *)
      set_state t Connected

    | Sctp_core.SetTimer _ | Sctp_core.CancelTimer _ ->
      (* Timer management handled separately *)
      ()

    | Sctp_core.ConnectionClosed ->
      set_state t Closed

    | Sctp_core.Error e ->
      set_error t ("SCTP: " ^ e)
  ) outputs

(** Process received SCTP data - could be DCEP or application data *)
and process_sctp_data t ~stream_id data =
  if Bytes.length data > 0 then begin
    let first_byte = Bytes.get data 0 |> Char.code in
    if first_byte = Dcep.msg_type_data_channel_open then begin
      (* DATA_CHANNEL_OPEN *)
      match Dcep.decode_open data with
      | Ok open_msg ->
        let (_, ack) = Dcep.handle_open t.dcep ~stream_id open_msg in
        let outputs = Sctp_core.handle t.sctp
          (Sctp_core.UserSend { stream_id; data = ack }) in
        process_sctp_outputs t outputs;
        begin match t.on_channel_open with
        | Some f -> f stream_id open_msg.Dcep.label
        | None -> ()
        end
      | Error e ->
        Printf.eprintf "[DCEP] Failed to decode OPEN: %s\n%!" e
    end
    else if first_byte = Dcep.msg_type_data_channel_ack then begin
      (* DATA_CHANNEL_ACK *)
      let _ = Dcep.handle_ack t.dcep ~stream_id in
      begin match t.on_channel_open with
      | Some f ->
        begin match Dcep.get_channel t.dcep ~stream_id with
        | Some ch -> f stream_id ch.Dcep.label
        | None -> ()
        end
      | None -> ()
      end
    end
    else begin
      (* Regular application data *)
      begin match t.on_channel_data with
      | Some f -> f stream_id data
      | None -> ()
      end
    end
  end

(** {1 Connection Establishment} *)

(** Start connectivity checks and DTLS handshake *)
let connect t : (unit, string) result Lwt.t =
  set_state t ConnectingICE;

  (* Run ICE connectivity checks *)
  Lwt.bind (Ice.run_connectivity_checks t.ice) (fun () ->
    (* Check ICE state after connectivity checks complete *)
    let ice_state = Ice.get_state t.ice in
    let has_nominated = Option.is_some (Ice.get_nominated_pair t.ice) in

    if ice_state = Ice.Failed then begin
      set_error t "ICE failed: all checks failed";
      Lwt.return (Result.Error "ICE failed")
    end
    else if not has_nominated && ice_state <> Ice.Connected && ice_state <> Ice.Completed then begin
      set_error t "ICE failed: no connectivity";
      Lwt.return (Result.Error "ICE: no connectivity")
    end
    else begin
      (* ICE connected, start DTLS handshake *)
      set_state t HandshakingDTLS;

      (* Clear any previous retransmission state *)
      Dtls.clear_retransmit t.dtls;

      (* Client initiates DTLS handshake *)
      if t.config.is_controlling then begin
        match Dtls.start_handshake t.dtls with
        | Result.Ok records ->
          send_dtls_records t records;
          Dtls.store_flight t.dtls records;
          Lwt.return (Result.Ok ())
        | Result.Error e ->
          set_error t e;
          Lwt.return (Result.Error e)
      end else begin
        (* Server waits for ClientHello *)
        Lwt.return (Result.Ok ())
      end
    end
  )

(** {1 DataChannel API} *)

(** Open a new DataChannel *)
let open_channel t ~label ?protocol ?priority ?channel_type ()
    : (int, string) result =
  if t.state <> Connected then
    Result.error "Not connected"
  else begin
    let (stream_id, open_msg) =
      Dcep.open_channel t.dcep ~label ?protocol ?priority ?channel_type ()
    in
    let outputs = Sctp_core.handle t.sctp
      (Sctp_core.UserSend { stream_id; data = open_msg }) in
    process_sctp_outputs t outputs;
    Result.ok stream_id
  end

(** Send data on a channel *)
let send t ~stream_id ~data : (int, string) result =
  if t.state <> Connected then
    Result.error "Not connected"
  else
    match Dcep.get_channel t.dcep ~stream_id with
    | Some ch when ch.Dcep.state = Dcep.Open ->
      let outputs = Sctp_core.handle t.sctp
        (Sctp_core.UserSend { stream_id; data }) in
      process_sctp_outputs t outputs;
      Result.ok (Bytes.length data)
    | Some _ ->
      Result.error "Channel not open"
    | None ->
      Result.error "Channel not found"

(** Close a channel *)
let close_channel t ~stream_id =
  Dcep.close_channel t.dcep ~stream_id

(** {1 Timer Handling} *)

(** Handle DTLS retransmission timeout *)
let handle_dtls_timeout t =
  match Dtls.handle_retransmit_timeout t.dtls with
  | Ok flight when flight <> [] ->
    send_dtls_records t flight
  | Ok _ -> ()
  | Error e ->
    set_error t ("DTLS timeout: " ^ e)

(** Check if DTLS retransmit is needed (for polling) *)
let check_dtls_retransmit t =
  Dtls.check_retransmit_needed t.dtls

(** {1 Incoming Packet Handling} *)

(** Process incoming packet (called when data arrives on UDP) *)
let handle_incoming t data =
  match t.state with
  | ConnectingICE ->
    (* During ICE, packets are STUN binding requests/responses *)
    (* ICE module handles these internally *)
    ()

  | HandshakingDTLS | AssociatingSCTP | Connected ->
    (* After ICE, all packets go through DTLS *)
    process_dtls_record t data

  | _ ->
    Printf.eprintf "[ICE-DTLS] Unexpected packet in state %s\n%!"
      (string_of_state t.state)

(** {1 Queries} *)

let get_state t = t.state
let is_connected t = t.state = Connected

let get_nominated_pair t = Ice.get_nominated_pair t.ice

(** {1 Statistics} *)

type stats = {
  transport_state: transport_state;
  ice_state: Ice.connection_state;
  dtls_state: Dtls.state;
  sctp_stats: Sctp_core.stats;
  dcep_stats: Dcep.stats;
}

let get_stats t = {
  transport_state = t.state;
  ice_state = Ice.get_state t.ice;
  dtls_state = Dtls.get_state t.dtls;
  sctp_stats = Sctp_core.get_stats t.sctp;
  dcep_stats = Dcep.get_stats t.dcep;
}

(** {1 Cleanup} *)

let close t =
  (* Send DTLS close_notify if connected *)
  if t.state = Connected then begin
    match Dtls.close t.dtls with
    | Some alert ->
      ignore (send_through_ice t alert)
    | None -> ()
  end;
  set_state t Closed
