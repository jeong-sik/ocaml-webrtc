(** ICE-DTLS-SCTP Transport - Full WebRTC DataChannel Stack

    WebRTC DataChannel stack with ICE NAT traversal:
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
    │     >>>  ICE (NAT Traversal)  <<<       │  ← This module adds ICE
    ├─────────────────────────────────────────┤
    │           UDP (Network)                 │
    └─────────────────────────────────────────┘
    v}

    This module integrates ICE (RFC 8445) with DTLS-SCTP for complete
    WebRTC DataChannel connectivity including NAT traversal.

    Key features:
    - STUN/DTLS packet demultiplexing (RFC 7983)
    - ICE candidate gathering and connectivity checks
    - Nominated pair selection for data transmission
    - Trickle ICE support (RFC 8838)

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

(** {1 Transport State} *)

type ice_dtls_state =
  | Ice_gathering         (** Gathering ICE candidates *)
  | Ice_checking          (** Running ICE connectivity checks *)
  | Ice_connected         (** ICE connected, starting DTLS *)
  | Dtls_handshaking      (** DTLS handshake in progress *)
  | Established           (** Fully connected *)
  | Failed of string      (** Connection failed *)
  | Closed                (** Connection closed *)

(** {1 Configuration} *)

type config = {
  mtu: int;                           (** Max transmission unit *)
  sctp_port: int;                     (** SCTP port (default: 5000) *)
  fingerprint: string;                (** Expected peer certificate fingerprint *)
  is_client: bool;                    (** true if initiating connection *)
  ice_config: Ice.config;             (** ICE configuration *)
}

let default_config = {
  mtu = 1200;
  sctp_port = 5000;
  fingerprint = "";
  is_client = true;
  ice_config = Ice.default_config;
}

(** {1 Transport Type} *)

type t = {
  config: config;
  ice: Ice.agent;                     (** ICE agent for NAT traversal *)
  dtls: Dtls.t;                       (** DTLS state machine *)
  sctp: Sctp_core.t;                  (** SCTP state machine *)
  dcep: Dcep.t;                       (** DataChannel establishment *)

  mutable state: ice_dtls_state;
  recv_buffer: bytes;

  (* Bound local socket for sending/receiving *)
  mutable local_socket: Unix.file_descr option;
  mutable local_addr: (string * int) option;

  (* Callbacks *)
  mutable on_ice_candidate: (Ice.candidate -> unit) option;
  mutable on_ice_gathering_complete: (unit -> unit) option;
  mutable on_channel_open: (int -> string -> unit) option;
  mutable on_channel_data: (int -> bytes -> unit) option;
  mutable on_channel_close: (int -> unit) option;
  mutable on_connected: (unit -> unit) option;
  mutable on_error: (string -> unit) option;
}

(** {1 Packet Demultiplexing (RFC 7983)}

    STUN, DTLS, and RTP/RTCP share the same 5-tuple.
    Demultiplexing is based on the first byte:

    - STUN: 0x00-0x03 (actually 0x00-0x01 for binding)
    - DTLS: 0x14-0x17 (content types: CCS=20, Alert=21, Handshake=22, AppData=23)
    - RTP:  0x80-0xBF (version=2, padding bit varies)
    - RTCP: 0xC0-0xCF (SR=200, RR=201, etc.)
*)

type packet_type =
  | Stun_packet
  | Dtls_packet
  | Unknown_packet

let classify_packet data =
  if Bytes.length data = 0 then Unknown_packet
  else
    let first_byte = Bytes.get_uint8 data 0 in
    if first_byte >= 0 && first_byte <= 3 then Stun_packet
    else if first_byte >= 20 && first_byte <= 23 then Dtls_packet
    else Unknown_packet

(** {1 Creation} *)

let create ?(config = default_config) () =
  let ice = Ice.create config.ice_config in
  let dtls_config =
    if config.is_client then Dtls.default_client_config
    else Dtls.default_server_config
  in
  let dtls = Dtls.create dtls_config in
  let sctp = Sctp_core.create ~config:Sctp.default_config () in
  let dcep = Dcep.create ~is_client:config.is_client in
  {
    config;
    ice;
    dtls;
    sctp;
    dcep;
    state = Ice_gathering;
    recv_buffer = Bytes.create 65536;
    local_socket = None;
    local_addr = None;
    on_ice_candidate = None;
    on_ice_gathering_complete = None;
    on_channel_open = None;
    on_channel_data = None;
    on_channel_close = None;
    on_connected = None;
    on_error = None;
  }

(** {1 Callback Registration} *)

let on_ice_candidate t f = t.on_ice_candidate <- Some f
let on_ice_gathering_complete t f = t.on_ice_gathering_complete <- Some f
let on_channel_open t f = t.on_channel_open <- Some f
let on_channel_data t f = t.on_channel_data <- Some f
let on_channel_close t f = t.on_channel_close <- Some f
let on_connected t f = t.on_connected <- Some f
let on_error t f = t.on_error <- Some f

(** {1 ICE Candidate Gathering} *)

(** Start ICE candidate gathering *)
let gather_candidates t =
  (* Set up ICE candidate callback *)
  Ice.on_candidate t.ice (fun candidate ->
    match t.on_ice_candidate with
    | Some f -> f candidate
    | None -> ()
  );

  Ice.on_gathering_complete t.ice (fun () ->
    t.state <- Ice_checking;
    match t.on_ice_gathering_complete with
    | Some f -> f ()
    | None -> ()
  );

  (* Start gathering (host + srflx + relay) *)
  Ice.gather_candidates_full t.ice

(** Add remote ICE candidate (Trickle ICE) *)
let add_remote_candidate t candidate =
  Ice.add_remote_candidate t.ice candidate

(** Set remote ICE credentials *)
let set_remote_credentials t ~ufrag ~pwd =
  Ice.set_remote_credentials t.ice ~ufrag ~pwd

(** Get local ICE credentials *)
let get_local_credentials t =
  Ice.get_local_credentials t.ice

(** Get local candidates *)
let get_local_candidates t =
  Ice.get_local_candidates t.ice

(** Signal end of remote candidates *)
let set_remote_end_of_candidates t =
  Ice.set_remote_end_of_candidates t.ice

(** {1 Internal Helpers} *)

(** Send data through nominated ICE pair *)
let send_via_ice t data =
  match Ice.get_nominated_pair t.ice with
  | Some pair ->
    begin match t.local_socket with
    | Some sock ->
      let dest_addr = Unix.ADDR_INET (
        Unix.inet_addr_of_string pair.Ice.remote.address,
        pair.remote.port
      ) in
      let _ = Unix.sendto sock data 0 (Bytes.length data) [] dest_addr in
      ()
    | None ->
      Printf.eprintf "[ICE-DTLS] No local socket bound\n%!"
    end
  | None ->
    Printf.eprintf "[ICE-DTLS] No nominated pair yet\n%!"

(** Send DTLS records via ICE *)
let send_records t records =
  List.iter (send_via_ice t) records

(** {1 STUN Processing} *)

(** Process incoming STUN packet for ICE *)
let process_stun_packet t data ~from_addr =
  (* Decode STUN message *)
  match Stun.decode data with
  | Ok msg ->
    begin match (msg.Stun.msg_class, msg.Stun.msg_method) with
    | (Stun.Request, Stun.Binding) ->
      (* ICE connectivity check request - send response *)
      let (from_ip, from_port) = from_addr in
      let mapped_address : Stun.address = {
        family = Stun.IPv4;
        port = from_port;
        ip = from_ip;
      } in
      let response = Stun.create_binding_response
        ~transaction_id:msg.transaction_id
        ~mapped_address
      in
      let response_bytes = Stun.encode response in
      send_via_ice t response_bytes

    | (Stun.Success_response, Stun.Binding) ->
      (* ICE connectivity check response - process for ICE *)
      (* In a full implementation, we would update ICE check state *)
      ()

    | _ -> ()
    end
  | Error _ -> ()

(** {1 DTLS Processing} *)

(** Process incoming DTLS record *)
let rec process_dtls_record t data =
  let handler = if t.config.is_client then
    Dtls.handle_record t.dtls data
  else
    (* Server needs client address for cookie validation *)
    match t.local_addr with
    | Some addr -> Dtls.handle_record_as_server t.dtls data ~client_addr:addr
    | None -> Dtls.handle_record t.dtls data
  in
  match handler with
  | Ok (response_records, app_data_opt) ->
    (* Send any response records via ICE *)
    send_records t response_records;

    (* Check if handshake completed *)
    if Dtls.is_established t.dtls && t.state = Dtls_handshaking then begin
      t.state <- Established;
      match t.on_connected with
      | Some f -> f ()
      | None -> ()
    end;

    (* Process application data if any *)
    begin match app_data_opt with
    | Some plaintext -> process_sctp_packet t plaintext
    | None -> ()
    end

  | Error e ->
    Printf.eprintf "[ICE-DTLS] DTLS error: %s\n%!" e;
    t.state <- Failed e

(** {1 SCTP Processing} *)

(** Process decrypted SCTP packet *)
and process_sctp_packet t packet =
  let outputs = Sctp_core.handle t.sctp (Sctp_core.PacketReceived packet) in
  process_sctp_outputs t outputs

(** Process SCTP outputs after state machine step *)
and process_sctp_outputs t outputs =
  List.iter (fun output ->
    match output with
    | Sctp_core.SendPacket packet ->
      (* Encrypt with DTLS then send via ICE *)
      begin match Dtls.encrypt t.dtls packet with
      | Ok encrypted -> send_via_ice t encrypted
      | Error e -> Printf.eprintf "[ICE-DTLS] Encrypt error: %s\n%!" e
      end

    | Sctp_core.DeliverData { stream_id; data } ->
      process_sctp_data t ~stream_id data

    | Sctp_core.ConnectionEstablished -> ()
    | Sctp_core.SetTimer _ | Sctp_core.CancelTimer _ -> ()
    | Sctp_core.ConnectionClosed -> ()
    | Sctp_core.Error e ->
      Printf.eprintf "[SCTP] Error: %s\n%!" e
  ) outputs

(** Process received SCTP data - DCEP or application *)
and process_sctp_data t ~stream_id data =
  if Bytes.length data > 0 then begin
    let first_byte = Bytes.get data 0 |> Char.code in
    if first_byte = Dcep.msg_type_data_channel_open then begin
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
      match t.on_channel_data with
      | Some f -> f stream_id data
      | None -> ()
    end
  end

(** {1 Connection Management} *)

(** Start ICE connectivity checks *)
let start_connectivity_checks t =
  t.state <- Ice_checking;
  (* This runs async - use Lwt.async in real code *)
  let _ = Ice.run_connectivity_checks t.ice in
  ()

(** Start DTLS handshake after ICE connects *)
let start_dtls_handshake t =
  t.state <- Dtls_handshaking;

  (* Set up local socket if not already done *)
  begin match Ice.get_nominated_pair t.ice with
  | Some pair ->
    let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    let local_addr = Unix.ADDR_INET (
      Unix.inet_addr_of_string pair.Ice.local.address,
      pair.local.port
    ) in
    Unix.bind sock local_addr;
    t.local_socket <- Some sock;
    t.local_addr <- Some (pair.local.address, pair.local.port)
  | None ->
    Printf.eprintf "[ICE-DTLS] No nominated pair for DTLS\n%!"
  end;

  (* Client initiates DTLS handshake *)
  if t.config.is_client then begin
    match Dtls.start_handshake t.dtls with
    | Ok records -> send_records t records
    | Error e ->
      t.state <- Failed e;
      Printf.eprintf "[ICE-DTLS] DTLS handshake start failed: %s\n%!" e
  end

(** Notify that ICE has connected (called when nominated pair selected) *)
let on_ice_connected t =
  t.state <- Ice_connected;
  start_dtls_handshake t

(** {1 DataChannel API} *)

(** Open a new DataChannel *)
let open_channel t ~label ?protocol ?priority ?channel_type ()
    : (int, string) result =
  if t.state <> Established then
    Result.error "Connection not established"
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
  if t.state <> Established then
    Result.error "Connection not established"
  else
    match Dcep.get_channel t.dcep ~stream_id with
    | Some ch when ch.Dcep.state = Dcep.Open ->
      let outputs = Sctp_core.handle t.sctp
        (Sctp_core.UserSend { stream_id; data }) in
      process_sctp_outputs t outputs;
      Result.ok (Bytes.length data)
    | Some _ -> Result.error "Channel not open"
    | None -> Result.error "Channel not found"

(** Close a channel *)
let close_channel t ~stream_id =
  Dcep.close_channel t.dcep ~stream_id

(** {1 Main Loop Integration} *)

(** Process incoming packet (demux STUN vs DTLS) *)
let handle_incoming t ~data ~from_addr =
  match classify_packet data with
  | Stun_packet ->
    process_stun_packet t data ~from_addr
  | Dtls_packet ->
    process_dtls_record t data
  | Unknown_packet ->
    Printf.eprintf "[ICE-DTLS] Unknown packet type (first byte: 0x%02x)\n%!"
      (Bytes.get_uint8 data 0)

(** Poll for incoming packets *)
let tick t =
  match t.local_socket with
  | Some sock ->
    let buf = t.recv_buffer in
    begin try
      let (len, src_addr) = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
      let data = Bytes.sub buf 0 len in
      let from_addr = match src_addr with
        | Unix.ADDR_INET (addr, port) ->
          (Unix.string_of_inet_addr addr, port)
        | _ -> ("0.0.0.0", 0)
      in
      handle_incoming t ~data ~from_addr
    with
    | Unix.Unix_error (Unix.EAGAIN, _, _)
    | Unix.Unix_error (Unix.EWOULDBLOCK, _, _) -> ()
    end
  | None -> ()

(** {1 State Queries} *)

let get_state t = t.state
let is_connected t = t.state = Established

let get_ice_state t = Ice.get_state t.ice
let get_ice_gathering_state t = Ice.get_gathering_state t.ice

(** {1 Statistics} *)

type stats = {
  ice_dtls_state: ice_dtls_state;
  ice_state: Ice.connection_state;
  sctp_stats: Sctp_core.stats;
  dcep_stats: Dcep.stats;
}

let get_stats t = {
  ice_dtls_state = t.state;
  ice_state = Ice.get_state t.ice;
  sctp_stats = Sctp_core.get_stats t.sctp;
  dcep_stats = Dcep.get_stats t.dcep;
}

(** {1 Cleanup} *)

let close t =
  (* Send DTLS close_notify if connected *)
  if t.state = Established then begin
    match Dtls.close t.dtls with
    | Some alert -> send_via_ice t alert
    | None -> ()
  end;

  (* Close ICE agent *)
  Ice.close t.ice;

  (* Close local socket *)
  begin match t.local_socket with
  | Some sock -> Unix.close sock
  | None -> ()
  end;

  t.state <- Closed

(** {1 Pretty Printing} *)

let pp_state fmt = function
  | Ice_gathering -> Format.fprintf fmt "ICE Gathering"
  | Ice_checking -> Format.fprintf fmt "ICE Checking"
  | Ice_connected -> Format.fprintf fmt "ICE Connected"
  | Dtls_handshaking -> Format.fprintf fmt "DTLS Handshaking"
  | Established -> Format.fprintf fmt "Established"
  | Failed e -> Format.fprintf fmt "Failed: %s" e
  | Closed -> Format.fprintf fmt "Closed"
