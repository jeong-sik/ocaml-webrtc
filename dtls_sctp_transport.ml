(** DTLS-SCTP Transport - Encrypted SCTP for WebRTC DataChannels

    WebRTC DataChannel stack:
    {v
    ┌─────────────────────────────────────────┐
    │           Application (DataChannel)     │
    ├─────────────────────────────────────────┤
    │           DCEP (Channel Setup)          │
    ├─────────────────────────────────────────┤
    │           SCTP (Reliable Transport)     │
    ├─────────────────────────────────────────┤
    │     >>>  DTLS (Encryption)  <<<         │  ← This module
    ├─────────────────────────────────────────┤
    │           ICE (NAT Traversal)           │
    ├─────────────────────────────────────────┤
    │           UDP (Network)                 │
    └─────────────────────────────────────────┘
    v}

    DTLS 1.2 (RFC 6347) encrypts SCTP packets before UDP transmission.
    Uses TLS 1.2 crypto primitives (AES-GCM, ECDHE, SHA-256).

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

(** {1 DTLS Connection State} *)

type dtls_state =
  | Disconnected
  | Handshaking
  | Connected
  | Closed
  | Error of string

(** {1 Configuration} *)

type config =
  { mtu : int (** Max transmission unit *)
  ; sctp_port : int (** SCTP port (default: 5000) *)
  ; fingerprint : string (** Expected peer certificate fingerprint *)
  ; is_client : bool (** true if initiating DTLS handshake *)
  }

let default_config =
  { mtu = 1200
  ; (* Conservative for DTLS overhead *)
    sctp_port = 5000
  ; fingerprint = ""
  ; is_client = true
  }
;;

(** {1 Transport State} *)

type t =
  { config : config
  ; dtls : Dtls.t (** DTLS state machine *)
  ; sctp : Sctp_core.t (** SCTP state machine *)
  ; dcep : Dcep.t (** DataChannel establishment *)
  ; udp : Udp_transport.t (** UDP socket *)
  ; mutable state : dtls_state
  ; recv_buffer : bytes
  ; (* Callbacks *)
    mutable on_channel_open : (int -> string -> unit) option
  ; mutable on_channel_data : (int -> bytes -> unit) option
  ; mutable on_channel_close : (int -> unit) option
  ; mutable on_connected : (unit -> unit) option
  ; mutable on_error : (string -> unit) option
  }

(** {1 Creation} *)

let create ?(config = default_config) ~host ~port () =
  let udp = Udp_transport.create ~host ~port () in
  let dtls_config =
    if config.is_client then Dtls.default_client_config else Dtls.default_server_config
  in
  let dtls = Dtls.create dtls_config in
  let sctp = Sctp_core.create ~config:Sctp.default_config () in
  let dcep = Dcep.create ~is_client:config.is_client in
  { config
  ; dtls
  ; sctp
  ; dcep
  ; udp
  ; state = Disconnected
  ; recv_buffer = Bytes.create 65536
  ; on_channel_open = None
  ; on_channel_data = None
  ; on_channel_close = None
  ; on_connected = None
  ; on_error = None
  }
;;

(** {1 Callback Registration} *)

let on_channel_open t f = t.on_channel_open <- Some f
let on_channel_data t f = t.on_channel_data <- Some f
let on_channel_close t f = t.on_channel_close <- Some f
let on_connected t f = t.on_connected <- Some f
let on_error t f = t.on_error <- Some f

(** {1 Internal Helpers} *)

(** Send records to UDP *)
let send_records t records =
  List.iter
    (fun record ->
       let _ = Udp_transport.send_connected t.udp ~data:record in
       ())
    records
;;

(** {1 DTLS Handshake} *)

(** Start DTLS handshake (client initiates) *)
let start_handshake t ~remote_host ~remote_port =
  Udp_transport.connect t.udp ~host:remote_host ~port:remote_port;
  t.state <- Handshaking;
  (* Generate ClientHello *)
  match Dtls.start_handshake t.dtls with
  | Ok records -> send_records t records
  | Error e ->
    t.state <- Error e;
    Log.error "[DTLS-SCTP] Handshake start failed: %s" e
;;

(** Process incoming DTLS record *)
let rec process_dtls_record t data =
  match Dtls.handle_record t.dtls data with
  | Ok (response_records, app_data_opt) ->
    (* Send any response records *)
    send_records t response_records;
    (* Check if handshake completed *)
    if Dtls.is_established t.dtls && t.state = Handshaking
    then (
      t.state <- Connected;
      match t.on_connected with
      | Some f -> f ()
      | None -> ());
    (* Process application data if any *)
    (match app_data_opt with
     | Some plaintext -> process_sctp_packet t plaintext
     | None -> ())
  | Error e ->
    Log.error "[DTLS-SCTP] Record processing error: %s" e;
    t.state <- Error e

(** {1 SCTP Processing} *)

(** Process decrypted SCTP packet *)
and process_sctp_packet t packet =
  let outputs = Sctp_core.handle t.sctp (Sctp_core.PacketReceived packet) in
  process_sctp_outputs t outputs

(** Process SCTP outputs after state machine step *)
and process_sctp_outputs t outputs =
  List.iter
    (fun output ->
       match output with
       | Sctp_core.SendPacket packet ->
         (* Encrypt with DTLS before sending *)
         (match Dtls.encrypt t.dtls packet with
          | Ok encrypted ->
            let _ = Udp_transport.send_connected t.udp ~data:encrypted in
            ()
          | Error e -> Log.error "[DTLS-SCTP] Encrypt error: %s" e)
       | Sctp_core.DeliverData { stream_id; data } -> process_sctp_data t ~stream_id data
       | Sctp_core.ConnectionEstablished ->
         (* SCTP association established over DTLS *)
         ()
       | Sctp_core.SetTimer _ | Sctp_core.CancelTimer _ ->
         (* Timer management handled separately *)
         ()
       | Sctp_core.ConnectionClosed -> ()
       | Sctp_core.Error e -> Log.error "[SCTP] Error: %s" e)
    outputs

(** Process received SCTP data - could be DCEP or application data *)
and process_sctp_data t ~stream_id data =
  (* Check first byte for DCEP message types *)
  if Bytes.length data > 0
  then (
    let first_byte = Bytes.get data 0 |> Char.code in
    if first_byte = Dcep.msg_type_data_channel_open
    then (
      (* DATA_CHANNEL_OPEN *)
      match Dcep.decode_open data with
      | Ok open_msg ->
        let _, ack = Dcep.handle_open t.dcep ~stream_id open_msg in
        (* Send ACK through SCTP *)
        let outputs =
          Sctp_core.handle t.sctp (Sctp_core.UserSend { stream_id; data = ack })
        in
        process_sctp_outputs t outputs;
        (* Notify application *)
        (match t.on_channel_open with
         | Some f -> f stream_id open_msg.Dcep.label
         | None -> ())
      | Error e -> Log.error "[DCEP] Failed to decode OPEN: %s" e)
    else if first_byte = Dcep.msg_type_data_channel_ack
    then (
      (* DATA_CHANNEL_ACK *)
      let _ = Dcep.handle_ack t.dcep ~stream_id in
      match t.on_channel_open with
      | Some f ->
        (match Dcep.get_channel t.dcep ~stream_id with
         | Some ch -> f stream_id ch.Dcep.label
         | None -> ())
      | None -> ())
    else (
      (* Regular application data *)
      match t.on_channel_data with
      | Some f -> f stream_id data
      | None -> ()))
;;

(** {1 DataChannel API} *)

(** Open a new DataChannel *)
let open_channel t ~label ?protocol ?priority ?channel_type () : (int, string) result =
  if t.state <> Connected
  then Result.error "DTLS not connected"
  else (
    let stream_id, open_msg =
      Dcep.open_channel t.dcep ~label ?protocol ?priority ?channel_type ()
    in
    (* Send OPEN through SCTP *)
    let outputs =
      Sctp_core.handle t.sctp (Sctp_core.UserSend { stream_id; data = open_msg })
    in
    process_sctp_outputs t outputs;
    Result.ok stream_id)
;;

(** Send data on a channel *)
let send t ~stream_id ~data : (int, string) result =
  if t.state <> Connected
  then Result.error "DTLS not connected"
  else (
    match Dcep.get_channel t.dcep ~stream_id with
    | Some ch when ch.Dcep.state = Dcep.Open ->
      let outputs = Sctp_core.handle t.sctp (Sctp_core.UserSend { stream_id; data }) in
      process_sctp_outputs t outputs;
      Result.ok (Bytes.length data)
    | Some _ -> Result.error "Channel not open"
    | None -> Result.error "Channel not found")
;;

(** Close a channel *)
let close_channel t ~stream_id = Dcep.close_channel t.dcep ~stream_id

(** {1 Main Loop Integration} *)

(** Poll for incoming packets and process *)
let tick t =
  match Udp_transport.recv t.udp ~buf:t.recv_buffer with
  | Ok (len, _) ->
    let data = Bytes.sub t.recv_buffer 0 len in
    process_dtls_record t data
  | Error _ -> ()
;;

(** Get DTLS state *)
let get_state t = t.state

(** Check if connected *)
let is_connected t = t.state = Connected

(** {1 Statistics} *)

type stats =
  { dtls_state : dtls_state
  ; sctp_stats : Sctp_core.stats
  ; dcep_stats : Dcep.stats
  }

let get_stats t =
  { dtls_state = t.state
  ; sctp_stats = Sctp_core.get_stats t.sctp
  ; dcep_stats = Dcep.get_stats t.dcep
  }
;;

(** {1 Cleanup} *)

let close t =
  (* Send DTLS close_notify *)
  if t.state = Connected
  then (
    match Dtls.close t.dtls with
    | Some alert ->
      let _ = Udp_transport.send_connected t.udp ~data:alert in
      ()
    | None -> ());
  t.state <- Closed;
  Udp_transport.close t.udp
;;
