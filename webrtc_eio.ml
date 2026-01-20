(** Eio-based WebRTC Full Stack

    Complete WebRTC stack using Eio for fiber-based concurrency.
    Integrates ICE, DTLS, and SCTP layers into a unified API.

    Data Flow:
    ┌─────────────────────────────────────────────────────────────┐
    │  Application: DataChannel.send("Hello")                     │
    ├─────────────────────────────────────────────────────────────┤
    │  SCTP: Fragment + Reliability + Flow Control                │
    ├─────────────────────────────────────────────────────────────┤
    │  DTLS: Encrypt (AES-GCM)                                    │
    ├─────────────────────────────────────────────────────────────┤
    │  ICE: Select best path, STUN keepalives                     │
    ├─────────────────────────────────────────────────────────────┤
    │  UDP: Send to peer                                          │
    └─────────────────────────────────────────────────────────────┘

    @author Second Brain
    @since ocaml-webrtc 0.6.0
*)

(** {1 Types} *)

type role = Client | Server

type connection_state =
  | New
  | Connecting
  | Connected
  | Disconnected
  | Failed
  | Closed
[@@deriving show, eq]

type datachannel = {
  id: int;
  label: string;
  mutable on_message: (bytes -> unit) option;
  mutable on_open: (unit -> unit) option;
  mutable on_close: (unit -> unit) option;
}

type t = {
  role: role;
  mutable state: connection_state;

  (* Protocol layers *)
  ice: Ice_eio.t;
  dtls: Dtls_eio.t;
  sctp: Sctp_core.t;

  (* Data channels *)
  mutable channels: datachannel list;
  mutable next_channel_id: int;

  (* Buffers *)
  recv_buffer: bytes;

  (* Callbacks *)
  mutable on_state_change: (connection_state -> unit) option;
  mutable on_datachannel: (datachannel -> unit) option;
  mutable on_ice_candidate: (Ice.candidate -> unit) option;
}

(** {1 Creation} *)

let default_ice_config = {
  Ice.role = Ice.Controlling;
  ice_servers = [
    {
      Ice.urls = ["stun:stun.l.google.com:19302"];
      username = None;
      credential = None;
      tls_ca = None;
    };
  ];
  ice_lite = false;
  aggressive_nomination = true;
  check_interval_ms = 50;
  max_check_attempts = 25;
  ta_timeout_ms = 500;
}

let create ?(ice_config = default_ice_config) ~role () =
  (* Initialize crypto RNG *)
  (try Mirage_crypto_rng_unix.use_default () with _ -> ());

  let is_client = (role = Client) in

  {
    role;
    state = New;

    ice = Ice_eio.create ~config:ice_config ();
    dtls = if is_client then Dtls_eio.create_client ()
           else Dtls_eio.create_server ();
    sctp = Sctp_core.create ~config:Sctp.default_config ();

    channels = [];
    next_channel_id = if is_client then 0 else 1;  (* Even/odd allocation *)

    recv_buffer = Bytes.create 65536;

    on_state_change = None;
    on_datachannel = None;
    on_ice_candidate = None;
  }

(** {1 Callbacks} *)

let on_state_change t f = t.on_state_change <- Some f
let on_datachannel t f = t.on_datachannel <- Some f
let on_ice_candidate t f = t.on_ice_candidate <- Some f

(** {1 State Access} *)

let get_state t = t.state
let get_local_candidates t = Ice_eio.get_local_candidates t.ice
let get_local_credentials t = Ice_eio.get_local_credentials t.ice

(** {1 Internal: State Transitions} *)

let set_state t new_state =
  if t.state <> new_state then begin
    t.state <- new_state;
    Option.iter (fun f -> f new_state) t.on_state_change
  end

(** {1 Internal: Layer Integration} *)

(** Wire up DTLS to use ICE for transport *)
let connect_dtls_to_ice t =
  Dtls_eio.set_transport t.dtls
    ~send:(fun data ->
      match Ice_eio.send t.ice data with
      | Ok _ -> ()
      | Error _ -> ())
    ~recv:(fun () -> None)  (* Handled by main recv loop *)

(** Process decrypted DTLS data through SCTP *)
let process_sctp_packet t packet =
  let outputs = Sctp_core.handle t.sctp (Sctp_core.PacketReceived packet) in

  List.iter (function
    | Sctp_core.SendPacket data ->
      (* Encrypt with DTLS and send *)
      begin match Dtls_eio.send t.dtls data with
      | Ok _ -> ()
      | Error _ -> ()
      end

    | Sctp_core.DeliverData { stream_id; data } ->
      (* Find channel and deliver *)
      begin match List.find_opt (fun ch -> ch.id = stream_id) t.channels with
      | Some ch -> Option.iter (fun f -> f data) ch.on_message
      | None -> ()  (* Unknown channel *)
      end

    | Sctp_core.ConnectionEstablished ->
      set_state t Connected

    | Sctp_core.ConnectionClosed ->
      set_state t Closed

    | Sctp_core.Error _e -> ()
    | Sctp_core.SetTimer _ -> ()
    | Sctp_core.CancelTimer _ -> ()
  ) outputs

(** {1 DataChannel API} *)

(** Create a new DataChannel *)
let create_datachannel t ~label =
  let id = t.next_channel_id in
  t.next_channel_id <- t.next_channel_id + 2;  (* Even/odd increment *)

  let channel = {
    id;
    label;
    on_message = None;
    on_open = None;
    on_close = None;
  } in

  t.channels <- channel :: t.channels;

  (* Send DCEP OPEN message *)
  let dcep_open = Dcep.encode_open {
    Dcep.channel_type = Dcep.Reliable;
    priority = 0;
    label;
    protocol = "";
  } in
  let outputs = Sctp_core.handle t.sctp
    (Sctp_core.UserSend { stream_id = id; data = dcep_open }) in

  List.iter (function
    | Sctp_core.SendPacket data ->
      ignore (Dtls_eio.send t.dtls data)
    | _ -> ()
  ) outputs;

  channel

(** Send data on a channel *)
let send_channel t channel data =
  if t.state <> Connected then
    Error "Not connected"
  else begin
    let outputs = Sctp_core.handle t.sctp
      (Sctp_core.UserSend { stream_id = channel.id; data }) in

    List.iter (function
      | Sctp_core.SendPacket packet ->
        ignore (Dtls_eio.send t.dtls packet)
      | _ -> ()
    ) outputs;

    Ok (Bytes.length data)
  end

(** {1 Signaling Integration} *)

(** Add remote ICE candidate *)
let add_ice_candidate t candidate =
  Ice_eio.add_remote_candidate t.ice candidate

(** Set remote ICE credentials *)
let set_remote_credentials t ~ufrag ~pwd =
  Ice_eio.set_remote_credentials t.ice ~ufrag ~pwd

(** {1 Connection Lifecycle} *)

(** Connect to remote peer using Eio *)
let connect t ~sw ~net ~clock =
  set_state t Connecting;

  (* Wire up layers *)
  connect_dtls_to_ice t;

  (* Forward ICE candidates *)
  Ice_eio.on_candidate t.ice (fun cand ->
    Option.iter (fun f -> f cand) t.on_ice_candidate
  );

  (* ICE: Gather candidates and establish connectivity *)
  Ice_eio.on_data t.ice (fun data ->
    (* Received ICE data -> DTLS decrypt -> SCTP *)
    match Dtls_eio.decrypt t.dtls data with
    | Ok plaintext -> process_sctp_packet t plaintext
    | Error _ -> ()  (* Not DTLS data or decryption failed *)
  );

  (* Start ICE *)
  Eio.Fiber.fork ~sw (fun () ->
    Ice_eio.run t.ice ~sw ~net ~clock ~on_connected:(fun () ->
      (* ICE connected - start DTLS handshake *)
      let role = if t.role = Client then `Client else `Server in
      let client_addr = ("127.0.0.1", 5000) in  (* Placeholder *)

      Dtls_eio.run t.dtls ~sw ~clock ~role ~client_addr
        ~on_established:(fun () ->
          (* DTLS connected - start SCTP association *)
          let outputs = Sctp_core.initiate t.sctp in

          List.iter (function
            | Sctp_core.SendPacket data ->
              ignore (Dtls_eio.send t.dtls data)
            | _ -> ()
          ) outputs
        )
    )
  )

(** Main event loop fiber *)
let run_event_loop t ~sw:_ ~clock =
  let open Eio in

  let rec loop () =
    match t.state with
    | Closed | Failed -> ()
    | _ ->
      (* SCTP timer tick *)
      let outputs = Sctp_core.poll_transmit t.sctp in
      List.iter (function
        | Sctp_core.SendPacket data ->
          ignore (Dtls_eio.send t.dtls data)
        | _ -> ()
      ) outputs;

      Time.sleep clock 0.010;  (* 10ms tick *)
      loop ()
  in
  loop ()

(** Run WebRTC connection *)
let run t ~sw ~net ~clock =
  (* Start connection process *)
  connect t ~sw ~net ~clock;

  (* Run event loop *)
  run_event_loop t ~sw ~clock

(** Close the connection *)
let close t =
  set_state t Closed;
  Ice_eio.close t.ice

(** {1 Convenience: Simple API} *)

(** Run a WebRTC peer with Eio environment *)
let run_peer ~env ~role ~on_channel ~on_message =
  Eio.Switch.run (fun sw ->
    let net = Eio.Stdenv.net env in
    let clock = Eio.Stdenv.clock env in

    let peer = create ~role () in

    on_datachannel peer (fun ch ->
      on_channel ch;
      ch.on_message <- Some (on_message ch)
    );

    run peer ~sw ~net ~clock;

    peer
  )
