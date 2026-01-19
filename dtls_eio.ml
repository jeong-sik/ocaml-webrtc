(** Eio-based DTLS Transport

    Bridges the Sans-IO DTLS implementation (dtls.ml) with Eio's
    fiber-based concurrency for actual network I/O and timer management.

    Architecture:
    ┌─────────────────────────────────────────────────────────────┐
    │                    Application Layer                        │
    │              (encrypt/decrypt application data)             │
    ├─────────────────────────────────────────────────────────────┤
    │                  Dtls_eio (this module)                     │
    │   ┌──────────────┐  ┌──────────────┐  ┌──────────────┐     │
    │   │Handshake Fib │  │ Timer Fiber  │  │ Recv Fiber   │     │
    │   └──────────────┘  └──────────────┘  └──────────────┘     │
    ├─────────────────────────────────────────────────────────────┤
    │               Dtls.t (Sans-IO State Machine)                │
    ├─────────────────────────────────────────────────────────────┤
    │                     UDP Transport                           │
    └─────────────────────────────────────────────────────────────┘

    @author Second Brain
    @since ocaml-webrtc 0.6.0
*)

(** {1 Types} *)

type send_fn = bytes -> unit
type recv_fn = unit -> bytes option

type t = {
  dtls: Dtls.t;
  mutable send_fn: send_fn option;
  mutable recv_fn: recv_fn option;
  mutable retransmit_deadline: float option;

  (* Callbacks *)
  mutable on_handshake_complete: (unit -> unit) option;
  mutable on_data: (bytes -> unit) option;
  mutable on_error: (string -> unit) option;
}

(** {1 Creation} *)

let create_client () =
  {
    dtls = Dtls.create Dtls.default_client_config;
    send_fn = None;
    recv_fn = None;
    retransmit_deadline = None;
    on_handshake_complete = None;
    on_data = None;
    on_error = None;
  }

let create_server () =
  {
    dtls = Dtls.create Dtls.default_server_config;
    send_fn = None;
    recv_fn = None;
    retransmit_deadline = None;
    on_handshake_complete = None;
    on_data = None;
    on_error = None;
  }

(** {1 Configuration} *)

let set_transport t ~send ~recv =
  t.send_fn <- Some send;
  t.recv_fn <- Some recv

(** {1 Callbacks} *)

let on_handshake_complete t f = t.on_handshake_complete <- Some f
let on_data t f = t.on_data <- Some f
let on_error t f = t.on_error <- Some f

(** {1 State Access} *)

let is_established t = Dtls.is_established t.dtls
let get_state t = Dtls.get_state t.dtls
let get_cipher_suite t = Dtls.get_cipher_suite t.dtls

(** {1 Internal: I/O Operations} *)

(** Create Dtls.io_ops from Eio primitives *)
let make_io_ops ~clock =
  {
    Dtls.send = (fun _ -> 0);  (* We handle sends manually via records *)
    recv = (fun _ -> Bytes.empty);
    now = (fun () -> Eio.Time.now clock);
    random = (fun n -> Mirage_crypto_rng.generate n |> Bytes.of_string);
    set_timer = (fun _ -> ());
    cancel_timer = (fun () -> ());
  }

(** Send DTLS records *)
let send_records t records =
  match t.send_fn with
  | Some send ->
    List.iter (fun record -> send record) records
  | None -> ()

(** {1 Handshake} *)

(** Run DTLS handshake as client *)
let handshake_client t ~clock =
  let io_ops = make_io_ops ~clock in

  (* Start handshake - send ClientHello *)
  Dtls.run_with_io ~ops:io_ops (fun () ->
    match Dtls.start_handshake t.dtls with
    | Ok records -> send_records t records
    | Error e ->
      Option.iter (fun f -> f e) t.on_error
  );

  (* Set initial retransmit timer (1 second) *)
  t.retransmit_deadline <- Some (Eio.Time.now clock +. 1.0)

(** Process incoming DTLS record *)
let handle_record t ~clock record =
  let io_ops = make_io_ops ~clock in

  Dtls.run_with_io ~ops:io_ops (fun () ->
    match Dtls.handle_record t.dtls record with
    | Ok (records, app_data) ->
      (* Send any response records *)
      send_records t records;

      (* Deliver application data *)
      Option.iter (fun data ->
        Option.iter (fun f -> f data) t.on_data
      ) app_data;

      (* Check if handshake just completed *)
      if Dtls.is_established t.dtls then begin
        t.retransmit_deadline <- None;
        Option.iter (fun f -> f ()) t.on_handshake_complete
      end else begin
        (* Reset retransmit timer on progress *)
        t.retransmit_deadline <- Some (Eio.Time.now clock +. 1.0)
      end

    | Error e ->
      Option.iter (fun f -> f e) t.on_error
  )

(** Process incoming record as server *)
let handle_record_server t ~clock ~client_addr record =
  let io_ops = make_io_ops ~clock in

  Dtls.run_with_io ~ops:io_ops (fun () ->
    match Dtls.handle_record_as_server t.dtls record ~client_addr with
    | Ok (records, app_data) ->
      send_records t records;
      Option.iter (fun data ->
        Option.iter (fun f -> f data) t.on_data
      ) app_data;

      if Dtls.is_established t.dtls then begin
        t.retransmit_deadline <- None;
        Option.iter (fun f -> f ()) t.on_handshake_complete
      end

    | Error e ->
      Option.iter (fun f -> f e) t.on_error
  )

(** Check for retransmission timeout *)
let check_retransmit t ~clock =
  match t.retransmit_deadline with
  | Some deadline when Eio.Time.now clock >= deadline ->
    (* Retransmit last flight *)
    let io_ops = make_io_ops ~clock in
    Dtls.run_with_io ~ops:io_ops (fun () ->
      match Dtls.handle_retransmit_timeout t.dtls with
      | Ok records ->
        send_records t records;
        (* Exponential backoff: double the timeout, max 60s *)
        let current_timeout = deadline -. (Eio.Time.now clock -. 1.0) in
        let new_timeout = min 60.0 (current_timeout *. 2.0) in
        t.retransmit_deadline <- Some (Eio.Time.now clock +. new_timeout)
      | Error _ ->
        (* Give up after too many retries *)
        t.retransmit_deadline <- None
    )
  | _ -> ()

(** {1 Data Transfer} *)

(** Encrypt and send application data *)
let send t data =
  if not (Dtls.is_established t.dtls) then
    Error "Handshake not complete"
  else
    match Dtls.encrypt t.dtls data with
    | Ok encrypted ->
      begin match t.send_fn with
      | Some send ->
        send encrypted;
        Ok (Bytes.length data)
      | None -> Error "No transport configured"
      end
    | Error e -> Error e

(** Decrypt received data *)
let decrypt t data =
  Dtls.decrypt t.dtls data

(** {1 Event Loop Integration} *)

(** Process pending events - call from main loop *)
let tick t ~clock =
  (* Check retransmit timer *)
  check_retransmit t ~clock;

  (* Try to receive *)
  match t.recv_fn with
  | Some recv ->
    begin match recv () with
    | Some data -> handle_record t ~clock data
    | None -> ()
    end
  | None -> ()

(** Run client handshake to completion *)
let run_client_handshake t ~clock ~timeout_s =
  let deadline = Eio.Time.now clock +. timeout_s in

  handshake_client t ~clock;

  let rec loop () =
    if Dtls.is_established t.dtls then
      Ok ()
    else if Eio.Time.now clock >= deadline then
      Error "Handshake timeout"
    else begin
      tick t ~clock;
      Eio.Time.sleep clock 0.010;  (* 10ms *)
      loop ()
    end
  in
  loop ()

(** Run server - wait for client and complete handshake *)
let run_server_handshake t ~clock ~client_addr ~timeout_s =
  let deadline = Eio.Time.now clock +. timeout_s in

  let rec loop () =
    if Dtls.is_established t.dtls then
      Ok ()
    else if Eio.Time.now clock >= deadline then
      Error "Handshake timeout"
    else begin
      (* Check retransmit *)
      check_retransmit t ~clock;

      (* Try to receive *)
      begin match t.recv_fn with
      | Some recv ->
        begin match recv () with
        | Some data -> handle_record_server t ~clock ~client_addr data
        | None -> ()
        end
      | None -> ()
      end;

      Eio.Time.sleep clock 0.010;
      loop ()
    end
  in
  loop ()

(** {1 Full Fiber-based Operation} *)

(** Run DTLS with Eio fibers *)
let run t ~sw:_ ~clock ~role ~client_addr ~on_established =
  (* Initialize RNG if not done *)
  (try Mirage_crypto_rng_unix.use_default () with _ -> ());

  match role with
  | `Client ->
    begin match run_client_handshake t ~clock ~timeout_s:30.0 with
    | Ok () -> on_established ()
    | Error e -> Option.iter (fun f -> f e) t.on_error
    end

  | `Server ->
    begin match run_server_handshake t ~clock ~client_addr ~timeout_s:30.0 with
    | Ok () -> on_established ()
    | Error e -> Option.iter (fun f -> f e) t.on_error
    end

(** Export keying material for SRTP (RFC 5764) *)
let export_keying_material t ~label ~context ~length =
  Dtls.export_keying_material t.dtls ~label ~context ~length
