(** SCTP 4-Way Handshake - RFC 4960 Section 5

    Implements connection establishment with state cookie for DoS protection.

    Handshake flow:
    {v
    Client                    Server
      |                         |
      |------ INIT ------------>|  (1) Initiate Tag, TSN, streams
      |<----- INIT-ACK ---------|  (2) Cookie + peer info
      |------ COOKIE-ECHO ----->|  (3) Return cookie
      |<----- COOKIE-ACK -------|  (4) Connection established
      |                         |
    v}

    Security: Server is STATELESS until COOKIE-ECHO, preventing SYN floods.

    @author Second Brain
    @since RFC 4960 compliance
*)

(** {1 Types} *)

(** Connection state machine *)
type state =
  | Closed
  | CookieWait    (* Client: sent INIT, waiting for INIT-ACK *)
  | CookieEchoed  (* Client: sent COOKIE-ECHO, waiting for COOKIE-ACK *)
  | Established   (* Both: connection ready *)
  | ShutdownPending
  | ShutdownSent
  | ShutdownReceived
  | ShutdownAckSent

(** INIT chunk parameters - RFC 4960 Section 3.3.2 *)
type init_params = {
  initiate_tag: int32;          (* Random verification tag *)
  a_rwnd: int32;                (* Advertised receiver window *)
  num_outbound_streams: int;    (* OS value *)
  num_inbound_streams: int;     (* MIS value *)
  initial_tsn: int32;           (* Initial TSN *)
}

(** State cookie - encodes all association info for stateless server *)
type state_cookie = {
  creation_time: float;         (* Unix timestamp *)
  lifespan_ms: int;             (* Cookie validity (default 60000ms) *)
  peer_vtag: int32;             (* Peer's verification tag from INIT *)
  local_vtag: int32;            (* Our verification tag for INIT-ACK *)
  peer_initial_tsn: int32;      (* Peer's initial TSN *)
  local_initial_tsn: int32;     (* Our initial TSN *)
  peer_rwnd: int32;             (* Peer's rwnd *)
  local_rwnd: int32;            (* Our rwnd *)
  hmac: bytes;                  (* HMAC-SHA256 for integrity *)
}

(** Association (connection) state *)
type association = {
  mutable state: state;
  local_vtag: int32;            (* Our verification tag *)
  peer_vtag: int32;             (* Peer's verification tag *)
  local_initial_tsn: int32;     (* Our initial TSN *)
  peer_initial_tsn: int32;      (* Peer's initial TSN *)
  mutable local_rwnd: int32;
  mutable peer_rwnd: int32;
  num_outbound_streams: int;
  num_inbound_streams: int;
}

(** {1 Chunk Types - RFC 4960 Section 3.2} *)

let chunk_type_init = 1
let chunk_type_init_ack = 2
let chunk_type_cookie_echo = 10
let chunk_type_cookie_ack = 11

(** {1 Random Generation} *)

(** Generate random verification tag - RFC 4960 Section 5.3.1 *)
let random_vtag () =
  let r = Random.int32 0x7FFFFFFFl in
  if r = 0l then 1l else r  (* Must not be 0 *)

(** Generate random initial TSN - same as vtag *)
let random_initial_tsn () = random_vtag ()

(** {1 HMAC for Cookie Integrity} *)

(** Default secret - INSECURE, only for development/testing *)
let default_hmac_secret = "sctp-cookie-secret-DO-NOT-USE-IN-PRODUCTION"

(** Secret key for HMAC - must be set before production use *)
let hmac_secret : bytes ref = ref (Bytes.of_string default_hmac_secret)

(** Track if secret was explicitly set *)
let hmac_secret_configured = ref false

(** Set HMAC secret from string. Call this at startup before any connections. *)
let set_hmac_secret secret =
  hmac_secret := Bytes.of_string secret;
  hmac_secret_configured := true

(** Initialize HMAC secret from environment variable SCTP_HMAC_SECRET.
    Returns true if successfully loaded, false if not set.
    @raise Failure if env var is set but empty *)
let init_hmac_secret_from_env () =
  match Sys.getenv_opt "SCTP_HMAC_SECRET" with
  | Some s when String.length s > 0 ->
    set_hmac_secret s;
    Ok true
  | Some _ -> Error "SCTP_HMAC_SECRET is set but empty"
  | None -> Ok false

(** HMAC-SHA256 for cookie integrity (RFC 4960 §5.1.3) *)
let compute_hmac data =
  (* Warn once if using default secret *)
  if not !hmac_secret_configured then
    Printf.eprintf "[SECURITY WARNING] Using default HMAC secret - set SCTP_HMAC_SECRET for production\n%!";
  let key = Bytes.to_string !hmac_secret in
  let data_str = Bytes.to_string data in
  let mac = Digestif.SHA256.hmac_string ~key data_str in
  Bytes.of_string (Digestif.SHA256.to_raw_string mac)

let verify_hmac data expected_hmac =
  Bytes.equal (compute_hmac data) expected_hmac

(** {1 Cookie Encoding/Decoding} *)

(** Encode state cookie to bytes *)
let encode_cookie cookie =
  (* Format: timestamp(8) + lifespan(4) + peer_vtag(4) + local_vtag(4) +
             peer_tsn(4) + local_tsn(4) + peer_rwnd(4) + local_rwnd(4) + hmac(32) = 68 bytes *)
  let buf = Bytes.create 68 in

  (* Creation time as int64 bits *)
  let time_bits = Int64.bits_of_float cookie.creation_time in
  for i = 0 to 7 do
    Bytes.set buf i (Char.chr (Int64.to_int (Int64.shift_right_logical time_bits (i * 8)) land 0xFF))
  done;

  (* Lifespan *)
  Bytes.set_int32_be buf 8 (Int32.of_int cookie.lifespan_ms);

  (* Tags and TSNs *)
  Bytes.set_int32_be buf 12 cookie.peer_vtag;
  Bytes.set_int32_be buf 16 cookie.local_vtag;
  Bytes.set_int32_be buf 20 cookie.peer_initial_tsn;
  Bytes.set_int32_be buf 24 cookie.local_initial_tsn;
  Bytes.set_int32_be buf 28 cookie.peer_rwnd;
  Bytes.set_int32_be buf 32 cookie.local_rwnd;

  (* HMAC over the data portion (first 36 bytes) *)
  let data_portion = Bytes.sub buf 0 36 in
  let hmac = compute_hmac data_portion in
  Bytes.blit hmac 0 buf 36 32;

  buf

(** Decode state cookie from bytes *)
let decode_cookie buf =
  if Bytes.length buf <> 68 then
    Error "Invalid cookie length"
  else begin
    (* Extract fields *)
    let time_bits = ref 0L in
    for i = 0 to 7 do
      time_bits := Int64.logor !time_bits
        (Int64.shift_left (Int64.of_int (Char.code (Bytes.get buf i))) (i * 8))
    done;
    let creation_time = Int64.float_of_bits !time_bits in

    let lifespan_ms = Int32.to_int (Bytes.get_int32_be buf 8) in
    let peer_vtag = Bytes.get_int32_be buf 12 in
    let local_vtag = Bytes.get_int32_be buf 16 in
    let peer_initial_tsn = Bytes.get_int32_be buf 20 in
    let local_initial_tsn = Bytes.get_int32_be buf 24 in
    let peer_rwnd = Bytes.get_int32_be buf 28 in
    let local_rwnd = Bytes.get_int32_be buf 32 in
    let hmac = Bytes.sub buf 36 32 in

    (* Verify HMAC *)
    let data_portion = Bytes.sub buf 0 36 in
    if not (verify_hmac data_portion hmac) then
      Error "Cookie HMAC verification failed"
    else begin
      (* Check expiry *)
      let now = Unix.gettimeofday () in
      let age_ms = (now -. creation_time) *. 1000.0 in
      if age_ms > float_of_int lifespan_ms then
        Error "Cookie expired"
      else
        Ok {
          creation_time;
          lifespan_ms;
          peer_vtag;
          local_vtag;
          peer_initial_tsn;
          local_initial_tsn;
          peer_rwnd;
          local_rwnd;
          hmac;
        }
    end
  end

(** {1 INIT/INIT-ACK Encoding} *)

(** Encode INIT or INIT-ACK chunk *)
let encode_init ~chunk_type params =
  (* Chunk format:
     - Type (1) + Flags (1) + Length (2) = 4 bytes header
     - Initiate Tag (4) + A-RWND (4) + OS (2) + MIS (2) + Initial TSN (4) = 16 bytes
     Total = 20 bytes minimum *)
  let buf = Bytes.create 20 in

  Bytes.set buf 0 (Char.chr chunk_type);
  Bytes.set buf 1 (Char.chr 0);  (* flags *)
  Bytes.set_int16_be buf 2 20;   (* length *)

  Bytes.set_int32_be buf 4 params.initiate_tag;
  Bytes.set_int32_be buf 8 params.a_rwnd;
  Bytes.set_int16_be buf 12 params.num_outbound_streams;
  Bytes.set_int16_be buf 14 params.num_inbound_streams;
  Bytes.set_int32_be buf 16 params.initial_tsn;

  buf

let encode_init_chunk params = encode_init ~chunk_type:chunk_type_init params

(** Encode INIT-ACK with cookie *)
let encode_init_ack params cookie =
  let init_buf = encode_init ~chunk_type:chunk_type_init_ack params in
  let cookie_buf = encode_cookie cookie in

  (* Add cookie as parameter: Type (2) + Length (2) + Cookie (68) = 72 bytes *)
  let result = Bytes.create (20 + 4 + 68) in
  Bytes.blit init_buf 0 result 0 20;

  (* Update chunk length *)
  Bytes.set_int16_be result 2 (20 + 4 + 68);

  (* Cookie parameter: Type = 7, Length = 72 *)
  Bytes.set_int16_be result 20 7;  (* State Cookie parameter type *)
  Bytes.set_int16_be result 22 72; (* 4 + 68 *)
  Bytes.blit cookie_buf 0 result 24 68;

  result

(** Decode INIT chunk *)
let decode_init buf =
  if Bytes.length buf < 20 then
    Error "INIT chunk too short"
  else begin
    let chunk_type = Char.code (Bytes.get buf 0) in
    if chunk_type <> chunk_type_init && chunk_type <> chunk_type_init_ack then
      Error (Printf.sprintf "Not an INIT chunk (type=%d)" chunk_type)
    else
      Ok {
        initiate_tag = Bytes.get_int32_be buf 4;
        a_rwnd = Bytes.get_int32_be buf 8;
        num_outbound_streams = Bytes.get_int16_be buf 12;
        num_inbound_streams = Bytes.get_int16_be buf 14;
        initial_tsn = Bytes.get_int32_be buf 16;
      }
  end

(** {1 COOKIE-ECHO/COOKIE-ACK} *)

(** Encode COOKIE-ECHO *)
let encode_cookie_echo cookie =
  let cookie_buf = encode_cookie cookie in
  let buf = Bytes.create (4 + 68) in

  Bytes.set buf 0 (Char.chr chunk_type_cookie_echo);
  Bytes.set buf 1 (Char.chr 0);
  Bytes.set_int16_be buf 2 (4 + 68);
  Bytes.blit cookie_buf 0 buf 4 68;

  buf

(** Decode COOKIE-ECHO *)
let decode_cookie_echo buf =
  if Bytes.length buf < 72 then
    Error "COOKIE-ECHO too short"
  else begin
    let chunk_type = Char.code (Bytes.get buf 0) in
    if chunk_type <> chunk_type_cookie_echo then
      Error "Not a COOKIE-ECHO chunk"
    else
      decode_cookie (Bytes.sub buf 4 68)
  end

(** Encode COOKIE-ACK *)
let encode_cookie_ack () =
  let buf = Bytes.create 4 in
  Bytes.set buf 0 (Char.chr chunk_type_cookie_ack);
  Bytes.set buf 1 (Char.chr 0);
  Bytes.set_int16_be buf 2 4;
  buf

(** {1 Handshake State Machine} *)

(** Default association parameters *)
let default_rwnd = Int32.mul 256l 1024l  (* 256 KB *)
let default_streams = 10
let cookie_lifespan_ms = 60000  (* 60 seconds *)

(** Client: Initiate connection by sending INIT *)
let client_init () =
  let params = {
    initiate_tag = random_vtag ();
    a_rwnd = default_rwnd;
    num_outbound_streams = default_streams;
    num_inbound_streams = default_streams;
    initial_tsn = random_initial_tsn ();
  } in
  let init_chunk = encode_init_chunk params in
  (params, init_chunk, CookieWait)

(** Server: Process INIT and generate INIT-ACK with cookie (stateless!) *)
let server_process_init init_buf =
  match decode_init init_buf with
  | Error e -> Error e
  | Ok peer_params ->
    (* Generate our parameters *)
    let local_params = {
      initiate_tag = random_vtag ();
      a_rwnd = default_rwnd;
      num_outbound_streams = min peer_params.num_inbound_streams default_streams;
      num_inbound_streams = min peer_params.num_outbound_streams default_streams;
      initial_tsn = random_initial_tsn ();
    } in

    (* Create state cookie - encodes everything needed to recreate state *)
    let cookie = {
      creation_time = Unix.gettimeofday ();
      lifespan_ms = cookie_lifespan_ms;
      peer_vtag = peer_params.initiate_tag;
      local_vtag = local_params.initiate_tag;
      peer_initial_tsn = peer_params.initial_tsn;
      local_initial_tsn = local_params.initial_tsn;
      peer_rwnd = peer_params.a_rwnd;
      local_rwnd = local_params.a_rwnd;
      hmac = Bytes.empty;  (* Will be computed in encode *)
    } in

    let init_ack = encode_init_ack local_params cookie in
    Ok (local_params, init_ack)

(** Client: Process INIT-ACK and generate COOKIE-ECHO *)
let client_process_init_ack init_ack_buf local_params =
  if Bytes.length init_ack_buf < 92 then
    Error "INIT-ACK too short"
  else begin
    match decode_init init_ack_buf with
    | Error e -> Error e
    | Ok peer_params ->
      (* Extract cookie (starts at offset 24) *)
      let cookie_buf = Bytes.sub init_ack_buf 24 68 in
      match decode_cookie cookie_buf with
      | Error e -> Error e
      | Ok cookie ->
        let cookie_echo = encode_cookie_echo cookie in
        let assoc = {
          state = CookieEchoed;
          local_vtag = local_params.initiate_tag;
          peer_vtag = peer_params.initiate_tag;
          local_initial_tsn = local_params.initial_tsn;
          peer_initial_tsn = peer_params.initial_tsn;
          local_rwnd = local_params.a_rwnd;
          peer_rwnd = peer_params.a_rwnd;
          num_outbound_streams = min local_params.num_outbound_streams peer_params.num_inbound_streams;
          num_inbound_streams = min local_params.num_inbound_streams peer_params.num_outbound_streams;
        } in
        Ok (assoc, cookie_echo)
  end

(** Server: Process COOKIE-ECHO and generate COOKIE-ACK *)
let server_process_cookie_echo cookie_echo_buf =
  match decode_cookie_echo cookie_echo_buf with
  | Error e -> Error e
  | Ok cookie ->
    (* Recreate association from cookie - server was stateless until now! *)
    let assoc = {
      state = Established;
      local_vtag = cookie.local_vtag;
      peer_vtag = cookie.peer_vtag;
      local_initial_tsn = cookie.local_initial_tsn;
      peer_initial_tsn = cookie.peer_initial_tsn;
      local_rwnd = cookie.local_rwnd;
      peer_rwnd = cookie.peer_rwnd;
      num_outbound_streams = default_streams;
      num_inbound_streams = default_streams;
    } in
    let cookie_ack = encode_cookie_ack () in
    Ok (assoc, cookie_ack)

(** Client: Process COOKIE-ACK and transition to Established *)
let client_process_cookie_ack cookie_ack_buf assoc =
  if Bytes.length cookie_ack_buf < 4 then
    Error "COOKIE-ACK too short"
  else begin
    let chunk_type = Char.code (Bytes.get cookie_ack_buf 0) in
    if chunk_type <> chunk_type_cookie_ack then
      Error "Not a COOKIE-ACK chunk"
    else begin
      assoc.state <- Established;
      Ok assoc
    end
  end

(** {1 Utility} *)

let state_to_string = function
  | Closed -> "CLOSED"
  | CookieWait -> "COOKIE-WAIT"
  | CookieEchoed -> "COOKIE-ECHOED"
  | Established -> "ESTABLISHED"
  | ShutdownPending -> "SHUTDOWN-PENDING"
  | ShutdownSent -> "SHUTDOWN-SENT"
  | ShutdownReceived -> "SHUTDOWN-RECEIVED"
  | ShutdownAckSent -> "SHUTDOWN-ACK-SENT"

let pp_association fmt assoc =
  Format.fprintf fmt "Association{state=%s, local_vtag=%ld, peer_vtag=%ld, \
                      local_tsn=%ld, peer_tsn=%ld}"
    (state_to_string assoc.state)
    assoc.local_vtag assoc.peer_vtag
    assoc.local_initial_tsn assoc.peer_initial_tsn
