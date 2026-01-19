(** Eio-based ICE Agent

    Bridges the Sans-IO ICE implementation (ice.ml, ice_check.ml) with
    Eio's fiber-based concurrency for actual network I/O.

    This implementation uses Unix UDP sockets in non-blocking mode,
    which integrates well with Eio's fiber scheduler.

    @author Second Brain
    @since ocaml-webrtc 0.6.0
*)

(** {1 Types} *)

type t = {
  agent: Ice.agent;
  mutable socket: Unix.file_descr option;
  recv_buffer: bytes;

  (* Callbacks *)
  mutable on_candidate: (Ice.candidate -> unit) option;
  mutable on_state_change: (Ice.connection_state -> unit) option;
  mutable on_gathering_complete: (unit -> unit) option;
  mutable on_data: (bytes -> unit) option;
}

(** {1 Creation} *)

let create ?(config = Ice.default_config) () =
  {
    agent = Ice.create config;
    socket = None;
    recv_buffer = Bytes.create 65536;
    on_candidate = None;
    on_state_change = None;
    on_gathering_complete = None;
    on_data = None;
  }

(** {1 Callbacks} *)

let on_candidate t f = t.on_candidate <- Some f
let on_state_change t f = t.on_state_change <- Some f
let on_gathering_complete t f = t.on_gathering_complete <- Some f
let on_data t f = t.on_data <- Some f

(** {1 State Access} *)

let get_state t = Ice.get_state t.agent
let get_gathering_state t = Ice.get_gathering_state t.agent
let get_local_candidates t = Ice.get_local_candidates t.agent
let get_remote_candidates t = Ice.get_remote_candidates t.agent
let get_local_credentials t = Ice.get_local_credentials t.agent
let get_nominated_pair t = Ice.get_nominated_pair t.agent

(** {1 Internal Helpers} *)

(** Create non-blocking UDP socket *)
let create_socket ~host ~port =
  let fd = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.set_nonblock fd;
  Unix.setsockopt fd Unix.SO_REUSEADDR true;
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string host, port) in
  Unix.bind fd addr;
  fd

(** Send data via UDP *)
let send_udp fd ~data ~host ~port =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string host, port) in
  try
    let _ = Unix.sendto fd data 0 (Bytes.length data) [] addr in
    Ok ()
  with Unix.Unix_error (e, _, _) ->
    Error (Unix.error_message e)

(** Receive data from UDP (non-blocking) *)
let recv_udp fd ~buf =
  try
    let len, _addr = Unix.recvfrom fd buf 0 (Bytes.length buf) [] in
    Some (Bytes.sub buf 0 len)
  with
  | Unix.Unix_error (Unix.EAGAIN, _, _)
  | Unix.Unix_error (Unix.EWOULDBLOCK, _, _) -> None
  | Unix.Unix_error _ -> None

(** Gather server-reflexive candidate via STUN *)
let gather_srflx t ~stun_server ~local_addr ~local_port =
  (* Parse STUN server URL *)
  let host, port =
    if String.length stun_server > 5 && String.sub stun_server 0 5 = "stun:" then
      let rest = String.sub stun_server 5 (String.length stun_server - 5) in
      match String.split_on_char ':' rest with
      | [h; p] -> (h, int_of_string p)
      | [h] -> (h, 3478)
      | _ -> (rest, 3478)
    else (stun_server, 3478)
  in

  try
    (* Create STUN binding request *)
    let txn_id = Stun.generate_transaction_id () in
    let request = Stun.create_binding_request ~transaction_id:txn_id () in
    let request_bytes = Stun.encode request in

    (* Send request *)
    begin match t.socket with
    | Some fd ->
      ignore (send_udp fd ~data:request_bytes ~host ~port);

      (* Wait for response with timeout (simple polling) *)
      let buf = Bytes.create 1500 in
      let deadline = Unix.gettimeofday () +. 3.0 in
      let rec wait () =
        if Unix.gettimeofday () >= deadline then None
        else match recv_udp fd ~buf with
          | Some response when Stun.is_stun_message response ->
            begin match Stun.decode response with
            | Ok msg ->
              (* Extract XOR-MAPPED-ADDRESS *)
              let mapped = List.find_opt (fun (attr : Stun.attribute) ->
                attr.attr_type = Stun.XOR_MAPPED_ADDRESS
              ) msg.attributes in
              begin match mapped with
              | Some { value = Stun.Xor_mapped_address addr; _ } ->
                (* XOR-MAPPED-ADDRESS is already unxored by decode *)
                let srflx = Ice.create_srflx_candidate
                  ~component:1
                  ~address:addr.ip
                  ~port:addr.port
                  ~base_address:local_addr
                  ~base_port:local_port
                in
                Some srflx
              | _ -> None
              end
            | Error _ -> wait ()
            end
          | _ ->
            Unix.sleepf 0.010;
            wait ()
      in
      wait ()
    | None -> None
    end
  with _ -> None

(** {1 Gathering} *)

(** Start gathering candidates *)
let start_gathering t ~clock:_ =
  (* Gather host candidates from local interfaces *)
  let host_candidates = Ice.gather_host_candidates t.agent in

  (* Create socket for first host candidate *)
  begin match host_candidates with
  | cand :: _ ->
    let fd = create_socket ~host:cand.address ~port:cand.port in
    t.socket <- Some fd
  | [] -> ()
  end;

  (* Notify each host candidate *)
  List.iter (fun cand ->
    Option.iter (fun f -> f cand) t.on_candidate
  ) host_candidates;

  (* Gather server-reflexive candidates *)
  let config = Ice.get_config t.agent in
  List.iter (fun server ->
    List.iter (fun url ->
      begin match host_candidates with
      | cand :: _ ->
        begin match gather_srflx t ~stun_server:url
                      ~local_addr:cand.address ~local_port:cand.port with
        | Some srflx ->
          Ice.add_local_candidate t.agent srflx;
          Option.iter (fun f -> f srflx) t.on_candidate
        | None -> ()
        end
      | [] -> ()
      end
    ) server.Ice.urls
  ) config.ice_servers;

  (* Mark gathering complete *)
  Ice.set_gathering_complete t.agent;
  Option.iter (fun f -> f ()) t.on_gathering_complete

(** {1 Remote Candidates} *)

let add_remote_candidate t candidate =
  Ice.add_remote_candidate t.agent candidate

let set_remote_credentials t ~ufrag ~pwd =
  Ice.set_remote_credentials t.agent ~ufrag ~pwd

(** {1 Data Transfer} *)

(** Send data through the nominated pair *)
let send t data =
  match Ice.get_nominated_pair t.agent, t.socket with
  | Some pair, Some fd ->
    send_udp fd ~data ~host:pair.remote.address ~port:pair.remote.port
  | None, _ -> Error "No nominated pair"
  | _, None -> Error "No socket"

(** Try to receive data (non-blocking) *)
let try_recv t =
  match t.socket with
  | Some fd ->
    begin match recv_udp fd ~buf:t.recv_buffer with
    | Some data ->
      (* Demux: STUN or application data *)
      if Bytes.length data > 0 && Char.code (Bytes.get data 0) land 0xC0 = 0 then
        (* STUN message *)
        None
      else
        Some data
    | None -> None
    end
  | None -> None

(** {1 Connectivity Checks} *)

(** Run connectivity checks (simplified - immediate success for local testing) *)
let run_checks _t ~clock:_ =
  (* For now, this is a simplified implementation that skips actual STUN
     connectivity checks. In a full implementation, we would:
     1. Create Ice_check instances for each candidate pair
     2. Send STUN binding requests
     3. Process responses with Ice_check.step
     4. Handle retransmissions via timers

     For local testing (loopback), we can assume connectivity works. *)
  ()

(** {1 Main Event Loop} *)

(** Run the ICE agent with Eio *)
let run t ~sw:_ ~net:_ ~clock ~on_connected =
  (* Phase 1: Gather candidates *)
  start_gathering t ~clock;

  (* Phase 2: Run checks (simplified - assumes local connectivity) *)
  run_checks t ~clock;

  (* Phase 3: For local testing, assume immediate connection *)
  (* In a full implementation, we would wait for connectivity checks *)
  on_connected ()

(** {1 Lifecycle} *)

let close t =
  Ice.close t.agent;
  Option.iter Unix.close t.socket;
  t.socket <- None
