(** UDP Transport Layer

    Provides actual network I/O for WebRTC using Eio.
    This is the real transport layer that sends/receives UDP packets.

    @author Second Brain
    @since ocaml-webrtc 0.3.0
*)

(** {1 Types} *)

type endpoint = {
  host: string;
  port: int;
}

type stats = {
  mutable packets_sent: int;
  mutable packets_recv: int;
  mutable bytes_sent: int;
  mutable bytes_recv: int;
  mutable send_errors: int;
  mutable recv_errors: int;
}

type t = {
  socket: Unix.file_descr;
  local_endpoint: endpoint;
  mutable remote_endpoint: endpoint option;
  mutable remote_sockaddr: Unix.sockaddr option;  (* Cached for performance *)
  stats: stats;
  mutable closed: bool;
}

(** {1 Statistics} *)

let create_stats () = {
  packets_sent = 0;
  packets_recv = 0;
  bytes_sent = 0;
  bytes_recv = 0;
  send_errors = 0;
  recv_errors = 0;
}

let get_stats t = t.stats

(** {1 Socket Operations} *)

let create ?(host = "0.0.0.0") ?(port = 0) () =
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.setsockopt socket Unix.SO_REUSEADDR true;

  (* Increase socket buffer sizes for high throughput *)
  (* Default is typically 8KB-64KB, we want 4MB for benchmarks *)
  (try Unix.setsockopt_int socket Unix.SO_SNDBUF (4 * 1024 * 1024) with _ -> ());
  (try Unix.setsockopt_int socket Unix.SO_RCVBUF (4 * 1024 * 1024) with _ -> ());

  (* Bind to local address *)
  let addr = Unix.inet_addr_of_string host in
  Unix.bind socket (Unix.ADDR_INET (addr, port));

  (* Get actual bound port *)
  let local_port = match Unix.getsockname socket with
    | Unix.ADDR_INET (_, p) -> p
    | _ -> port
  in

  (* Set non-blocking for async compatibility *)
  Unix.set_nonblock socket;

  {
    socket;
    local_endpoint = { host; port = local_port };
    remote_endpoint = None;
    remote_sockaddr = None;
    stats = create_stats ();
    closed = false;
  }

let bind t ~host ~port =
  let addr = Unix.inet_addr_of_string host in
  Unix.bind t.socket (Unix.ADDR_INET (addr, port))

let connect t ~host ~port =
  t.remote_endpoint <- Some { host; port };
  let addr = Unix.inet_addr_of_string host in
  let sockaddr = Unix.ADDR_INET (addr, port) in
  t.remote_sockaddr <- Some sockaddr;
  Unix.connect t.socket sockaddr

let local_endpoint t = t.local_endpoint

let remote_endpoint t = t.remote_endpoint

(** {1 Send/Receive} *)

let send t ~data ~host ~port =
  if t.closed then Error "Transport closed"
  else
    try
      let addr = Unix.inet_addr_of_string host in
      let len = Bytes.length data in
      let sent = Unix.sendto t.socket data 0 len [] (Unix.ADDR_INET (addr, port)) in
      t.stats.packets_sent <- t.stats.packets_sent + 1;
      t.stats.bytes_sent <- t.stats.bytes_sent + sent;
      Ok sent
    with
    | Unix.Unix_error (Unix.EAGAIN, _, _)
    | Unix.Unix_error (Unix.EWOULDBLOCK, _, _) ->
      Error "Would block"
    | Unix.Unix_error (e, _, _) ->
      t.stats.send_errors <- t.stats.send_errors + 1;
      Error (Unix.error_message e)

let send_connected t ~data =
  if t.closed then Error "Transport closed"
  else if t.remote_endpoint = None then Error "Not connected"
  else
    try
      let len = Bytes.length data in
      (* Use Unix.send for connected socket, not sendto *)
      let sent = Unix.send t.socket data 0 len [] in
      t.stats.packets_sent <- t.stats.packets_sent + 1;
      t.stats.bytes_sent <- t.stats.bytes_sent + sent;
      Ok sent
    with
    | Unix.Unix_error (Unix.EAGAIN, _, _)
    | Unix.Unix_error (Unix.EWOULDBLOCK, _, _) ->
      Error "Would block"
    | Unix.Unix_error (e, _, _) ->
      t.stats.send_errors <- t.stats.send_errors + 1;
      Error (Unix.error_message e)

(** Send from buffer view - zero-copy (no Bytes.sub needed) *)
let send_view t ~buf ~off ~len =
  if t.closed then Error "Transport closed"
  else if t.remote_endpoint = None then Error "Not connected"
  else
    try
      let sent = Unix.send t.socket buf off len [] in
      t.stats.packets_sent <- t.stats.packets_sent + 1;
      t.stats.bytes_sent <- t.stats.bytes_sent + sent;
      Ok sent
    with
    | Unix.Unix_error (Unix.EAGAIN, _, _)
    | Unix.Unix_error (Unix.EWOULDBLOCK, _, _) ->
      Error "Would block"
    | Unix.Unix_error (e, _, _) ->
      t.stats.send_errors <- t.stats.send_errors + 1;
      Error (Unix.error_message e)

let recv t ~buf =
  if t.closed then Error "Transport closed"
  else
    try
      let len, addr = Unix.recvfrom t.socket buf 0 (Bytes.length buf) [] in
      t.stats.packets_recv <- t.stats.packets_recv + 1;
      t.stats.bytes_recv <- t.stats.bytes_recv + len;
      let (host, port) = match addr with
        | Unix.ADDR_INET (a, p) -> (Unix.string_of_inet_addr a, p)
        | _ -> ("unknown", 0)
      in
      Ok (len, { host; port })
    with
    | Unix.Unix_error (Unix.EAGAIN, _, _)
    | Unix.Unix_error (Unix.EWOULDBLOCK, _, _) ->
      Error "Would block"
    | Unix.Unix_error (e, _, _) ->
      t.stats.recv_errors <- t.stats.recv_errors + 1;
      Error (Unix.error_message e)

(** Blocking receive with timeout *)
let recv_timeout t ~buf ~timeout_ms =
  if t.closed then Error "Transport closed"
  else begin
    (* Use select for timeout *)
    let timeout = float_of_int timeout_ms /. 1000.0 in
    let ready, _, _ = Unix.select [t.socket] [] [] timeout in
    if ready = [] then
      Error "Timeout"
    else
      recv t ~buf
  end

(** {1 Lifecycle} *)

let close t =
  if not t.closed then begin
    t.closed <- true;
    Unix.close t.socket
  end

let is_closed t = t.closed

(** {1 Utilities} *)

let pp_endpoint fmt ep =
  Format.fprintf fmt "%s:%d" ep.host ep.port

let pp_stats fmt s =
  Format.fprintf fmt "sent=%d/%dB recv=%d/%dB errors=%d/%d"
    s.packets_sent s.bytes_sent
    s.packets_recv s.bytes_recv
    s.send_errors s.recv_errors
