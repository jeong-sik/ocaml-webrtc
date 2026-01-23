(** SCTP Transport Layer

    Integrates SCTP protocol with UDP transport for real network I/O.
    This provides the complete data path for WebRTC Data Channels.

    Architecture:
    - Application sends data via send_data
    - SCTP fragments into chunks, encodes packets
    - UDP transport sends actual bytes over network
    - Receive path reverses: UDP recv -> SCTP decode -> Application

    @author Second Brain
    @since ocaml-webrtc 0.3.0
*)

(** {1 Types} *)

type config =
  { local_port : int
  ; remote_port : int
  ; mtu : int
  ; max_message_size : int
  }

let default_config =
  { local_port = 5000
  ; remote_port = 5000
  ; mtu = 1280
  ; max_message_size = 262144 (* 256KB *)
  }
;;

type stats =
  { mutable messages_sent : int
  ; mutable messages_recv : int
  ; mutable bytes_sent : int
  ; mutable bytes_recv : int
  ; mutable chunks_sent : int
  ; mutable chunks_recv : int
  ; mutable retransmits : int
  ; mutable errors : int
  }

type t =
  { config : config
  ; udp : Udp_transport.t
  ; sctp : Sctp.association
  ; stats : stats
  ; mutable next_tsn : int32
  ; mutable next_stream_seq : int
  ; recv_buffer : bytes
  }

(** {1 Statistics} *)

let create_stats () =
  { messages_sent = 0
  ; messages_recv = 0
  ; bytes_sent = 0
  ; bytes_recv = 0
  ; chunks_sent = 0
  ; chunks_recv = 0
  ; retransmits = 0
  ; errors = 0
  }
;;

let get_stats t = t.stats

(** {1 Creation} *)

let create ?(config = default_config) ~host ~port () =
  let udp = Udp_transport.create ~host ~port () in
  let sctp_config = Sctp.{ default_config with mtu = config.mtu } in
  let sctp = Sctp.create sctp_config in
  { config
  ; udp
  ; sctp
  ; stats = create_stats ()
  ; next_tsn = 1000l
  ; next_stream_seq = 0
  ; recv_buffer = Bytes.create 65536
  }
;;

(** {1 Connection} *)

let connect t ~host ~port =
  Udp_transport.connect t.udp ~host ~port;
  (* Perform SCTP INIT handshake *)
  Sctp.establish t.sctp
;;

let local_endpoint t = Udp_transport.local_endpoint t.udp

(** {1 Data Transmission} *)

(** Send data with real network I/O *)
let send_data t ~stream_id ~data =
  let data_len = Bytes.length data in
  (* Fragment if needed *)
  let chunks =
    Sctp.fragment_data
      ~data
      ~stream_id
      ~stream_seq:t.next_stream_seq
      ~ppid:0x32l (* WebRTC String *)
      ~start_tsn:t.next_tsn
      ~mtu:t.config.mtu
  in
  t.next_stream_seq <- t.next_stream_seq + 1;
  let chunk_count = List.length chunks in
  t.next_tsn <- Int32.add t.next_tsn (Int32.of_int chunk_count);
  (* Encode and send each chunk - stop on first error *)
  let rec send_chunks acc = function
    | [] -> Ok acc
    | chunk :: rest ->
      let encoded = Sctp.encode_data_chunk chunk in
      (match Udp_transport.send_connected t.udp ~data:encoded with
       | Ok sent ->
         t.stats.chunks_sent <- t.stats.chunks_sent + 1;
         send_chunks (acc + sent) rest
       | Error e ->
         t.stats.errors <- t.stats.errors + 1;
         Error ("Send failed: " ^ e))
  in
  match send_chunks 0 chunks with
  | Error e -> Error e
  | Ok _total_sent ->
    t.stats.messages_sent <- t.stats.messages_sent + 1;
    t.stats.bytes_sent <- t.stats.bytes_sent + data_len;
    Ok data_len
;;

(** Send with batch encoding (more efficient) *)
let send_data_batch t ~stream_id ~data =
  let data_len = Bytes.length data in
  let chunks =
    Sctp.fragment_data
      ~data
      ~stream_id
      ~stream_seq:t.next_stream_seq
      ~ppid:0x32l
      ~start_tsn:t.next_tsn
      ~mtu:t.config.mtu
  in
  t.next_stream_seq <- t.next_stream_seq + 1;
  let chunk_count = List.length chunks in
  t.next_tsn <- Int32.add t.next_tsn (Int32.of_int chunk_count);
  (* Batch encode all chunks *)
  let packets = Sctp.encode_data_chunks_batch chunks ~mtu:t.config.mtu in
  (* Send each packet - stop on first error *)
  let rec send_packets acc = function
    | [] -> Ok acc
    | packet :: rest ->
      (match Udp_transport.send_connected t.udp ~data:packet with
       | Ok sent ->
         t.stats.chunks_sent <- t.stats.chunks_sent + 1;
         send_packets (acc + sent) rest
       | Error e ->
         t.stats.errors <- t.stats.errors + 1;
         Error ("Send failed: " ^ e))
  in
  match send_packets 0 packets with
  | Error e -> Error e
  | Ok _total_sent ->
    t.stats.messages_sent <- t.stats.messages_sent + 1;
    t.stats.bytes_sent <- t.stats.bytes_sent + data_len;
    Ok data_len
;;

(** {1 Data Reception} *)

(** Receive with timeout *)
let recv_data t ~timeout_ms =
  match Udp_transport.recv_timeout t.udp ~buf:t.recv_buffer ~timeout_ms with
  | Error e -> Error e
  | Ok (len, _from) ->
    let packet = Bytes.sub t.recv_buffer 0 len in
    (* Decode SCTP chunk *)
    (match Sctp.decode_data_chunk packet with
     | Error e -> Error e
     | Ok chunk ->
       t.stats.chunks_recv <- t.stats.chunks_recv + 1;
       t.stats.messages_recv <- t.stats.messages_recv + 1;
       t.stats.bytes_recv <- t.stats.bytes_recv + Bytes.length chunk.user_data;
       Ok chunk.user_data)
;;

(** Non-blocking receive *)
let try_recv_data t =
  match Udp_transport.recv t.udp ~buf:t.recv_buffer with
  | Error "Would block" -> None
  | Error _e ->
    (* Network errors in non-blocking receive are treated as "no data available" *)
    t.stats.errors <- t.stats.errors + 1;
    None
  | Ok (len, _from) ->
    let packet = Bytes.sub t.recv_buffer 0 len in
    (match Sctp.decode_data_chunk packet with
     | Error _ -> None
     | Ok chunk ->
       t.stats.chunks_recv <- t.stats.chunks_recv + 1;
       t.stats.messages_recv <- t.stats.messages_recv + 1;
       t.stats.bytes_recv <- t.stats.bytes_recv + Bytes.length chunk.user_data;
       Some chunk.user_data)
;;

(** {1 Lifecycle} *)

let close t = Udp_transport.close t.udp
let is_closed t = Udp_transport.is_closed t.udp

(** {1 Utilities} *)

let pp_stats fmt s =
  Format.fprintf
    fmt
    "msgs=%d/%d bytes=%d/%d chunks=%d/%d errs=%d"
    s.messages_sent
    s.messages_recv
    s.bytes_sent
    s.bytes_recv
    s.chunks_sent
    s.chunks_recv
    s.errors
;;
