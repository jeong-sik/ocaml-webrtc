(** DTLS-SRTP Media Loopback Example

    Demonstrates:
    - DTLS handshake
    - DTLS-SRTP key export
    - SRTP RTP send/receive
    - SRTCP RTCP send/receive

    Usage:
      Server: dune exec ./examples/media_loopback.exe -- server 12345
      Client: dune exec ./examples/media_loopback.exe -- client 127.0.0.1 12345
*)

open Webrtc

let profile = Srtp.SRTP_AES128_CM_HMAC_SHA1_80
let payload_type = 111
let client_ssrc = 0x11223344l
let server_ssrc = 0x55667788l

let random_bytes n =
  let b = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set_uint8 b i (Random.int 256)
  done;
  b
;;

let addr_of_sockaddr = function
  | Unix.ADDR_INET (addr, port) -> Unix.string_of_inet_addr addr, port
  | _ -> "0.0.0.0", 0
;;

let send_to sock (ip, port) data =
  let addr = Unix.ADDR_INET (Unix.inet_addr_of_string ip, port) in
  Unix.sendto sock data 0 (Bytes.length data) [] addr
;;

let is_dtls data =
  if Bytes.length data = 0
  then false
  else (
    let first = Bytes.get_uint8 data 0 in
    first >= 20 && first <= 23)
;;

let is_rtcp data =
  if Bytes.length data < 2
  then false
  else (
    let pt = Bytes.get_uint8 data 1 in
    pt >= 192 && pt <= 223)
;;

let run_server port =
  Printf.printf "DTLS-SRTP Media Loopback Server\n%!";
  Printf.printf "Listening on port %d...\n%!" port;
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_any, port));
  let buf = Bytes.create 65536 in
  let client_addr = ref ("0.0.0.0", 0) in
  let dtls = Dtls.create Dtls.default_server_config in
  let ops : Dtls.io_ops =
    { send = (fun data -> send_to sock !client_addr data)
    ; recv = (fun _ -> Bytes.empty)
    ; now = Unix.gettimeofday
    ; random = random_bytes
    ; set_timer = (fun _ -> ())
    ; cancel_timer = (fun () -> ())
    }
  in
  let rec handshake () =
    let len, src = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
    let data = Bytes.sub buf 0 len in
    let from_addr = addr_of_sockaddr src in
    client_addr := from_addr;
    Dtls.run_with_io ~ops (fun () ->
      match Dtls.handle_record_as_server dtls data ~client_addr:from_addr with
      | Ok (responses, _) ->
        List.iter (fun r -> ignore (ops.send r)) responses;
        if Dtls.is_established dtls then Printf.printf "DTLS handshake complete.\n%!"
      | Error e -> Log.error "DTLS error: %s" e);
    if not (Dtls.is_established dtls) then handshake ()
  in
  handshake ();
  let local_keys, remote_keys =
    match Dtls_srtp.session_keys_of_dtls ~dtls ~role:Dtls_srtp.Server ~profile () with
    | Ok keys -> keys
    | Error e -> failwith ("DTLS-SRTP export failed: " ^ e)
  in
  let media =
    Media_transport.create
      ~profile
      ~local_keys
      ~remote_keys
      ~ssrc:server_ssrc
      ~payload_type
  in
  let received = ref 0 in
  while !received < 3 do
    let len, _ = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
    let data = Bytes.sub buf 0 len in
    if is_dtls data
    then Printf.printf "Ignoring DTLS packet after handshake.\n%!"
    else if is_rtcp data
    then Printf.printf "Server received SRTCP (unexpected).\n%!"
    else (
      match Media_transport.unprotect_rtp media ~packet:data with
      | Ok pkt ->
        let payload = Bytes.to_string pkt.Rtp.payload in
        Printf.printf "RTP seq=%d payload=%s\n%!" pkt.Rtp.header.sequence payload;
        incr received
      | Error e -> Log.error "SRTP error: %s" e)
  done;
  let rr = Rtcp.Receiver_report { ssrc = server_ssrc; report_blocks = [] } in
  (match Media_transport.protect_rtcp media ~packet:rr () with
   | Ok srtcp ->
     ignore (ops.send srtcp);
     Printf.printf "Sent SRTCP RR.\n%!"
   | Error e -> Log.error "SRTCP error: %s" e);
  Unix.close sock
;;

let run_client host port =
  Printf.printf "DTLS-SRTP Media Loopback Client\n%!";
  Printf.printf "Connecting to %s:%d...\n%!" host port;
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.setsockopt_float sock Unix.SO_RCVTIMEO 5.0;
  let server_addr =
    let host_entry = Unix.gethostbyname host in
    Unix.ADDR_INET (host_entry.Unix.h_addr_list.(0), port)
  in
  let buf = Bytes.create 65536 in
  let dtls = Dtls.create Dtls.default_client_config in
  let ops : Dtls.io_ops =
    { send = (fun data -> Unix.sendto sock data 0 (Bytes.length data) [] server_addr)
    ; recv =
        (fun _ ->
          let len, _ = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
          Bytes.sub buf 0 len)
    ; now = Unix.gettimeofday
    ; random = random_bytes
    ; set_timer = (fun _ -> ())
    ; cancel_timer = (fun () -> ())
    }
  in
  Dtls.run_with_io ~ops (fun () ->
    match Dtls.start_handshake dtls with
    | Ok records ->
      List.iter (fun r -> ignore (ops.send r)) records;
      let rec handshake_loop () =
        if Dtls.is_established dtls
        then Printf.printf "DTLS handshake complete.\n%!"
        else (
          let response = ops.recv 0 in
          match Dtls.handle_record dtls response with
          | Ok (responses, _) ->
            List.iter (fun r -> ignore (ops.send r)) responses;
            handshake_loop ()
          | Error e -> Log.error "Handshake error: %s" e)
      in
      handshake_loop ()
    | Error e -> Log.error "Handshake start error: %s" e);
  let local_keys, remote_keys =
    match Dtls_srtp.session_keys_of_dtls ~dtls ~role:Dtls_srtp.Client ~profile () with
    | Ok keys -> keys
    | Error e -> failwith ("DTLS-SRTP export failed: " ^ e)
  in
  let media =
    Media_transport.create
      ~profile
      ~local_keys
      ~remote_keys
      ~ssrc:client_ssrc
      ~payload_type
  in
  let timestamp = ref 0l in
  for i = 1 to 3 do
    let payload = Bytes.of_string (Printf.sprintf "media-%d" i) in
    let ts = !timestamp in
    timestamp := Int32.add !timestamp 160l;
    match Media_transport.protect_rtp media ~timestamp:ts ~payload () with
    | Ok srtp ->
      ignore (ops.send srtp);
      Printf.printf "Sent SRTP payload=%s\n%!" (Bytes.to_string payload)
    | Error e -> Log.error "SRTP error: %s" e
  done;
  let rec wait_rtcp () =
    let data = ops.recv 0 in
    if is_dtls data
    then wait_rtcp ()
    else if is_rtcp data
    then (
      match Media_transport.unprotect_rtcp media ~packet:data with
      | Ok (pkt, index) ->
        let label =
          match pkt with
          | Rtcp.Sender_report _ -> "SR"
          | Rtcp.Receiver_report _ -> "RR"
          | Rtcp.Source_description _ -> "SDES"
          | Rtcp.Bye _ -> "BYE"
          | Rtcp.App _ -> "APP"
          | Rtcp.Unknown_packet _ -> "Unknown"
        in
        Printf.printf "Received SRTCP %s (index=%ld)\n%!" label index
      | Error e -> Log.error "SRTCP error: %s" e)
    else wait_rtcp ()
  in
  wait_rtcp ();
  Unix.close sock
;;

let () =
  if Array.length Sys.argv < 2
  then (
    Printf.printf "Usage:\n";
    Printf.printf "  Server: %s server <port>\n" Sys.argv.(0);
    Printf.printf "  Client: %s client <host> <port>\n" Sys.argv.(0);
    exit 1);
  match Sys.argv.(1) with
  | "server" ->
    let port = if Array.length Sys.argv > 2 then int_of_string Sys.argv.(2) else 12345 in
    run_server port
  | "client" ->
    let host = if Array.length Sys.argv > 2 then Sys.argv.(2) else "127.0.0.1" in
    let port = if Array.length Sys.argv > 3 then int_of_string Sys.argv.(3) else 12345 in
    run_client host port
  | _ ->
    Log.error "Unknown mode: %s" Sys.argv.(1);
    exit 1
;;
