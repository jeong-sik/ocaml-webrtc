(** STUN Client Example - Discover Public IP via STUN Server

    RFC 5389 - Session Traversal Utilities for NAT (STUN)

    This example demonstrates:
    - Sending STUN Binding Request to a public STUN server
    - Receiving and parsing STUN Binding Response
    - Extracting the XOR-MAPPED-ADDRESS (your public IP as seen by server)

    Usage: dune exec ./examples/stun_client.exe [stun_server] [port]
    Example: dune exec ./examples/stun_client.exe stun.l.google.com 19302

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

open Webrtc

let default_stun_server = "stun.l.google.com"
let default_stun_port = 19302

(** Discover public IP address using STUN *)
let discover_public_ip ~server_host ~server_port =
  Printf.printf "┌─────────────────────────────────────────────────┐\n";
  Printf.printf "│           STUN Client (RFC 5389)                │\n";
  Printf.printf "└─────────────────────────────────────────────────┘\n\n";

  Printf.printf "➤ Querying STUN server: %s:%d\n%!" server_host server_port;

  (* Create UDP socket *)
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.setsockopt_float sock Unix.SO_RCVTIMEO 5.0;  (* 5 second timeout *)

  (* Resolve STUN server address *)
  let server_addr =
    try
      let host_entry = Unix.gethostbyname server_host in
      Unix.ADDR_INET (host_entry.Unix.h_addr_list.(0), server_port)
    with Not_found ->
      Printf.eprintf "Error: Cannot resolve hostname %s\n" server_host;
      exit 1
  in

  (* Create STUN Binding Request (RFC 5389 §6) *)
  let request = Stun.create_binding_request () in
  let request_bytes = Stun.encode request in

  Printf.printf "➤ Sending STUN Binding Request...\n";
  let tid = request.Stun.transaction_id in
  let hex_tid = String.concat "" (List.init (Bytes.length tid) (fun i ->
    Printf.sprintf "%02X" (Bytes.get_uint8 tid i)
  )) in
  Printf.printf "   Transaction ID: %s\n%!" hex_tid;

  (* Send request *)
  let start_time = Unix.gettimeofday () in
  let _ = Unix.sendto sock request_bytes 0 (Bytes.length request_bytes) [] server_addr in

  (* Receive response *)
  let buf = Bytes.create 2048 in
  begin try
    let (len, _) = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
    let rtt = (Unix.gettimeofday () -. start_time) *. 1000.0 in
    let response_bytes = Bytes.sub buf 0 len in

    Printf.printf "➤ Received response (%d bytes, RTT: %.2fms)\n%!" len rtt;

    (* Parse response *)
    match Stun.decode response_bytes with
    | Ok response ->
      Printf.printf "\n┌─────────────────────────────────────────────────┐\n";
      Printf.printf "│                  STUN Response                  │\n";
      Printf.printf "├─────────────────────────────────────────────────┤\n";
      Printf.printf "│ Class:  %s\n"
        (match response.msg_class with
         | Stun.Success_response -> "Success Response       │"
         | Stun.Error_response -> "Error Response         │"
         | Stun.Request -> "Request (unexpected)   │"
         | Stun.Indication -> "Indication             │");
      Printf.printf "│ Method: Binding                                 │\n";
      Printf.printf "├─────────────────────────────────────────────────┤\n";

      (* Extract XOR-MAPPED-ADDRESS *)
      List.iter (fun attr ->
        match attr.Stun.value with
        | Stun.Xor_mapped_address addr ->
          Printf.printf "│ ★ Your Public IP: %-28s │\n"
            (Printf.sprintf "%s:%d" addr.Stun.ip addr.Stun.port)
        | Stun.Mapped_address addr ->
          Printf.printf "│   Mapped Address: %-28s │\n"
            (Printf.sprintf "%s:%d" addr.Stun.ip addr.Stun.port)
        | Stun.Software name ->
          Printf.printf "│   Server Software: %-27s │\n" name
        | _ -> ()
      ) response.Stun.attributes;

      Printf.printf "└─────────────────────────────────────────────────┘\n";
      Unix.close sock;
      0

    | Error e ->
      Printf.eprintf "Error parsing response: %s\n" e;
      Unix.close sock;
      1
  with
  | Unix.Unix_error (Unix.ETIMEDOUT, _, _)
  | Unix.Unix_error (Unix.EAGAIN, _, _) ->
    Printf.eprintf "Error: Request timed out\n";
    Unix.close sock;
    1
  end

let () =
  let server_host = if Array.length Sys.argv > 1 then Sys.argv.(1) else default_stun_server in
  let server_port = if Array.length Sys.argv > 2 then int_of_string Sys.argv.(2) else default_stun_port in
  exit (discover_public_ip ~server_host ~server_port)
