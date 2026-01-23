(** Integration tests for SCTP 4-Way Handshake through Sctp_core

    Tests the full Sans-IO state machine integration:
    - Client initiate() sends INIT
    - Server handle() responds with INIT-ACK
    - Client handle() responds with COOKIE-ECHO
    - Server handle() responds with COOKIE-ACK
    - Both sides reach Established state

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try
    f ();
    incr passed;
    Printf.printf "✅ PASS\n%!"
  with
  | e ->
    incr failed;
    Printf.printf "❌ FAIL (%s)\n%!" (Printexc.to_string e)
;;

let assert_true msg b = if not b then failwith msg

let assert_state msg expected actual =
  if expected <> actual
  then
    failwith
      (Printf.sprintf
         "%s: expected %s, got %s"
         msg
         (Sctp_core.string_of_conn_state expected)
         (Sctp_core.string_of_conn_state actual))
;;

(** Extract SendPacket outputs from a list *)
let extract_packets outputs =
  List.filter_map
    (function
      | Sctp_core.SendPacket pkt -> Some pkt
      | _ -> None)
    outputs
;;

(** Extract first SendPacket or fail *)
let extract_packet outputs =
  match extract_packets outputs with
  | pkt :: _ -> pkt
  | [] -> failwith "Expected SendPacket output"
;;

(** Simulate receiving a packet by passing through handle *)
let receive_packet t packet = Sctp_core.handle t (Sctp_core.PacketReceived packet)

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Basic State Tests                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_initial_state () =
  Printf.printf "\n═══ Initial State Tests ═══\n";
  test "client starts in Closed state" (fun () ->
    let client = Sctp_core.create () in
    assert_state "initial state" Sctp_core.Closed (Sctp_core.get_conn_state client));
  test "server starts in Closed state" (fun () ->
    let server = Sctp_core.create () in
    assert_state "initial state" Sctp_core.Closed (Sctp_core.get_conn_state server))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Initiate Tests                                                              *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_initiate () =
  Printf.printf "\n═══ Initiate Tests ═══\n";
  test "initiate() produces SendPacket with INIT" (fun () ->
    let client = Sctp_core.create () in
    let outputs = Sctp_core.initiate client in
    let packets = extract_packets outputs in
    assert_true "produces packets" (List.length packets > 0);
    (* INIT chunk type is 1 - check first byte after SCTP header *)
    let pkt = List.hd packets in
    assert_true "packet long enough" (Bytes.length pkt >= 16);
    (* SCTP header is 12 bytes, chunk type is first byte of chunk *)
    let chunk_type = Bytes.get_uint8 pkt 12 in
    assert_true "chunk type is INIT (1)" (chunk_type = 1));
  test "initiate() transitions to CookieWait" (fun () ->
    let client = Sctp_core.create () in
    let _ = Sctp_core.initiate client in
    assert_state "after initiate" Sctp_core.CookieWait (Sctp_core.get_conn_state client));
  test "initiate_direct() goes directly to Established" (fun () ->
    let client = Sctp_core.create () in
    let _ = Sctp_core.initiate_direct client in
    assert_state
      "after initiate_direct"
      Sctp_core.Established
      (Sctp_core.get_conn_state client))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Full 4-Way Handshake                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_full_handshake () =
  Printf.printf "\n═══ Full 4-Way Handshake ═══\n";
  test "complete handshake flow" (fun () ->
    (* Set up HMAC secret for cookie validation *)
    Sctp_handshake.set_hmac_secret "test-secret-for-handshake";
    (* Create client and server *)
    let client = Sctp_core.create ~src_port:5000 ~dst_port:5001 () in
    let server = Sctp_core.create ~src_port:5001 ~dst_port:5000 () in
    Printf.printf "\n    [Step 1] Client sends INIT\n%!";
    (* Step 1: Client initiates - sends INIT *)
    let client_outputs = Sctp_core.initiate client in
    assert_state
      "client after INIT"
      Sctp_core.CookieWait
      (Sctp_core.get_conn_state client);
    let init_packet = extract_packet client_outputs in
    Printf.printf "    INIT packet size: %d bytes\n%!" (Bytes.length init_packet);
    Printf.printf "    [Step 2] Server receives INIT, sends INIT-ACK\n%!";
    (* Step 2: Server receives INIT, responds with INIT-ACK *)
    let server_outputs = receive_packet server init_packet in
    let init_ack_packets = extract_packets server_outputs in
    Printf.printf "    Server outputs: %d packets\n%!" (List.length init_ack_packets);
    (* Server should remain in Closed or transition to listening state *)
    (* Per RFC 4960, server doesn't change state until COOKIE-ECHO *)
    assert_true "server produces INIT-ACK" (List.length init_ack_packets > 0);
    let init_ack_packet = List.hd init_ack_packets in
    Printf.printf "    INIT-ACK packet size: %d bytes\n%!" (Bytes.length init_ack_packet);
    Printf.printf "    [Step 3] Client receives INIT-ACK, sends COOKIE-ECHO\n%!";
    (* Step 3: Client receives INIT-ACK, sends COOKIE-ECHO *)
    let client_outputs2 = receive_packet client init_ack_packet in
    let cookie_echo_packets = extract_packets client_outputs2 in
    Printf.printf "    Client outputs: %d packets\n%!" (List.length cookie_echo_packets);
    assert_true "client produces COOKIE-ECHO" (List.length cookie_echo_packets > 0);
    assert_state
      "client after INIT-ACK"
      Sctp_core.CookieEchoed
      (Sctp_core.get_conn_state client);
    let cookie_echo_packet = List.hd cookie_echo_packets in
    Printf.printf
      "    COOKIE-ECHO packet size: %d bytes\n%!"
      (Bytes.length cookie_echo_packet);
    Printf.printf "    [Step 4] Server receives COOKIE-ECHO, sends COOKIE-ACK\n%!";
    (* Step 4: Server receives COOKIE-ECHO, sends COOKIE-ACK, transitions to Established *)
    let server_outputs2 = receive_packet server cookie_echo_packet in
    let cookie_ack_packets = extract_packets server_outputs2 in
    Printf.printf "    Server outputs: %d packets\n%!" (List.length cookie_ack_packets);
    assert_true "server produces COOKIE-ACK" (List.length cookie_ack_packets > 0);
    assert_state
      "server after COOKIE-ECHO"
      Sctp_core.Established
      (Sctp_core.get_conn_state server);
    let cookie_ack_packet = List.hd cookie_ack_packets in
    Printf.printf
      "    COOKIE-ACK packet size: %d bytes\n%!"
      (Bytes.length cookie_ack_packet);
    Printf.printf "    [Step 5] Client receives COOKIE-ACK, becomes Established\n%!";
    (* Step 5: Client receives COOKIE-ACK, transitions to Established *)
    let _ = receive_packet client cookie_ack_packet in
    assert_state
      "client after COOKIE-ACK"
      Sctp_core.Established
      (Sctp_core.get_conn_state client);
    Printf.printf "    ✅ Both sides Established!\n%!";
    (* Verify both can now send data *)
    assert_true "client can send" (Sctp_core.is_established client);
    assert_true "server can send" (Sctp_core.is_established server))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Data Transfer After Handshake                                               *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_data_after_handshake () =
  Printf.printf "\n═══ Data Transfer After Handshake ═══\n";
  test "send data after established" (fun () ->
    Sctp_handshake.set_hmac_secret "data-test-secret";
    (* Complete handshake *)
    let client = Sctp_core.create ~src_port:5000 ~dst_port:5001 () in
    let server = Sctp_core.create ~src_port:5001 ~dst_port:5000 () in
    (* Quick handshake *)
    let init_packet = extract_packet (Sctp_core.initiate client) in
    let init_ack_packet = extract_packet (receive_packet server init_packet) in
    let cookie_echo_packet = extract_packet (receive_packet client init_ack_packet) in
    let cookie_ack_packet = extract_packet (receive_packet server cookie_echo_packet) in
    let _ = receive_packet client cookie_ack_packet in
    assert_true
      "both established"
      (Sctp_core.is_established client && Sctp_core.is_established server);
    (* Now send data *)
    let test_data = Bytes.of_string "Hello from handshake test!" in
    let send_outputs =
      Sctp_core.handle client (Sctp_core.UserSend { stream_id = 0; data = test_data })
    in
    let data_packets = extract_packets send_outputs in
    assert_true "client sends DATA" (List.length data_packets > 0);
    Printf.printf
      "    Data packet sent: %d bytes\n%!"
      (Bytes.length (List.hd data_packets)))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Edge Cases                                                                  *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_edge_cases () =
  Printf.printf "\n═══ Edge Cases ═══\n";
  test "receiving INIT when not in Closed state" (fun () ->
    Sctp_handshake.set_hmac_secret "edge-case-secret";
    let client1 = Sctp_core.create () in
    let client2 = Sctp_core.create () in
    (* Start handshake on client1 *)
    let init_packet = extract_packet (Sctp_core.initiate client1) in
    (* client2 also initiates (so it's in CookieWait) *)
    let _ = Sctp_core.initiate client2 in
    assert_state
      "client2 in CookieWait"
      Sctp_core.CookieWait
      (Sctp_core.get_conn_state client2);
    (* Send INIT to client2 - it should still process as simultaneous open *)
    let outputs = receive_packet client2 init_packet in
    (* May produce INIT-ACK for simultaneous open scenario *)
    Printf.printf "    (Simultaneous open: %d outputs)\n%!" (List.length outputs));
  test "double initiate is no-op" (fun () ->
    let client = Sctp_core.create () in
    let outputs1 = Sctp_core.initiate client in
    assert_state "first initiate" Sctp_core.CookieWait (Sctp_core.get_conn_state client);
    let outputs2 = Sctp_core.initiate client in
    (* Second initiate should return empty or same state *)
    assert_state
      "after second initiate"
      Sctp_core.CookieWait
      (Sctp_core.get_conn_state client);
    Printf.printf
      "    (First: %d outputs, Second: %d outputs)\n%!"
      (List.length outputs1)
      (List.length outputs2))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main                                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     SCTP Core Handshake Integration Tests                     ║\n";
  Printf.printf "║     RFC 4960 §5 4-Way Handshake through Sans-IO               ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";
  test_initial_state ();
  test_initiate ();
  test_full_handshake ();
  test_data_after_handshake ();
  test_edge_cases ();
  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";
  if !failed > 0 then exit 1
;;
