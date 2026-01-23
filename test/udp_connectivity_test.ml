(** Test basic UDP connectivity after warmup *)
open Webrtc

let () =
  Printf.printf "=== UDP Connectivity Test ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:56000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:56001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:56001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:56000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  Printf.printf "Initial UDP stats:\n";
  Printf.printf
    "  sender: sent=%d recv=%d errors=%d\n"
    (Udp_transport.get_stats sender_udp).packets_sent
    (Udp_transport.get_stats sender_udp).packets_recv
    (Udp_transport.get_stats sender_udp).send_errors;
  Printf.printf
    "  receiver: sent=%d recv=%d\n\n%!"
    (Udp_transport.get_stats receiver_udp).packets_sent
    (Udp_transport.get_stats receiver_udp).packets_recv;
  (* Test 1: Direct UDP send *)
  Printf.printf "Test 1: Direct UDP send (100 bytes)...\n%!";
  let test_data = Bytes.make 100 'A' in
  (match Udp_transport.send_connected sender_udp ~data:test_data with
   | Ok n -> Printf.printf "  send returned Ok %d\n" n
   | Error e -> Printf.printf "  send returned Error: %s\n" e);
  Printf.printf
    "  sender packets_sent: %d\n%!"
    (Udp_transport.get_stats sender_udp).packets_sent;
  (* Receive on receiver side *)
  let buf = Bytes.make 200 '\000' in
  Unix.sleepf 0.001;
  (* Brief pause *)
  (match Udp_transport.recv receiver_udp ~buf with
   | Ok (n, _) -> Printf.printf "  receiver got %d bytes\n" n
   | Error e -> Printf.printf "  receiver error: %s\n" e);
  Printf.printf
    "  receiver packets_recv: %d\n\n%!"
    (Udp_transport.get_stats receiver_udp).packets_recv;
  (* Test 2: Send via SCTP after warmup *)
  Printf.printf "Test 2: Warming up with 31700 messages...\n%!";
  let data = Bytes.make 1024 'X' in
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  let s1 = Udp_transport.get_stats sender_udp in
  let r1 = Udp_transport.get_stats receiver_udp in
  Printf.printf "After warmup:\n";
  Printf.printf
    "  sender: sent=%d recv=%d errors=%d\n"
    s1.packets_sent
    s1.packets_recv
    s1.send_errors;
  Printf.printf "  receiver: sent=%d recv=%d\n" r1.packets_sent r1.packets_recv;
  Printf.printf "  delta: %d\n\n%!" (s1.packets_sent - r1.packets_recv);
  (* Test 3: Direct UDP send after warmup *)
  Printf.printf "Test 3: Direct UDP send after warmup...\n%!";
  let test_data2 = Bytes.make 100 'B' in
  let s_before = (Udp_transport.get_stats sender_udp).packets_sent in
  (match Udp_transport.send_connected sender_udp ~data:test_data2 with
   | Ok n -> Printf.printf "  send returned Ok %d\n" n
   | Error e -> Printf.printf "  send returned Error: %s\n" e);
  let s_after = (Udp_transport.get_stats sender_udp).packets_sent in
  Printf.printf
    "  packets_sent: %d -> %d (delta: %d)\n%!"
    s_before
    s_after
    (s_after - s_before);
  Unix.sleepf 0.001;
  let r_before = (Udp_transport.get_stats receiver_udp).packets_recv in
  (match Udp_transport.recv receiver_udp ~buf with
   | Ok (n, _) -> Printf.printf "  receiver got %d bytes\n" n
   | Error e -> Printf.printf "  receiver error: %s\n" e);
  let r_after = (Udp_transport.get_stats receiver_udp).packets_recv in
  Printf.printf
    "  packets_recv: %d -> %d (delta: %d)\n\n%!"
    r_before
    r_after
    (r_after - r_before);
  (* Test 4: SCTP send_data after warmup *)
  Printf.printf "Test 4: SCTP send_data after warmup...\n%!";
  let flight = Sctp_full_transport.get_flight_size sender in
  let cwnd = Sctp_full_transport.get_cwnd sender in
  Printf.printf "  flight=%d cwnd=%d can_send=%b\n%!" flight cwnd (flight < cwnd);
  let s_before = (Udp_transport.get_stats sender_udp).packets_sent in
  (match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
   | Ok n -> Printf.printf "  send_data returned Ok %d\n" n
   | Error e -> Printf.printf "  send_data returned Error: %s\n" e);
  let s_after = (Udp_transport.get_stats sender_udp).packets_sent in
  Printf.printf
    "  UDP packets_sent: %d -> %d (delta: %d)\n%!"
    s_before
    s_after
    (s_after - s_before);
  Printf.printf "\nDone.\n"
;;
