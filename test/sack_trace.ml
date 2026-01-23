(** SACK content trace - verify cumulative_tsn is advancing *)
open Webrtc

let () =
  Printf.printf "=== SACK Trace ===\n\n";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:43000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:43001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:43001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:43000;
  let data = Bytes.make 1024 'X' in
  (* Send 10 packets *)
  Printf.printf "Sending 10 packets...\n";
  for i = 1 to 10 do
    match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
    | Ok _ -> Printf.printf "  Sent packet %d\n" i
    | Error e -> Printf.printf "  Error: %s\n" e
  done;
  Printf.printf "\nReceiver tick 5 times...\n";
  for i = 1 to 5 do
    Sctp_full_transport.tick receiver;
    let stats = Sctp_full_transport.get_stats receiver in
    Printf.printf
      "  Tick %d: msgs_recv=%d sacks_sent=%d\n"
      i
      stats.messages_recv
      stats.sacks_sent
  done;
  Printf.printf "\nSender tick 5 times...\n";
  for i = 1 to 5 do
    Sctp_full_transport.tick sender;
    let stats = Sctp_full_transport.get_stats sender in
    Printf.printf
      "  Tick %d: sacks_recv=%d flight=%d cwnd=%d\n"
      i
      stats.sacks_recv
      (Sctp_full_transport.get_flight_size sender)
      (Sctp_full_transport.get_cwnd sender)
  done;
  Printf.printf "\n=== Stress test: 1000 rapid iterations ===\n";
  let initial_sacks = (Sctp_full_transport.get_stats sender).sacks_recv in
  let msgs = ref 0 in
  for i = 1 to 1000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ());
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    if i mod 200 = 0
    then (
      let stats = Sctp_full_transport.get_stats sender in
      let sacks_this_period = stats.sacks_recv - initial_sacks in
      Printf.printf
        "  Iter %d: msgs=%d sacks_recv=%d ratio=%.2f sacks/iter\n"
        i
        !msgs
        sacks_this_period
        (float sacks_this_period /. float i))
  done
;;
