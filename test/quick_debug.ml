(** Quick debug test for SACK optimization *)
open Webrtc

let () =
  Printf.printf "=== Quick SACK Debug ===\n";
  
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:40000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:40001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:40001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:40000;
  
  let data = Bytes.make 1024 'X' in
  
  Printf.printf "\n=== Phase 1: Send 100 packets ===\n";
  for i = 1 to 100 do
    match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
    | Ok _ -> ()
    | Error e -> Printf.printf "  [%d] Send error: %s\n" i e
  done;
  
  Printf.printf "  After sends:\n";
  Printf.printf "    cwnd:   %d\n" (Sctp_full_transport.get_cwnd sender);
  Printf.printf "    flight: %d\n" (Sctp_full_transport.get_flight_size sender);
  
  Printf.printf "\n=== Phase 2: Process receiver (10 ticks) ===\n";
  for _ = 1 to 10 do
    Sctp_full_transport.tick receiver
  done;
  
  let recv_stats = Sctp_full_transport.get_stats receiver in
  Printf.printf "  Receiver: msgs=%d sacks_sent=%d\n" recv_stats.messages_recv recv_stats.sacks_sent;
  
  Printf.printf "\n=== Phase 3: Process sender (10 ticks) ===\n";
  for _ = 1 to 10 do
    Sctp_full_transport.tick sender
  done;
  
  let send_stats = Sctp_full_transport.get_stats sender in
  Printf.printf "  Sender after SACK:\n";
  Printf.printf "    cwnd:   %d\n" (Sctp_full_transport.get_cwnd sender);
  Printf.printf "    flight: %d\n" (Sctp_full_transport.get_flight_size sender);
  Printf.printf "    sacks_recv: %d\n" send_stats.sacks_recv;
  Printf.printf "    retransmissions: %d\n" send_stats.retransmissions;
  Printf.printf "    fast_rtx: %d\n" send_stats.fast_retransmissions;
  
  Printf.printf "\n=== Phase 4: Full loop 1000 times ===\n";
  let msgs = ref 0 in
  let blocked = ref 0 in
  for _ = 1 to 1000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ()
    end else
      incr blocked;
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  
  Printf.printf "  Messages sent: %d\n" !msgs;
  Printf.printf "  Blocked: %d\n" !blocked;
  Printf.printf "  Final cwnd: %d\n" (Sctp_full_transport.get_cwnd sender);
  Printf.printf "  Final flight: %d\n" (Sctp_full_transport.get_flight_size sender)
