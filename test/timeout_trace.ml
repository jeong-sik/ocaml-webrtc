(** Trace what happens around T3-rtx timeout *)
open Webrtc

let () =
  Printf.printf "=== T3-rtx Timeout Trace ===\n\n";
  
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:44000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:44001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:44001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:44000;
  
  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  
  Printf.printf "Running until near timeout...\n";
  Printf.printf "Initial RTO: %.3f s\n\n" (Sctp_full_transport.get_rto sender);
  
  (* Run until we're close to 30000 sends *)
  while !msgs < 30000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ()
    end;
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  
  let stats_before = Sctp_full_transport.get_stats sender in
  Printf.printf "=== At 30000 sends ===\n";
  Printf.printf "  cwnd: %d\n" (Sctp_full_transport.get_cwnd sender);
  Printf.printf "  flight: %d\n" (Sctp_full_transport.get_flight_size sender);
  Printf.printf "  rto: %.3f s\n" (Sctp_full_transport.get_rto sender);
  Printf.printf "  sacks_recv: %d\n" stats_before.sacks_recv;
  Printf.printf "  retransmissions: %d\n" stats_before.retransmissions;
  
  (* Now carefully step through the next few hundred iterations *)
  Printf.printf "\n=== Stepping through next 3000 iterations ===\n";
  let prev_cwnd = ref (Sctp_full_transport.get_cwnd sender) in
  
  for i = 1 to 3000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ()
    end;
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    
    let cwnd = Sctp_full_transport.get_cwnd sender in
    let stats = Sctp_full_transport.get_stats sender in
    
    (* Detect significant changes *)
    if cwnd < !prev_cwnd / 2 || stats.retransmissions > stats_before.retransmissions then begin
      Printf.printf "\n*** EVENT at step %d (total msgs: %d) ***\n" i !msgs;
      Printf.printf "  cwnd: %d -> %d\n" !prev_cwnd cwnd;
      Printf.printf "  flight: %d\n" (Sctp_full_transport.get_flight_size sender);
      Printf.printf "  rto: %.3f s\n" (Sctp_full_transport.get_rto sender);
      Printf.printf "  sacks_recv: %d (delta: %d)\n" stats.sacks_recv (stats.sacks_recv - stats_before.sacks_recv);
      Printf.printf "  retransmissions: %d\n" stats.retransmissions;
      Printf.printf "  fast_rtx: %d\n" stats.fast_retransmissions;
      
      if cwnd < 2000 then begin
        Printf.printf "\n*** CWND COLLAPSED ***\n";
        
        (* Run a few more iterations to see what happens *)
        Printf.printf "\n=== After collapse, 10 more ticks ===\n";
        for j = 1 to 10 do
          Sctp_full_transport.tick receiver;
          Sctp_full_transport.tick sender;
          let stats2 = Sctp_full_transport.get_stats sender in
          Printf.printf "  tick %d: sacks=%d flight=%d\n" 
            j stats2.sacks_recv (Sctp_full_transport.get_flight_size sender)
        done;
        exit 1
      end
    end;
    prev_cwnd := cwnd
  done;
  
  Printf.printf "\n=== Completed without collapse ===\n"
