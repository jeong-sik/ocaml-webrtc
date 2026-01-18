(** Flight size tracing - find where it goes wrong *)
open Webrtc

let () =
  Printf.printf "=== Flight Size Trace ===\n\n";
  
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:41000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:41001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:41001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:41000;
  
  let data = Bytes.make 1024 'X' in
  
  let last_flight = ref 0 in
  let last_cwnd = ref 0 in
  let msgs_sent = ref 0 in
  
  Printf.printf "Iteration | Msgs | cwnd | flight | sacks_recv | status\n";
  Printf.printf "----------|------|------|--------|------------|-------\n";
  
  for i = 1 to 50000 do
    (* Try to send *)
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs_sent
      | Error _ -> ()
    end;
    
    (* Process both sides *)
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    
    (* Check for anomalies every 1000 iterations or when cwnd changes significantly *)
    let flight = Sctp_full_transport.get_flight_size sender in
    let cwnd = Sctp_full_transport.get_cwnd sender in
    let stats = Sctp_full_transport.get_stats sender in
    
    if i mod 5000 = 0 || cwnd < !last_cwnd / 2 || flight > !last_flight * 2 + 10000 then begin
      let status = 
        if cwnd < 2000 then "CWND_COLLAPSED!"
        else if flight > cwnd * 10 then "FLIGHT_STUCK!"
        else "OK"
      in
      Printf.printf "%9d | %4d | %4d | %6d | %10d | %s\n"
        i !msgs_sent cwnd flight stats.sacks_recv status
    end;
    
    last_flight := flight;
    last_cwnd := cwnd;
    
    (* Early exit if things go badly wrong *)
    if cwnd < 1300 && flight > 100000 then begin
      Printf.printf "\n*** ABORT: cwnd collapsed, flight stuck ***\n";
      Printf.printf "Final state:\n";
      Printf.printf "  cwnd: %d\n" cwnd;
      Printf.printf "  flight: %d\n" flight;
      Printf.printf "  rto: %.3f\n" (Sctp_full_transport.get_rto sender);
      Printf.printf "  retransmissions: %d\n" stats.retransmissions;
      Printf.printf "  fast_rtx: %d\n" stats.fast_retransmissions;
      exit 1
    end
  done;
  
  let final_stats = Sctp_full_transport.get_stats sender in
  Printf.printf "\n=== Final ===\n";
  Printf.printf "Messages sent: %d\n" !msgs_sent;
  Printf.printf "cwnd: %d\n" (Sctp_full_transport.get_cwnd sender);
  Printf.printf "flight: %d\n" (Sctp_full_transport.get_flight_size sender);
  Printf.printf "sacks_recv: %d\n" final_stats.sacks_recv
