(** Ring buffer detailed trace *)
open Webrtc

(* Access ring buffer internals via sctp_reliable *)
let () =
  Printf.printf "=== Ring Buffer Trace ===\n\n";
  
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:42000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:42001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:42001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:42000;
  
  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let prev_cwnd = ref 0 in
  
  Printf.printf "Ring buffer capacity: 4096\n";
  Printf.printf "Initial TSN: 1000\n\n";
  
  for i = 1 to 40000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ()
    end;
    
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    
    let cwnd = Sctp_full_transport.get_cwnd sender in
    let flight = Sctp_full_transport.get_flight_size sender in
    let stats = Sctp_full_transport.get_stats sender in
    
    (* Detect cwnd collapse *)
    if cwnd < !prev_cwnd / 2 && !prev_cwnd > 10000 then begin
      Printf.printf "\n*** CWND COLLAPSE at iteration %d ***\n" i;
      Printf.printf "  msgs_sent: %d\n" !msgs;
      Printf.printf "  prev_cwnd: %d -> cwnd: %d\n" !prev_cwnd cwnd;
      Printf.printf "  flight: %d\n" flight;
      Printf.printf "  sacks_recv: %d\n" stats.sacks_recv;
      Printf.printf "  retransmissions: %d\n" stats.retransmissions;
      Printf.printf "  fast_rtx: %d\n" stats.fast_retransmissions;
      Printf.printf "  rto: %.3f\n" (Sctp_full_transport.get_rto sender);
      
      (* Ring buffer would be TSN 1000 + msgs *)
      Printf.printf "  Expected tail_tsn: ~%d\n" (1000 + !msgs);
      Printf.printf "  If capacity is 4096, head should be ~%d\n" (1000 + !msgs - 4096);
      
      if cwnd < 2000 then begin
        Printf.printf "\n*** FATAL: cwnd collapsed to minimum ***\n";
        exit 1
      end
    end;
    prev_cwnd := cwnd
  done;
  
  Printf.printf "\n=== Success! ===\n";
  Printf.printf "Sent %d messages without collapse\n" !msgs
