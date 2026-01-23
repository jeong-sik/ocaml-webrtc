(** Trace SACK acknowledgment to find why flight_bytes doesn't decrease *)
open Webrtc

let () =
  Printf.printf "=== ACK Trace Debug ===\n\n";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:42000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:42001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:42001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:42000;
  let data = Bytes.make 1024 'X' in
  Printf.printf "=== Phase 1: Warm up to ~32000 messages ===\n";
  let msgs = ref 0 in
  for _ = 1 to 35000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ());
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    let cwnd = Sctp_full_transport.get_cwnd sender in
    let flight = Sctp_full_transport.get_flight_size sender in
    (* Detect collapse *)
    if cwnd < 2000 && flight > 100000
    then (
      Printf.printf "\n*** COLLAPSE at msg %d ***\n" !msgs;
      Printf.printf "cwnd: %d\n" cwnd;
      Printf.printf "flight: %d\n" flight;
      Printf.printf "rto: %.3f\n" (Sctp_full_transport.get_rto sender);
      let stats = Sctp_full_transport.get_stats sender in
      Printf.printf "sacks_recv before: %d\n\n" stats.sacks_recv;
      (* Now trace what happens on each tick *)
      Printf.printf "=== Detailed tick trace ===\n";
      Printf.printf "tick | sacks | flight | cum_tsn_from_sack\n";
      Printf.printf "-----|-------|--------|------------------\n";
      for tick = 1 to 20 do
        let stats_before = Sctp_full_transport.get_stats sender in
        let flight_before = Sctp_full_transport.get_flight_size sender in
        Sctp_full_transport.tick receiver;
        Sctp_full_transport.tick sender;
        let stats_after = Sctp_full_transport.get_stats sender in
        let flight_after = Sctp_full_transport.get_flight_size sender in
        let new_sacks = stats_after.sacks_recv - stats_before.sacks_recv in
        let flight_delta = flight_after - flight_before in
        Printf.printf
          "%4d | %5d | %6d | delta=%d\n"
          tick
          new_sacks
          flight_after
          flight_delta
      done;
      Printf.printf "\n=== After 20 ticks ===\n";
      Printf.printf
        "flight: %d (should be decreasing!)\n"
        (Sctp_full_transport.get_flight_size sender);
      exit 1)
  done;
  Printf.printf "Test completed without collapse (unexpected)\n"
;;
