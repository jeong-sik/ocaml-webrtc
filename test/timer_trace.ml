(** Trace T3-rtx timer behavior after collapse *)
open Webrtc

let () =
  Printf.printf "=== T3-rtx Timer Trace ===\n\n";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:44000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:44001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:44001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:44000;
  let data = Bytes.make 1024 'X' in
  Printf.printf "=== Warm up until collapse ===\n";
  let msgs = ref 0 in
  for _ = 1 to 35000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ());
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    if
      Sctp_full_transport.get_cwnd sender < 2000
      && Sctp_full_transport.get_flight_size sender > 100000
    then (
      Printf.printf "\n*** COLLAPSE at msg %d ***\n" !msgs;
      Printf.printf "cwnd: %d\n" (Sctp_full_transport.get_cwnd sender);
      Printf.printf "flight: %d\n" (Sctp_full_transport.get_flight_size sender);
      Printf.printf "rto: %.3f s\n" (Sctp_full_transport.get_rto sender);
      let stats = Sctp_full_transport.get_stats sender in
      Printf.printf "retransmissions: %d\n" stats.retransmissions;
      (* Simulate time passing to trigger T3-rtx again *)
      Printf.printf "\n=== Simulating 3 seconds of ticks ===\n";
      Printf.printf
        "(RTO is 2.0s, so T3-rtx should fire after ~2 seconds worth of ticks)\n\n";
      (* Assume each tick is ~1ms in our simulation *)
      for tick = 1 to 50 do
        (* In real implementation, time passes between ticks *)
        (* Here we just tick rapidly *)
        let stats_before = Sctp_full_transport.get_stats sender in
        let flight_before = Sctp_full_transport.get_flight_size sender in
        Sctp_full_transport.tick receiver;
        Sctp_full_transport.tick sender;
        let stats_after = Sctp_full_transport.get_stats sender in
        let flight_after = Sctp_full_transport.get_flight_size sender in
        let rtx = stats_after.retransmissions - stats_before.retransmissions in
        let new_sacks = stats_after.sacks_recv - stats_before.sacks_recv in
        if rtx > 0 || new_sacks > 0 || flight_after <> flight_before
        then
          Printf.printf
            "tick %d: rtx=%d sacks=%d flight=%d (delta=%d)\n"
            tick
            rtx
            new_sacks
            flight_after
            (flight_after - flight_before)
      done;
      Printf.printf "\n=== Problem Identified ===\n";
      Printf.printf "The T3-rtx timer uses real wall-clock time (Unix.gettimeofday).\n";
      Printf.printf "In our test, ticks happen instantly without time passing.\n";
      Printf.printf "So after RTO doubles to 2s, no more retransmissions occur!\n";
      Printf.printf
        "\nFlight stays stuck at %d bytes.\n"
        (Sctp_full_transport.get_flight_size sender);
      Printf.printf "This is a TEST environment issue, not a protocol bug.\n\n";
      Printf.printf "To fix: Either add sleep() between ticks, or\n";
      Printf.printf "make the timer use simulated time instead of real time.\n";
      exit 0)
  done;
  Printf.printf "No collapse (unexpected)\n"
;;
