(** Trace UDP packets after collapse *)
open Webrtc

let () =
  Printf.printf "=== UDP Level Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:46000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:46001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:46001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:46000;
  let data = Bytes.make 1024 'X' in
  (* Warm up until collapse *)
  let msgs = ref 0 in
  let collapse_step = ref 0 in
  for step = 1 to 40000 do
    if !collapse_step = 0
    then (
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
        Printf.printf "*** COLLAPSE at step %d ***\n%!" step;
        Printf.printf
          "Retransmissions were sent. Waiting to see if packets arrive...\n\n%!";
        collapse_step := step;
        (* The retransmissions were sent during the tick above.
           Now let's manually tick and trace UDP activity. *)
        for tick = 1 to 5 do
          Printf.printf "Tick %d:\n%!" tick;
          (* Check if receiver has pending packets *)
          let recv_stats_before = Sctp_full_transport.get_stats receiver in
          (* Run receiver tick (this will try to read from UDP socket) *)
          Sctp_full_transport.tick receiver;
          let recv_stats_after = Sctp_full_transport.get_stats receiver in
          Printf.printf
            "  Receiver: msgs_recv delta=%d, sacks_sent delta=%d\n%!"
            (recv_stats_after.messages_recv - recv_stats_before.messages_recv)
            (recv_stats_after.sacks_sent - recv_stats_before.sacks_sent);
          (* Check if sender has pending packets *)
          let send_stats_before = Sctp_full_transport.get_stats sender in
          Sctp_full_transport.tick sender;
          let send_stats_after = Sctp_full_transport.get_stats sender in
          Printf.printf
            "  Sender: sacks_recv delta=%d, retransmissions delta=%d\n%!"
            (send_stats_after.sacks_recv - send_stats_before.sacks_recv)
            (send_stats_after.retransmissions - send_stats_before.retransmissions);
          Printf.printf "  Flight: %d\n\n%!" (Sctp_full_transport.get_flight_size sender)
        done;
        Printf.printf "=== Analysis ===\n";
        Printf.printf "If msgs_recv delta=0 and sacks_sent delta=0 for all ticks,\n";
        Printf.printf
          "the retransmitted packets are NOT being received by the receiver.\n";
        Printf.printf "This could be:\n";
        Printf.printf "1. UDP send failed (unlikely on localhost)\n";
        Printf.printf "2. Receiver's recv call returned no data\n";
        Printf.printf "3. Packets are in kernel buffer but not being read\n";
        exit 0))
  done
;;
