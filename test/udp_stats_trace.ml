(** Trace UDP-level packet stats to diagnose retransmission delivery *)
open Webrtc

let () =
  Printf.printf "=== UDP Stats Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:47000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:47001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:47001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:47000;
  let data = Bytes.make 1024 'X' in
  (* Get UDP transport handles for direct stats *)
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
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
        let s_stats = Sctp_full_transport.get_stats sender in
        let r_stats = Sctp_full_transport.get_stats receiver in
        let s_udp = Udp_transport.get_stats sender_udp in
        let r_udp = Udp_transport.get_stats receiver_udp in
        Printf.printf "\n=== SCTP Stats ===\n";
        Printf.printf
          "Sender: msgs_sent=%d, retransmissions=%d\n"
          s_stats.messages_sent
          s_stats.retransmissions;
        Printf.printf
          "Receiver: msgs_recv=%d, sacks_sent=%d\n%!"
          r_stats.messages_recv
          r_stats.sacks_sent;
        Printf.printf "\n=== UDP Stats (before trace) ===\n";
        Printf.printf
          "Sender UDP: packets_sent=%d, send_errors=%d\n"
          s_udp.packets_sent
          s_udp.send_errors;
        Printf.printf
          "Receiver UDP: packets_recv=%d, recv_errors=%d\n%!"
          r_udp.packets_recv
          r_udp.recv_errors;
        collapse_step := step;
        Printf.printf "\n=== Tracing 10 ticks post-collapse ===\n\n%!"))
    else (
      let tick_num = step - !collapse_step in
      if tick_num >= 1 && tick_num <= 10
      then (
        let s_udp_before = Udp_transport.get_stats sender_udp in
        let r_udp_before = Udp_transport.get_stats receiver_udp in
        let s_before = Sctp_full_transport.get_stats sender in
        let r_before = Sctp_full_transport.get_stats receiver in
        let flight_before = Sctp_full_transport.get_flight_size sender in
        Sctp_full_transport.tick receiver;
        Sctp_full_transport.tick sender;
        let s_udp_after = Udp_transport.get_stats sender_udp in
        let r_udp_after = Udp_transport.get_stats receiver_udp in
        let s_after = Sctp_full_transport.get_stats sender in
        let r_after = Sctp_full_transport.get_stats receiver in
        let flight_after = Sctp_full_transport.get_flight_size sender in
        Printf.printf "tick %d:\n" tick_num;
        Printf.printf
          "  UDP sender: pkts_sent delta=%d, send_errors delta=%d\n"
          (s_udp_after.packets_sent - s_udp_before.packets_sent)
          (s_udp_after.send_errors - s_udp_before.send_errors);
        Printf.printf
          "  UDP receiver: pkts_recv delta=%d, recv_errors delta=%d\n"
          (r_udp_after.packets_recv - r_udp_before.packets_recv)
          (r_udp_after.recv_errors - r_udp_before.recv_errors);
        Printf.printf
          "  SCTP: rtx delta=%d, sacks_recv delta=%d, msgs_recv delta=%d\n"
          (s_after.retransmissions - s_before.retransmissions)
          (s_after.sacks_recv - s_before.sacks_recv)
          (r_after.messages_recv - r_before.messages_recv);
        Printf.printf "  Flight: %d -> %d\n\n%!" flight_before flight_after)
      else if tick_num = 11
      then (
        Printf.printf "=== Final State ===\n";
        let s_udp = Udp_transport.get_stats sender_udp in
        let r_udp = Udp_transport.get_stats receiver_udp in
        Printf.printf "Sender UDP: packets_sent=%d\n" s_udp.packets_sent;
        Printf.printf "Receiver UDP: packets_recv=%d\n" r_udp.packets_recv;
        Printf.printf
          "Delta: %d packets sent but NOT received!\n"
          (s_udp.packets_sent - r_udp.packets_recv);
        Printf.printf "Flight: %d\n" (Sctp_full_transport.get_flight_size sender);
        exit 0))
  done;
  Printf.printf "No collapse detected\n"
;;
