(** Trace the exact T3-rtx burst moment *)
open Webrtc

let () =
  Printf.printf "=== T3-rtx Burst Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:53000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:53001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:53001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:53000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let collapse_detected = ref false in
  let burst_step = ref 0 in
  for step = 1 to 40000 do
    if not !collapse_detected
    then (
      (* Normal operation *)
      if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
      then (
        match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
        | Ok _ -> incr msgs
        | Error _ -> ());
      let s_before = Sctp_full_transport.get_stats sender in
      let r_udp_before = Udp_transport.get_stats receiver_udp in
      Sctp_full_transport.tick receiver;
      Sctp_full_transport.tick sender;
      let s_after = Sctp_full_transport.get_stats sender in
      let s_udp = Udp_transport.get_stats sender_udp in
      let r_udp_after = Udp_transport.get_stats receiver_udp in
      (* Detect retransmission burst *)
      let rtx_delta = s_after.retransmissions - s_before.retransmissions in
      if rtx_delta > 0
      then (
        Printf.printf "\n*** RETRANSMISSION BURST at step %d ***\n" step;
        Printf.printf "Retransmissions: %d\n" rtx_delta;
        Printf.printf "Sender UDP packets_sent: %d\n" s_udp.packets_sent;
        Printf.printf
          "Receiver UDP packets_recv during this tick: %d\n"
          (r_udp_after.packets_recv - r_udp_before.packets_recv);
        collapse_detected := true;
        burst_step := step);
      (* Also detect cwnd collapse *)
      if
        Sctp_full_transport.get_cwnd sender < 2000
        && Sctp_full_transport.get_flight_size sender > 100000
      then (
        Printf.printf "\n*** COLLAPSE detected at step %d ***\n%!" step;
        collapse_detected := true;
        burst_step := step))
    else (
      (* Post-collapse tracing *)
      let tick_num = step - !burst_step in
      if tick_num <= 20
      then (
        let s_udp_before = Udp_transport.get_stats sender_udp in
        let r_udp_before = Udp_transport.get_stats receiver_udp in
        Sctp_full_transport.tick receiver;
        Sctp_full_transport.tick sender;
        let s_udp_after = Udp_transport.get_stats sender_udp in
        let r_udp_after = Udp_transport.get_stats receiver_udp in
        let s = Sctp_full_transport.get_stats sender in
        Printf.printf
          "tick+%d: recv_delta=%d send_delta=%d sacks_recv=%d flight=%d\n%!"
          tick_num
          (r_udp_after.packets_recv - r_udp_before.packets_recv)
          (s_udp_after.packets_sent - s_udp_before.packets_sent)
          s.sacks_recv
          (Sctp_full_transport.get_flight_size sender))
      else if tick_num = 21
      then (
        Printf.printf "\n=== Final State ===\n";
        let s_udp = Udp_transport.get_stats sender_udp in
        let r_udp = Udp_transport.get_stats receiver_udp in
        Printf.printf "Sender UDP sent: %d\n" s_udp.packets_sent;
        Printf.printf "Receiver UDP recv: %d\n" r_udp.packets_recv;
        Printf.printf "DATA loss: %d\n" (s_udp.packets_sent - r_udp.packets_recv);
        exit 0))
  done;
  Printf.printf "No burst/collapse detected\n"
;;
