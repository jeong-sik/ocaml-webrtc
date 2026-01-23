(** Trace fast retransmit specifically *)
open Webrtc

let () =
  Printf.printf "=== Fast Retransmit Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:53000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:53001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:53001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:53000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  Printf.printf "Warmup...\n%!";
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  let s0 = Udp_transport.get_stats sender_udp in
  let r0 = Udp_transport.get_stats receiver_udp in
  let rel0 = Sctp_full_transport.get_reliable_stats sender in
  Printf.printf
    "At 31700: sent=%d recv=%d delta=%d\n"
    s0.packets_sent
    r0.packets_recv
    (s0.packets_sent - r0.packets_recv);
  Printf.printf
    "         fast_rtx=%d timeouts=%d\n\n%!"
    rel0.fast_retransmissions
    rel0.timeouts;
  Printf.printf "Detailed trace from 31701...\n\n%!";
  for step = 31701 to 31850 do
    let abs_sent_before = (Udp_transport.get_stats sender_udp).packets_sent in
    let flight_before = Sctp_full_transport.get_flight_size sender in
    let _rel_before = Sctp_full_transport.get_reliable_stats sender in
    (* send_data *)
    if flight_before < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    let abs_sent_after_send = (Udp_transport.get_stats sender_udp).packets_sent in
    let send_pkts = abs_sent_after_send - abs_sent_before in
    (* receiver tick *)
    Sctp_full_transport.tick receiver;
    let _abs_recv_after = (Udp_transport.get_stats receiver_udp).packets_recv in
    (* sender tick *)
    let rel_pre_tick = Sctp_full_transport.get_reliable_stats sender in
    Sctp_full_transport.tick sender;
    let rel_post_tick = Sctp_full_transport.get_reliable_stats sender in
    let abs_sent_final = (Udp_transport.get_stats sender_udp).packets_sent in
    let abs_recv_final = (Udp_transport.get_stats receiver_udp).packets_recv in
    let tick_pkts = abs_sent_final - abs_sent_after_send in
    let fast_delta =
      rel_post_tick.fast_retransmissions - rel_pre_tick.fast_retransmissions
    in
    let timeout_delta = rel_post_tick.timeouts - rel_pre_tick.timeouts in
    let retx_delta = rel_post_tick.retransmissions - rel_pre_tick.retransmissions in
    let delta = abs_sent_final - abs_recv_final in
    let flight_after = Sctp_full_transport.get_flight_size sender in
    (* Only print when interesting *)
    if tick_pkts > 0 || timeout_delta > 0 || fast_delta > 0 || step mod 20 = 0
    then
      Printf.printf
        "step %d: send:%d tick:%d | fast_rtx:%d timeout:%d retx:%d | delta=%d \
         flight:%d->%d\n\
         %!"
        step
        send_pkts
        tick_pkts
        fast_delta
        timeout_delta
        retx_delta
        delta
        flight_before
        flight_after;
    if delta > 30
    then (
      Printf.printf "\n*** Delta > 30 at step %d ***\n%!" step;
      Printf.printf
        "Total: fast_rtx=%d timeouts=%d retx=%d\n"
        rel_post_tick.fast_retransmissions
        rel_post_tick.timeouts
        rel_post_tick.retransmissions;
      exit 0)
  done;
  Printf.printf "\nCompleted without major issue\n"
;;
