(** Trace the exact boundary where things break *)
open Webrtc

let () =
  Printf.printf "=== Boundary Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:55000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:55001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:55001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:55000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  Printf.printf "Phase 1: Warmup to 31700...\n%!";
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  let s0 = Udp_transport.get_stats sender_udp in
  let r0 = Udp_transport.get_stats receiver_udp in
  Printf.printf
    "At 31700: sent=%d recv=%d delta=%d\n\n%!"
    s0.packets_sent
    r0.packets_recv
    (s0.packets_sent - r0.packets_recv);
  Printf.printf "Phase 2: Step-by-step from 31701...\n\n%!";
  for step = 31701 to 31850 do
    (* Capture ABSOLUTE stats before *)
    let abs_sent_before = (Udp_transport.get_stats sender_udp).packets_sent in
    let abs_recv_before = (Udp_transport.get_stats receiver_udp).packets_recv in
    (* === SEND_DATA === *)
    let flight = Sctp_full_transport.get_flight_size sender in
    let cwnd = Sctp_full_transport.get_cwnd sender in
    let can = flight < cwnd in
    let send_result =
      if can
      then Sctp_full_transport.send_data sender ~stream_id:0 ~data
      else Error "skipped"
    in
    let abs_sent_after_send = (Udp_transport.get_stats sender_udp).packets_sent in
    let udp_by_send = abs_sent_after_send - abs_sent_before in
    (* === RECEIVER TICK === *)
    Sctp_full_transport.tick receiver;
    let abs_recv_after_rtick = (Udp_transport.get_stats receiver_udp).packets_recv in
    let udp_recv = abs_recv_after_rtick - abs_recv_before in
    (* === SENDER TICK === *)
    Sctp_full_transport.tick sender;
    let abs_sent_final = (Udp_transport.get_stats sender_udp).packets_sent in
    let abs_recv_final = (Udp_transport.get_stats receiver_udp).packets_recv in
    let udp_by_stick = abs_sent_final - abs_sent_after_send in
    let total_delta = abs_sent_final - abs_recv_final in
    let flight_after = Sctp_full_transport.get_flight_size sender in
    (* Print every step for detailed analysis *)
    Printf.printf
      "step %d: can=%b result=%s | send_udp:%d recv_udp:%d tick_udp:%d | abs_sent=%d \
       abs_recv=%d delta=%d flight=%d->%d\n\
       %!"
      step
      can
      (match send_result with
       | Ok n -> Printf.sprintf "Ok(%d)" n
       | Error e -> Printf.sprintf "Err(%s)" e)
      udp_by_send
      udp_recv
      udp_by_stick
      abs_sent_final
      abs_recv_final
      total_delta
      flight
      flight_after;
    if total_delta > 30
    then (
      Printf.printf "\n*** Delta exceeded 30 at step %d, stopping ***\n%!" step;
      exit 0)
  done;
  Printf.printf "\nCompleted without major issue\n"
;;
