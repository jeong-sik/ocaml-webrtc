(** Trace gap blocks to understand why they're being generated *)
open Webrtc

let () =
  Printf.printf "=== Gap Block Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:59000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:59001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:59001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:59000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in

  Printf.printf "Warmup to 31700...\n%!";
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;

  Printf.printf "At 31700:\n%!";
  let s_udp = Udp_transport.get_stats sender_udp in
  let r_udp = Udp_transport.get_stats receiver_udp in
  Printf.printf "  UDP: sender_sent=%d receiver_recv=%d delta=%d\n"
    s_udp.packets_sent r_udp.packets_recv (s_udp.packets_sent - r_udp.packets_recv);
  Printf.printf "  sender errors=%d\n\n%!" s_udp.send_errors;

  Printf.printf "Detailed trace from 31701...\n\n%!";

  for step = 31701 to 31850 do
    let s_before = (Udp_transport.get_stats sender_udp).packets_sent in
    let r_before = (Udp_transport.get_stats receiver_udp).packets_recv in
    let flight_before = Sctp_full_transport.get_flight_size sender in

    (* send_data *)
    if flight_before < Sctp_full_transport.get_cwnd sender then
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);

    let s_after_send = (Udp_transport.get_stats sender_udp).packets_sent in

    (* receiver tick *)
    Sctp_full_transport.tick receiver;
    let r_after_rtick = (Udp_transport.get_stats receiver_udp).packets_recv in

    (* sender tick *)
    Sctp_full_transport.tick sender;

    let s_final = (Udp_transport.get_stats sender_udp).packets_sent in
    let r_final = (Udp_transport.get_stats receiver_udp).packets_recv in
    let send_errors = (Udp_transport.get_stats sender_udp).send_errors in

    let send_pkts = s_after_send - s_before in
    let tick_pkts = s_final - s_after_send in
    let recv_by_rtick = r_after_rtick - r_before in
    let total_delta = s_final - r_final in
    let flight_after = Sctp_full_transport.get_flight_size sender in

    (* Only print interesting steps *)
    if tick_pkts > 0 || total_delta > 10 || step mod 20 = 0 || send_errors > 0 then begin
      Printf.printf "step %d: send:%d tick:%d | recv_rtick:%d | delta=%d flight:%d->%d errors=%d\n%!"
        step send_pkts tick_pkts recv_by_rtick total_delta flight_before flight_after send_errors
    end;

    if total_delta > 40 then begin
      Printf.printf "\n*** Delta > 40 at step %d ***\n%!" step;
      Printf.printf "UDP: sender_sent=%d receiver_recv=%d\n" s_final r_final;
      Printf.printf "Send errors: %d\n" send_errors;
      exit 0
    end
  done;

  Printf.printf "\nCompleted successfully\n"
