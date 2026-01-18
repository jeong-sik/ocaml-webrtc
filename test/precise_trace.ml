(** Precise trace with fine-grained UDP monitoring *)
open Webrtc

let () =
  Printf.printf "=== Precise UDP Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:59000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:59001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:59001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:59000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in
  let last_delta = ref 0 in

  (* Skip to near the problem area *)
  Printf.printf "Fast forwarding to step 31700...\n%!";
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;

  let s0 = Udp_transport.get_stats sender_udp in
  let r0 = Udp_transport.get_stats receiver_udp in
  Printf.printf "At step 31700: sent=%d recv=%d delta=%d\n\n%!"
    s0.packets_sent r0.packets_recv (s0.packets_sent - r0.packets_recv);

  Printf.printf "Detailed trace from step 31700:\n%!";

  for step = 31701 to 32000 do
    let s_start = Udp_transport.get_stats sender_udp in
    let r_start = Udp_transport.get_stats receiver_udp in
    let flight_start = Sctp_full_transport.get_flight_size sender in

    (* send_data *)
    let _sent_ok =
      if flight_start < Sctp_full_transport.get_cwnd sender then begin
        match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
        | Ok _ -> true
        | Error _ -> false
      end else false
    in

    let s_after_send = Udp_transport.get_stats sender_udp in
    let udp_sent_by_send = s_after_send.packets_sent - s_start.packets_sent in

    (* receiver tick *)
    Sctp_full_transport.tick receiver;

    let r_after_recv_tick = Udp_transport.get_stats receiver_udp in
    let s_after_recv_tick = Udp_transport.get_stats sender_udp in
    let udp_recv_by_recv = r_after_recv_tick.packets_recv - r_start.packets_recv in
    let _sacks_sent_by_recv = s_after_recv_tick.packets_recv - s_after_send.packets_recv in

    (* sender tick *)
    Sctp_full_transport.tick sender;

    let s_final = Udp_transport.get_stats sender_udp in
    let r_final = Udp_transport.get_stats receiver_udp in
    let udp_sent_by_sender_tick = s_final.packets_sent - s_after_recv_tick.packets_sent in
    let _udp_recv_by_sender = s_final.packets_recv - r_after_recv_tick.packets_recv in

    let delta = s_final.packets_sent - r_final.packets_recv in
    let flight_end = Sctp_full_transport.get_flight_size sender in

    (* Report if delta changes or once per 10 steps *)
    if delta <> !last_delta || step mod 10 = 0 then begin
      Printf.printf "step %d: d=%d->%d | send_data:%d sent, recv_tick:%d recv, sender_tick:%d sent | flight:%d->%d\n%!"
        step !last_delta delta
        udp_sent_by_send udp_recv_by_recv udp_sent_by_sender_tick
        flight_start flight_end;
      last_delta := delta
    end;

    if delta > 100 then begin
      Printf.printf "\nDelta exceeded 100, stopping\n";
      Printf.printf "Final: sent=%d recv=%d\n" s_final.packets_sent r_final.packets_recv;
      exit 0
    end
  done;

  Printf.printf "Completed 300 steps without major loss\n"
