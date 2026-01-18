(** Trace which retransmission mechanism fires and packet delivery *)
open Webrtc

let () =
  Printf.printf "=== Retransmission Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:57000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:57001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:57001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:57000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in
  let last_delta = ref 0 in

  (* Skip to near problem area *)
  Printf.printf "Fast forwarding to step 31700...\n%!";
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;

  let s0 = Udp_transport.get_stats sender_udp in
  let r0 = Udp_transport.get_stats receiver_udp in
  Printf.printf "At step 31700: sent=%d recv=%d delta=%d\n"
    s0.packets_sent r0.packets_recv (s0.packets_sent - r0.packets_recv);
  Printf.printf "RTO: %.3fs  cwnd: %d  flight: %d\n\n%!"
    (Sctp_full_transport.get_rto sender)
    (Sctp_full_transport.get_cwnd sender)
    (Sctp_full_transport.get_flight_size sender);

  Printf.printf "Detailed trace from step 31701:\n%!";

  for step = 31701 to 32000 do
    let s_before = Udp_transport.get_stats sender_udp in
    let r_before = Udp_transport.get_stats receiver_udp in
    let flight_before = Sctp_full_transport.get_flight_size sender in
    let cwnd_before = Sctp_full_transport.get_cwnd sender in
    let rto_before = Sctp_full_transport.get_rto sender in
    let rel_stats_before = Sctp_full_transport.get_reliable_stats sender in

    (* send_data *)
    let did_send =
      if flight_before < cwnd_before then begin
        match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
        | Ok _ -> true
        | Error _ -> false
      end else false
    in

    let s_after_send = Udp_transport.get_stats sender_udp in
    let pkts_by_send = s_after_send.packets_sent - s_before.packets_sent in

    (* receiver tick *)
    Sctp_full_transport.tick receiver;

    let r_after_recv = Udp_transport.get_stats receiver_udp in
    let pkts_recv_by_tick = r_after_recv.packets_recv - r_before.packets_recv in
    let _sacks_sent = (Sctp_full_transport.get_stats receiver).sacks_sent in

    (* sender tick - this is where retransmissions happen *)
    let rel_stats_pre_tick = Sctp_full_transport.get_reliable_stats sender in

    Sctp_full_transport.tick sender;

    let s_final = Udp_transport.get_stats sender_udp in
    let r_final = Udp_transport.get_stats receiver_udp in
    let rel_stats_after = Sctp_full_transport.get_reliable_stats sender in

    let pkts_by_sender_tick = s_final.packets_sent - s_after_send.packets_sent in
    let t3_rtx_delta = rel_stats_after.retransmissions - rel_stats_pre_tick.retransmissions in
    let fast_rtx_delta = rel_stats_after.fast_retransmissions - rel_stats_pre_tick.fast_retransmissions in
    let timeouts = rel_stats_after.timeouts - rel_stats_before.timeouts in

    let delta = s_final.packets_sent - r_final.packets_recv in
    let flight_after = Sctp_full_transport.get_flight_size sender in
    let rto_after = Sctp_full_transport.get_rto sender in

    (* Report on changes *)
    if delta <> !last_delta || step mod 20 = 0 || timeouts > 0 || pkts_by_sender_tick > 0 then begin
      Printf.printf "step %d: delta=%d->%d | send:%b->%d recv:%d | tick_sent:%d (t3:%d fast:%d timeout:%d) | flight:%d->%d cwnd:%d rto:%.3f->%.3f\n%!"
        step !last_delta delta
        did_send pkts_by_send pkts_recv_by_tick
        pkts_by_sender_tick t3_rtx_delta fast_rtx_delta timeouts
        flight_before flight_after cwnd_before rto_before rto_after;
      last_delta := delta
    end;

    if delta > 50 then begin
      Printf.printf "\n*** Delta exceeded 50, stopping ***\n";
      Printf.printf "Final stats: sent=%d recv=%d\n" s_final.packets_sent r_final.packets_recv;
      exit 0
    end
  done;

  Printf.printf "Completed without major loss\n"
