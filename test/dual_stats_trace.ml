(** Trace BOTH stats structures to find the discrepancy *)
open Webrtc

let () =
  Printf.printf "=== Dual Stats Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:57000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:57001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:57001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:57000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let _receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in

  Printf.printf "Warmup to 31700...\n%!";
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;

  let rel_stats0 = Sctp_full_transport.get_reliable_stats sender in
  let tr_stats0 = Sctp_full_transport.get_stats sender in
  Printf.printf "At 31700:\n";
  Printf.printf "  reliable.stats: fast_rtx=%d timeouts=%d retx=%d\n"
    rel_stats0.fast_retransmissions rel_stats0.timeouts rel_stats0.retransmissions;
  Printf.printf "  transport.stats: fast_rtx=%d retx=%d\n\n%!"
    tr_stats0.fast_retransmissions tr_stats0.retransmissions;

  Printf.printf "Detailed trace from 31701...\n\n%!";

  for step = 31701 to 31850 do
    let abs_sent_before = (Udp_transport.get_stats sender_udp).packets_sent in
    let flight_before = Sctp_full_transport.get_flight_size sender in

    (* CAPTURE BOTH STATS BEFORE *)
    let rel_pre = Sctp_full_transport.get_reliable_stats sender in
    let tr_pre = Sctp_full_transport.get_stats sender in

    (* send_data *)
    if flight_before < Sctp_full_transport.get_cwnd sender then
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);

    let abs_sent_after_send = (Udp_transport.get_stats sender_udp).packets_sent in
    let send_pkts = abs_sent_after_send - abs_sent_before in

    (* receiver tick *)
    Sctp_full_transport.tick receiver;

    (* sender tick *)
    Sctp_full_transport.tick sender;

    (* CAPTURE STATS AFTER *)
    let rel_post = Sctp_full_transport.get_reliable_stats sender in
    let tr_post = Sctp_full_transport.get_stats sender in

    let abs_sent_final = (Udp_transport.get_stats sender_udp).packets_sent in
    let tick_pkts = abs_sent_final - abs_sent_after_send in
    let flight_after = Sctp_full_transport.get_flight_size sender in

    (* Compute deltas for reliable stats (marking counter) *)
    let rel_fast_delta = rel_post.fast_retransmissions - rel_pre.fast_retransmissions in
    let rel_timeout_delta = rel_post.timeouts - rel_pre.timeouts in
    let _rel_retx_delta = rel_post.retransmissions - rel_pre.retransmissions in

    (* Compute deltas for transport stats (actual sends) *)
    let tr_fast_delta = tr_post.fast_retransmissions - tr_pre.fast_retransmissions in
    let tr_retx_delta = tr_post.retransmissions - tr_pre.retransmissions in

    (* Only print interesting steps *)
    if tick_pkts > 0 || rel_fast_delta > 0 || rel_timeout_delta > 0 || step mod 20 = 0 then begin
      Printf.printf "step %d: send:%d tick:%d | rel_mark:%d rel_to:%d | tr_fast:%d tr_rtx:%d | flight:%d->%d\n%!"
        step send_pkts tick_pkts rel_fast_delta rel_timeout_delta
        tr_fast_delta tr_retx_delta
        flight_before flight_after
    end;

    if tick_pkts > 30 then begin
      Printf.printf "\n*** tick_pkts > 30 at step %d ***\n%!" step;
      Printf.printf "Final reliable stats: fast=%d to=%d rtx=%d\n"
        rel_post.fast_retransmissions rel_post.timeouts rel_post.retransmissions;
      Printf.printf "Final transport stats: fast=%d rtx=%d\n"
        tr_post.fast_retransmissions tr_post.retransmissions;
      exit 0
    end
  done;

  Printf.printf "\nFinal stats:\n";
  let rel_final = Sctp_full_transport.get_reliable_stats sender in
  let tr_final = Sctp_full_transport.get_stats sender in
  Printf.printf "  reliable: fast_rtx=%d timeouts=%d retx=%d\n"
    rel_final.fast_retransmissions rel_final.timeouts rel_final.retransmissions;
  Printf.printf "  transport: fast_rtx=%d retx=%d\n"
    tr_final.fast_retransmissions tr_final.retransmissions
