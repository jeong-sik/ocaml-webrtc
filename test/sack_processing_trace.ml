(** Trace SACK processing to understand why flight keeps growing *)
open Webrtc

let () =
  Printf.printf "=== SACK Processing Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:58000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:58001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:58001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:58000;

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
  let s_stats = Sctp_full_transport.get_stats sender in
  let r_stats = Sctp_full_transport.get_stats receiver in
  Printf.printf "  sender: sacks_recv=%d sacks_sent=%d\n" s_stats.sacks_recv s_stats.sacks_sent;
  Printf.printf "  receiver: sacks_recv=%d sacks_sent=%d\n" r_stats.sacks_recv r_stats.sacks_sent;
  Printf.printf "  flight_size=%d cwnd=%d\n\n%!"
    (Sctp_full_transport.get_flight_size sender) (Sctp_full_transport.get_cwnd sender);

  Printf.printf "Detailed trace from 31701...\n\n%!";

  for step = 31701 to 31850 do
    let flight_before = Sctp_full_transport.get_flight_size sender in
    let sacks_recv_before = (Sctp_full_transport.get_stats sender).sacks_recv in
    let recv_pkts_before = (Udp_transport.get_stats receiver_udp).packets_recv in

    (* send_data *)
    if flight_before < Sctp_full_transport.get_cwnd sender then
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);

    let _send_pkts = (Udp_transport.get_stats sender_udp).packets_sent in

    (* receiver tick - processes incoming DATA, may send SACK *)
    Sctp_full_transport.tick receiver;
    let recv_pkts_after = (Udp_transport.get_stats receiver_udp).packets_recv in
    let recv_delta = recv_pkts_after - recv_pkts_before in

    (* Check receiver's sacks_sent *)
    let recv_sacks = (Sctp_full_transport.get_stats receiver).sacks_sent in

    (* sender tick - should receive SACK and release chunks *)
    Sctp_full_transport.tick sender;

    let sacks_recv_after = (Sctp_full_transport.get_stats sender).sacks_recv in
    let sack_delta = sacks_recv_after - sacks_recv_before in
    let flight_after = Sctp_full_transport.get_flight_size sender in
    let flight_change = flight_after - flight_before in

    (* Only print interesting steps *)
    if step mod 10 = 0 || flight_change > 1040 || sack_delta > 0 then begin
      Printf.printf "step %d: recv_data:%d sack_sent_by_recv:%d sack_recv_by_sender:%d | flight:%d->%d (change:%d)\n%!"
        step recv_delta recv_sacks sack_delta flight_before flight_after flight_change
    end;

    if flight_after > 32000 then begin
      Printf.printf "\n*** Flight > 32000 at step %d ***\n%!" step;
      Printf.printf "Total UDP: sender_sent=%d receiver_recv=%d\n"
        (Udp_transport.get_stats sender_udp).packets_sent
        (Udp_transport.get_stats receiver_udp).packets_recv;
      Printf.printf "SACKs: sender_recv=%d receiver_sent=%d\n"
        (Sctp_full_transport.get_stats sender).sacks_recv
        (Sctp_full_transport.get_stats receiver).sacks_sent;
      exit 0
    end
  done;

  Printf.printf "\nCompleted without flight overflow\n"
