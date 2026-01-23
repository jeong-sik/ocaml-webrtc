(** Full stats trace - correlate SCTP and UDP stats *)
open Webrtc

let () =
  Printf.printf "=== Full Stats Correlation Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:52000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:52001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:52001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:52000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  for step = 1 to 40000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ());
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    (* Report every 5000 steps *)
    if step mod 5000 = 0
    then (
      let s_sctp = Sctp_full_transport.get_stats sender in
      let r_sctp = Sctp_full_transport.get_stats receiver in
      let s_udp = Udp_transport.get_stats sender_udp in
      let r_udp = Udp_transport.get_stats receiver_udp in
      Printf.printf "\n=== Step %d ===\n" step;
      Printf.printf
        "SCTP Sender: msgs_sent=%d sacks_recv=%d rtx=%d\n"
        s_sctp.messages_sent
        s_sctp.sacks_recv
        s_sctp.retransmissions;
      Printf.printf
        "SCTP Receiver: msgs_recv=%d sacks_sent=%d\n"
        r_sctp.messages_recv
        r_sctp.sacks_sent;
      Printf.printf
        "UDP Sender: pkts_sent=%d pkts_recv=%d\n"
        s_udp.packets_sent
        s_udp.packets_recv;
      Printf.printf
        "UDP Receiver: pkts_sent=%d pkts_recv=%d\n"
        r_udp.packets_sent
        r_udp.packets_recv;
      Printf.printf
        "Correlation: sender_data_pkts=%d vs receiver_udp_recv=%d (delta=%d)\n"
        s_udp.packets_sent
        r_udp.packets_recv
        (s_udp.packets_sent - r_udp.packets_recv);
      Printf.printf
        "Correlation: receiver_sack_udp=%d vs sender_udp_recv=%d (delta=%d)\n%!"
        r_udp.packets_sent
        s_udp.packets_recv
        (r_udp.packets_sent - s_udp.packets_recv));
    (* Detect collapse *)
    if
      Sctp_full_transport.get_cwnd sender < 2000
      && Sctp_full_transport.get_flight_size sender > 100000
    then (
      let s_sctp = Sctp_full_transport.get_stats sender in
      let r_sctp = Sctp_full_transport.get_stats receiver in
      let s_udp = Udp_transport.get_stats sender_udp in
      let r_udp = Udp_transport.get_stats receiver_udp in
      Printf.printf "\n*** COLLAPSE at step %d ***\n" step;
      Printf.printf
        "Flight: %d, cwnd: %d\n"
        (Sctp_full_transport.get_flight_size sender)
        (Sctp_full_transport.get_cwnd sender);
      Printf.printf
        "SCTP: sacks_sent=%d sacks_recv=%d DELTA=%d\n"
        r_sctp.sacks_sent
        s_sctp.sacks_recv
        (r_sctp.sacks_sent - s_sctp.sacks_recv);
      Printf.printf
        "UDP data: sent=%d recv=%d DELTA=%d\n"
        s_udp.packets_sent
        r_udp.packets_recv
        (s_udp.packets_sent - r_udp.packets_recv);
      Printf.printf
        "UDP SACK: sent=%d recv=%d DELTA=%d\n"
        r_udp.packets_sent
        s_udp.packets_recv
        (r_udp.packets_sent - s_udp.packets_recv);
      exit 0)
  done;
  Printf.printf "No collapse\n"
;;
