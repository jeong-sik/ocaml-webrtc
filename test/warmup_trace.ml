(** Trace packet loss during warmup - BEFORE collapse *)
open Webrtc

let () =
  Printf.printf "=== Warmup Packet Loss Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:49000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:49001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:49001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:49000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let last_report = ref 0 in
  Printf.printf "Sending messages and tracking packet loss...\n\n%!";
  for step = 1 to 40000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ());
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    (* Report every 5000 steps *)
    if step mod 5000 = 0 && step <> !last_report
    then (
      last_report := step;
      let s_udp = Udp_transport.get_stats sender_udp in
      let r_udp = Udp_transport.get_stats receiver_udp in
      let delta = s_udp.packets_sent - r_udp.packets_recv in
      let cwnd = Sctp_full_transport.get_cwnd sender in
      let flight = Sctp_full_transport.get_flight_size sender in
      let s = Sctp_full_transport.get_stats sender in
      Printf.printf
        "step %5d: msgs=%d sent=%d recv=%d DELTA=%d cwnd=%d flight=%d rtx=%d\n%!"
        step
        !msgs
        s_udp.packets_sent
        r_udp.packets_recv
        delta
        cwnd
        flight
        s.retransmissions;
      (* Detect collapse early *)
      if cwnd < 2000 && flight > 100000
      then (
        Printf.printf "\n*** COLLAPSE DETECTED at step %d ***\n" step;
        Printf.printf "Last delta before collapse: %d packets\n" delta;
        exit 0))
  done;
  let s_udp = Udp_transport.get_stats sender_udp in
  let r_udp = Udp_transport.get_stats receiver_udp in
  Printf.printf "\n=== Final ===\n";
  Printf.printf "Packets sent: %d\n" s_udp.packets_sent;
  Printf.printf "Packets recv: %d\n" r_udp.packets_recv;
  Printf.printf "Total delta: %d\n" (s_udp.packets_sent - r_udp.packets_recv)
;;
