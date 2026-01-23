(** Fine-grained trace around collapse point *)
open Webrtc

let () =
  Printf.printf "=== Fine-Grained Collapse Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:50000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:50001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:50001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:50000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let prev_delta = ref 0 in
  Printf.printf "Tracking delta changes (will report when delta increases)...\n\n%!";
  for step = 1 to 40000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ());
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;
    let s_udp = Udp_transport.get_stats sender_udp in
    let r_udp = Udp_transport.get_stats receiver_udp in
    let delta = s_udp.packets_sent - r_udp.packets_recv in
    (* Report when delta increases *)
    if delta > !prev_delta
    then (
      let cwnd = Sctp_full_transport.get_cwnd sender in
      let flight = Sctp_full_transport.get_flight_size sender in
      let s = Sctp_full_transport.get_stats sender in
      Printf.printf
        "step %d: delta %d->%d sent=%d recv=%d cwnd=%d flight=%d rtx=%d\n%!"
        step
        !prev_delta
        delta
        s_udp.packets_sent
        r_udp.packets_recv
        cwnd
        flight
        s.retransmissions;
      prev_delta := delta;
      if cwnd < 2000 && flight > 100000
      then (
        Printf.printf "\n*** COLLAPSE ***\n";
        exit 0));
    (* Also report when retransmissions first appear *)
    let s = Sctp_full_transport.get_stats sender in
    if step mod 10000 = 0
    then
      Printf.printf
        "[checkpoint step %d: msgs=%d rtx=%d]\n%!"
        step
        !msgs
        s.retransmissions
  done;
  Printf.printf "Test completed without collapse\n"
;;
