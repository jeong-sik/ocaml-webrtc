(** Trace absolute UDP stats values *)
open Webrtc

let () =
  Printf.printf "=== Absolute Stats Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:60000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:60001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:60001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:60000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  Printf.printf "Testing stat capture...\n";
  Printf.printf
    "Before any send: sender_sent=%d\n%!"
    (Udp_transport.get_stats sender_udp).packets_sent;
  (* Send one packet directly via UDP *)
  let buf = Bytes.make 100 'T' in
  ignore (Udp_transport.send_connected sender_udp ~data:buf);
  Printf.printf
    "After direct UDP send: sender_sent=%d\n%!"
    (Udp_transport.get_stats sender_udp).packets_sent;
  (* Send via SCTP *)
  ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
  Printf.printf
    "After SCTP send_data: sender_sent=%d\n%!"
    (Udp_transport.get_stats sender_udp).packets_sent;
  (* Tick receiver *)
  Sctp_full_transport.tick receiver;
  Printf.printf
    "After receiver tick: receiver_recv=%d\n%!"
    (Udp_transport.get_stats receiver_udp).packets_recv;
  Printf.printf "\n---\nNow testing in loop (steps 31770-31780):\n\n%!";
  (* Fast forward *)
  for _step = 1 to 31770 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  Printf.printf
    "At step 31770: sent=%d recv=%d\n\n%!"
    (Udp_transport.get_stats sender_udp).packets_sent
    (Udp_transport.get_stats receiver_udp).packets_recv;
  (* Detailed trace of 10 steps *)
  for step = 31771 to 31780 do
    let before = (Udp_transport.get_stats sender_udp).packets_sent in
    let recv_before = (Udp_transport.get_stats receiver_udp).packets_recv in
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    let after_send = (Udp_transport.get_stats sender_udp).packets_sent in
    Sctp_full_transport.tick receiver;
    let recv_after = (Udp_transport.get_stats receiver_udp).packets_recv in
    Sctp_full_transport.tick sender;
    let after_all = (Udp_transport.get_stats sender_udp).packets_sent in
    let recv_final = (Udp_transport.get_stats receiver_udp).packets_recv in
    let flight = Sctp_full_transport.get_flight_size sender in
    Printf.printf
      "step %d: sent %d->%d->%d | recv %d->%d->%d | delta=%d flight=%d\n%!"
      step
      before
      after_send
      after_all
      recv_before
      recv_after
      recv_final
      (after_all - recv_final)
      flight
  done
;;
