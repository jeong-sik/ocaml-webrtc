(** Trace the exact moment packets start being lost *)
open Webrtc

let () =
  Printf.printf "=== Moment Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:58000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:58001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:58001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:58000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let last_delta = ref 0 in
  for step = 1 to 50000 do
    (* Track state before operations *)
    let s_before = Udp_transport.get_stats sender_udp in
    let r_before = Udp_transport.get_stats receiver_udp in
    let cwnd_before = Sctp_full_transport.get_cwnd sender in
    let flight_before = Sctp_full_transport.get_flight_size sender in
    (* Try to send data *)
    let sent_this_step =
      if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
      then (
        match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
        | Ok _ ->
          incr msgs;
          true
        | Error _ -> false)
      else false
    in
    let s_after_send = Udp_transport.get_stats sender_udp in
    let packets_sent_this_step = s_after_send.packets_sent - s_before.packets_sent in
    (* Tick receiver and sender *)
    Sctp_full_transport.tick receiver;
    let r_after_recv = Udp_transport.get_stats receiver_udp in
    let packets_recv_this_step = r_after_recv.packets_recv - r_before.packets_recv in
    Sctp_full_transport.tick sender;
    let s_final = Udp_transport.get_stats sender_udp in
    let r_final = Udp_transport.get_stats receiver_udp in
    let delta = s_final.packets_sent - r_final.packets_recv in
    (* Report when delta changes *)
    if delta <> !last_delta
    then (
      Printf.printf
        "step %d: delta %d->%d | sent_this=%d recv_this=%d | cwnd=%d flight=%d | sent=%b\n\
         %!"
        step
        !last_delta
        delta
        packets_sent_this_step
        packets_recv_this_step
        cwnd_before
        flight_before
        sent_this_step;
      last_delta := delta);
    (* Stop after seeing significant loss *)
    if delta > 50
    then (
      Printf.printf "\nStopping after 50 lost packets\n";
      Printf.printf "Total sent: %d, recv: %d\n" s_final.packets_sent r_final.packets_recv;
      exit 0);
    (* Detect collapse *)
    if
      Sctp_full_transport.get_cwnd sender < 2000
      && Sctp_full_transport.get_flight_size sender > 50000
    then (
      Printf.printf "\n*** COLLAPSE at step %d ***\n" step;
      Printf.printf
        "Total sent: %d, recv: %d, delta: %d\n"
        s_final.packets_sent
        r_final.packets_recv
        delta;
      exit 0)
  done;
  Printf.printf "Completed without collapse\n"
;;
