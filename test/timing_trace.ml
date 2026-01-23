(** Trace wall-clock timing to understand T3-rtx trigger *)
open Webrtc

let () =
  Printf.printf "=== Timing Trace ===\n\n%!";
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:54000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:54001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:54001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:54000;
  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in
  let data = Bytes.make 1024 'X' in
  Printf.printf "Warmup timing...\n%!";
  let warmup_start = Unix.gettimeofday () in
  for _step = 1 to 31700 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  let warmup_end = Unix.gettimeofday () in
  Printf.printf
    "Warmup took %.3f seconds (%.3f ms per step)\n\n%!"
    (warmup_end -. warmup_start)
    ((warmup_end -. warmup_start) *. 1000.0 /. 31700.0);
  let s0 = Udp_transport.get_stats sender_udp in
  let r0 = Udp_transport.get_stats receiver_udp in
  Printf.printf
    "At 31700: sent=%d recv=%d delta=%d\n%!"
    s0.packets_sent
    r0.packets_recv
    (s0.packets_sent - r0.packets_recv);
  Printf.printf "RTO: %.3f seconds\n\n%!" (Sctp_full_transport.get_rto sender);
  Printf.printf "Detailed timing from step 31701...\n\n%!";
  let last_t3_fire = ref None in
  for step = 31701 to 31850 do
    let step_start = Unix.gettimeofday () in
    let _abs_sent_before = (Udp_transport.get_stats sender_udp).packets_sent in
    let flight_before = Sctp_full_transport.get_flight_size sender in
    (* send_data *)
    if flight_before < Sctp_full_transport.get_cwnd sender
    then ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
    let abs_sent_after_send = (Udp_transport.get_stats sender_udp).packets_sent in
    (* receiver tick *)
    Sctp_full_transport.tick receiver;
    (* sender tick - where T3-rtx fires *)
    let rel_before = Sctp_full_transport.get_reliable_stats sender in
    Sctp_full_transport.tick sender;
    let rel_after = Sctp_full_transport.get_reliable_stats sender in
    let step_end = Unix.gettimeofday () in
    let step_duration = step_end -. step_start in
    let abs_sent_final = (Udp_transport.get_stats sender_udp).packets_sent in
    let abs_recv_final = (Udp_transport.get_stats receiver_udp).packets_recv in
    let tick_udp = abs_sent_final - abs_sent_after_send in
    let timeouts = rel_after.timeouts - rel_before.timeouts in
    let delta = abs_sent_final - abs_recv_final in
    let flight_after = Sctp_full_transport.get_flight_size sender in
    let rto = Sctp_full_transport.get_rto sender in
    (* Track when T3 fires *)
    if timeouts > 0
    then (
      (match !last_t3_fire with
       | None -> ()
       | Some last_step ->
         Printf.printf "  --> T3 interval: %d steps since last\n%!" (step - last_step));
      last_t3_fire := Some step);
    (* Report interesting steps *)
    if tick_udp > 0 || timeouts > 0 || step mod 20 = 0 || flight_before = 0
    then
      Printf.printf
        "step %d: %.3fms | tick_udp:%d timeout:%d | delta=%d flight:%d->%d rto:%.3f\n%!"
        step
        (step_duration *. 1000.0)
        tick_udp
        timeouts
        delta
        flight_before
        flight_after
        rto;
    if delta > 30
    then (
      Printf.printf "\n*** Delta exceeded 30 at step %d ***\n%!" step;
      exit 0)
  done;
  Printf.printf "\nCompleted without major issue\n"
;;
