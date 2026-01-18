(** Trace what happens IMMEDIATELY after T3-rtx retransmissions *)
open Webrtc

let () =
  Printf.printf "=== Immediate Post-Collapse Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:45000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:45001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:45001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:45000;

  let data = Bytes.make 1024 'X' in

  Printf.printf "=== Warm up (watching for collapse) ===\n%!";
  let msgs = ref 0 in
  let collapse_step = ref 0 in

  for step = 1 to 40000 do
    if step mod 5000 = 0 then Printf.printf "step %d, msgs=%d\n%!" step !msgs;

    if !collapse_step = 0 then begin
      if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
        match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
        | Ok _ -> incr msgs
        | Error _ -> ()
      end;

      Sctp_full_transport.tick receiver;
      Sctp_full_transport.tick sender;

      let cwnd = Sctp_full_transport.get_cwnd sender in
      let flight = Sctp_full_transport.get_flight_size sender in

      (* Same detection as other working tests *)
      if cwnd < 2000 && flight > 100000 then begin
        Printf.printf "\n*** COLLAPSE at step %d, msgs=%d ***\n%!" step !msgs;
        Printf.printf "cwnd: %d\n" cwnd;
        Printf.printf "flight: %d\n" flight;
        Printf.printf "rto: %.3f s\n" (Sctp_full_transport.get_rto sender);

        let s = Sctp_full_transport.get_stats sender in
        let r = Sctp_full_transport.get_stats receiver in
        Printf.printf "sender retransmissions: %d\n" s.retransmissions;
        Printf.printf "sender sacks_recv: %d\n" s.sacks_recv;
        Printf.printf "receiver msgs_recv: %d\n" r.messages_recv;
        Printf.printf "receiver sacks_sent: %d\n%!" r.sacks_sent;

        collapse_step := step;
        Printf.printf "\n*** Tracing next 10 ticks ***\n\n%!"
      end
    end else begin
      (* Detailed tracing after collapse *)
      let tick_num = step - !collapse_step in
      if tick_num >= 0 && tick_num <= 10 then begin
        let s_before = Sctp_full_transport.get_stats sender in
        let r_before = Sctp_full_transport.get_stats receiver in
        let flight_before = Sctp_full_transport.get_flight_size sender in

        Sctp_full_transport.tick receiver;

        let r_mid = Sctp_full_transport.get_stats receiver in
        let recv_delta = r_mid.messages_recv - r_before.messages_recv in
        let sack_delta = r_mid.sacks_sent - r_before.sacks_sent in

        Sctp_full_transport.tick sender;

        let s_after = Sctp_full_transport.get_stats sender in
        let flight_after = Sctp_full_transport.get_flight_size sender in

        Printf.printf "tick: recv_msgs=%d sack_sent=%d sender_sacks=%d flight=%d->%d\n"
          recv_delta sack_delta
          (s_after.sacks_recv - s_before.sacks_recv)
          flight_before flight_after
      end else if tick_num = 11 then begin
        Printf.printf "\n=== After ticks ===\n";
        Printf.printf "Final flight: %d\n" (Sctp_full_transport.get_flight_size sender);
        exit 0
      end
    end
  done;

  Printf.printf "No collapse detected (unexpected)\n"
