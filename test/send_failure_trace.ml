(** Trace if sends fail during T3-rtx retransmission burst *)
open Webrtc

let () =
  Printf.printf "=== Send Failure Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:57000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:57001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:57001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:57000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let collapse_step = ref 0 in

  Printf.printf "Phase 1: Warm up until collapse...\n%!";

  for step = 1 to 50000 do
    if !collapse_step = 0 then begin
      (* Normal send *)
      if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
        match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
        | Ok _ -> incr msgs
        | Error _ -> ()
      end;

      Sctp_full_transport.tick receiver;
      Sctp_full_transport.tick sender;

      (* Detect collapse *)
      if Sctp_full_transport.get_cwnd sender < 2000 &&
         Sctp_full_transport.get_flight_size sender > 50000 then begin
        Printf.printf "\n*** COLLAPSE DETECTED at step %d ***\n%!" step;
        collapse_step := step;
        let s_udp = Udp_transport.get_stats sender_udp in
        let r_udp = Udp_transport.get_stats receiver_udp in
        Printf.printf "At collapse:\n";
        Printf.printf "  Sender: sent=%d errors=%d\n" s_udp.packets_sent s_udp.send_errors;
        Printf.printf "  Receiver: recv=%d\n" r_udp.packets_recv;
        Printf.printf "  Delta: %d\n" (s_udp.packets_sent - r_udp.packets_recv);
        Printf.printf "  cwnd=%d flight=%d\n"
          (Sctp_full_transport.get_cwnd sender)
          (Sctp_full_transport.get_flight_size sender);
      end
    end else begin
      (* Post-collapse: manually test send burst *)
      let ticks_since = step - !collapse_step in

      if ticks_since = 1 then begin
        Printf.printf "\nPhase 2: Manual burst test (sending 500 packets)...\n%!";
        let buf = Bytes.make 1100 'Y' in
        let success = ref 0 in
        let would_block = ref 0 in
        let other_error = ref 0 in

        for _ = 1 to 500 do
          match Udp_transport.send_connected sender_udp ~data:buf with
          | Ok _ -> incr success
          | Error "Would block" -> incr would_block
          | Error _ -> incr other_error
        done;

        Printf.printf "Burst results:\n";
        Printf.printf "  Success: %d\n" !success;
        Printf.printf "  Would block: %d\n" !would_block;
        Printf.printf "  Other errors: %d\n" !other_error;

        (* Now drain receiver *)
        Sctp_full_transport.tick receiver;

        let r_udp = Udp_transport.get_stats receiver_udp in
        let s_udp = Udp_transport.get_stats sender_udp in
        Printf.printf "\nAfter drain:\n";
        Printf.printf "  Sender: sent=%d\n" s_udp.packets_sent;
        Printf.printf "  Receiver: recv=%d\n" r_udp.packets_recv;
        Printf.printf "  New delta: %d\n" (s_udp.packets_sent - r_udp.packets_recv);

        exit 0
      end
    end
  done;

  Printf.printf "No collapse detected\n"
