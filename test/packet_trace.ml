(** Trace packet flow after T3-rtx collapse *)
open Webrtc

let () =
  Printf.printf "=== Packet Flow Trace ===\n\n";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:43000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:43001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:43001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:43000;

  let data = Bytes.make 1024 'X' in

  Printf.printf "=== Phase 1: Warm up ===\n";
  let msgs = ref 0 in
  let collapsed = ref false in

  for step = 1 to 40000 do
    if not !collapsed then begin
      if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
        match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
        | Ok _ -> incr msgs
        | Error _ -> ()
      end;

      let cwnd_before = Sctp_full_transport.get_cwnd sender in
      Sctp_full_transport.tick receiver;
      Sctp_full_transport.tick sender;
      let cwnd_after = Sctp_full_transport.get_cwnd sender in

      if cwnd_after < cwnd_before / 2 && cwnd_after < 2000 then begin
        Printf.printf "\n*** COLLAPSE at step %d (msg %d) ***\n" step !msgs;
        Printf.printf "cwnd: %d -> %d\n" cwnd_before cwnd_after;
        Printf.printf "flight: %d\n" (Sctp_full_transport.get_flight_size sender);

        let sender_stats = Sctp_full_transport.get_stats sender in
        let recv_stats = Sctp_full_transport.get_stats receiver in

        Printf.printf "\nSender stats:\n";
        Printf.printf "  msgs_sent: %d\n" sender_stats.messages_sent;
        Printf.printf "  bytes_sent: %d\n" sender_stats.bytes_sent;
        Printf.printf "  sacks_recv: %d\n" sender_stats.sacks_recv;
        Printf.printf "  retransmissions: %d\n" sender_stats.retransmissions;

        Printf.printf "\nReceiver stats:\n";
        Printf.printf "  msgs_recv: %d\n" recv_stats.messages_recv;
        Printf.printf "  bytes_recv: %d\n" recv_stats.bytes_recv;
        Printf.printf "  sacks_sent: %d\n" recv_stats.sacks_sent;

        collapsed := true
      end
    end else begin
      (* After collapse - trace detailed flow *)
      let s_before = Sctp_full_transport.get_stats sender in
      let r_before = Sctp_full_transport.get_stats receiver in

      Sctp_full_transport.tick receiver;
      Sctp_full_transport.tick sender;

      let s_after = Sctp_full_transport.get_stats sender in
      let r_after = Sctp_full_transport.get_stats receiver in

      let rtx = s_after.retransmissions - s_before.retransmissions in
      let fast_rtx = s_after.fast_retransmissions - s_before.fast_retransmissions in
      let new_sacks_sent = r_after.sacks_sent - r_before.sacks_sent in
      let new_sacks_recv = s_after.sacks_recv - s_before.sacks_recv in
      let new_msgs_recv = r_after.messages_recv - r_before.messages_recv in

      Printf.printf "tick %d: rtx=%d fast=%d sacks_sent=%d sacks_recv=%d msgs_recv=%d flight=%d\n"
        (step - 32144)  (* approximate collapse step *)
        rtx fast_rtx new_sacks_sent new_sacks_recv new_msgs_recv
        (Sctp_full_transport.get_flight_size sender);

      if step - 32144 > 50 then begin
        Printf.printf "\n=== After 50 post-collapse ticks ===\n";
        Printf.printf "flight: %d\n" (Sctp_full_transport.get_flight_size sender);
        Printf.printf "cwnd: %d\n" (Sctp_full_transport.get_cwnd sender);
        exit 0
      end
    end
  done
