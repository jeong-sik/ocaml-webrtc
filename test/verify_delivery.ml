(** Quick verification - is receiver actually receiving? *)
open Webrtc

let () =
  Eio_main.run @@ fun _env ->

  Printf.printf "=== Verification: Is data actually being received? ===\n\n";

  let sender = Eio_sctp_full_transport.create ~host:"127.0.0.1" ~port:24000 () in
  let receiver = Eio_sctp_full_transport.create ~host:"127.0.0.1" ~port:24001 () in

  Eio_sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:24001;
  Eio_sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:24000;

  let data = Bytes.make 1024 'X' in
  let sent_count = ref 0 in

  (* Send 1000 messages with proper ticking *)
  for _ = 1 to 1000 do
    (* Sender: try to send if cwnd allows *)
    if Eio_sctp_full_transport.get_flight_size sender <
       Eio_sctp_full_transport.get_cwnd sender then begin
      match Eio_sctp_full_transport.try_send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr sent_count
      | Error _ -> ()
    end;

    (* Both tick *)
    Eio_sctp_full_transport.tick receiver;
    Eio_sctp_full_transport.tick sender;
  done;

  (* Final drain *)
  for _ = 1 to 100 do
    Eio_sctp_full_transport.tick receiver;
    Eio_sctp_full_transport.tick sender;
  done;

  let sender_stats = Eio_sctp_full_transport.get_stats sender in
  let receiver_stats = Eio_sctp_full_transport.get_stats receiver in
  let sender_udp = Eio_sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Eio_sctp_full_transport.get_udp_transport receiver in
  let sender_udp_stats = Udp_transport.get_stats sender_udp in
  let receiver_udp_stats = Udp_transport.get_stats receiver_udp in

  Printf.printf "SENDER:\n";
  Printf.printf "  Messages sent (SCTP): %d\n" sender_stats.messages_sent;
  Printf.printf "  UDP packets sent:     %d\n" sender_udp_stats.packets_sent;
  Printf.printf "  SACKs received:       %d\n" sender_stats.sacks_recv;
  Printf.printf "  Retransmissions:      %d\n" sender_stats.retransmissions;

  Printf.printf "\nRECEIVER:\n";
  Printf.printf "  Messages recv (SCTP): %d\n" receiver_stats.messages_recv;
  Printf.printf "  UDP packets recv:     %d\n" receiver_udp_stats.packets_recv;
  Printf.printf "  SACKs sent:           %d\n" receiver_stats.sacks_sent;

  Printf.printf "\n=== VERIFICATION ===\n";
  if receiver_stats.messages_recv > 0 then
    Printf.printf "✓ Receiver IS receiving data! (%d messages)\n" receiver_stats.messages_recv
  else
    Printf.printf "✗ WARNING: Receiver got 0 messages!\n";

  let ratio = if sender_stats.messages_sent > 0
    then float_of_int receiver_stats.messages_recv /. float_of_int sender_stats.messages_sent *. 100.0
    else 0.0 in
  Printf.printf "  Delivery ratio: %.1f%%\n" ratio;

  Eio_sctp_full_transport.close sender;
  Eio_sctp_full_transport.close receiver
