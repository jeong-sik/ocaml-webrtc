(** Test with slower send rate to see if packet loss is rate-related *)
open Webrtc

let () =
  Printf.printf "=== Slow Rate Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:55000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:55001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:55001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:55000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let start_time = Unix.gettimeofday () in

  Printf.printf "Running with 100us delay between ticks...\n\n%!";

  for step = 1 to 40000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ()
    end;

    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;

    (* Add small delay to slow down the rate *)
    if step mod 10 = 0 then
      ignore (Unix.select [] [] [] 0.0001);  (* 100us every 10 steps *)

    if step mod 5000 = 0 then begin
      let s_udp = Udp_transport.get_stats sender_udp in
      let r_udp = Udp_transport.get_stats receiver_udp in
      let cwnd = Sctp_full_transport.get_cwnd sender in
      let delta = s_udp.packets_sent - r_udp.packets_recv in
      Printf.printf "step %d: msgs=%d delta=%d cwnd=%d\n%!" step !msgs delta cwnd
    end;

    if Sctp_full_transport.get_cwnd sender < 2000 &&
       Sctp_full_transport.get_flight_size sender > 100000 then begin
      Printf.printf "\n*** COLLAPSE at step %d ***\n" step;
      exit 0
    end
  done;

  let elapsed = Unix.gettimeofday () -. start_time in
  let s_udp = Udp_transport.get_stats sender_udp in
  let r_udp = Udp_transport.get_stats receiver_udp in
  Printf.printf "\n=== Completed without collapse! ===\n";
  Printf.printf "Time: %.2fs\n" elapsed;
  Printf.printf "Messages: %d\n" !msgs;
  Printf.printf "Packets sent: %d\n" s_udp.packets_sent;
  Printf.printf "Packets recv: %d\n" r_udp.packets_recv;
  Printf.printf "Final delta: %d\n" (s_udp.packets_sent - r_udp.packets_recv)
