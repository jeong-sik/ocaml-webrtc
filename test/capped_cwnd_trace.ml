(** Test with manually capped cwnd to prevent the burst problem *)
open Webrtc

let () =
  Printf.printf "=== Capped CWND Test ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:56000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:56001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:56001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:56000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let start_time = Unix.gettimeofday () in

  (* Limit how many packets we send per tick based on flight/cwnd ratio *)
  let max_flight = 100000 in  (* Cap at ~100KB in flight *)

  Printf.printf "Running with flight capped at %d bytes...\n\n%!" max_flight;

  for step = 1 to 50000 do
    (* Only send if flight is below our cap (ignoring actual cwnd) *)
    if Sctp_full_transport.get_flight_size sender < max_flight then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ()
    end;

    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;

    if step mod 10000 = 0 then begin
      let s_udp = Udp_transport.get_stats sender_udp in
      let r_udp = Udp_transport.get_stats receiver_udp in
      let cwnd = Sctp_full_transport.get_cwnd sender in
      let flight = Sctp_full_transport.get_flight_size sender in
      let delta = s_udp.packets_sent - r_udp.packets_recv in
      Printf.printf "step %d: msgs=%d delta=%d cwnd=%d flight=%d\n%!" step !msgs delta cwnd flight
    end;

    if Sctp_full_transport.get_cwnd sender < 2000 &&
       Sctp_full_transport.get_flight_size sender > 50000 then begin
      Printf.printf "\n*** COLLAPSE at step %d ***\n" step;
      exit 0
    end
  done;

  let elapsed = Unix.gettimeofday () -. start_time in
  let s_udp = Udp_transport.get_stats sender_udp in
  let r_udp = Udp_transport.get_stats receiver_udp in
  Printf.printf "\n=== Completed 50000 steps without collapse! ===\n";
  Printf.printf "Time: %.2fs\n" elapsed;
  Printf.printf "Messages: %d\n" !msgs;
  Printf.printf "Throughput: %.2f MB/s\n" (float_of_int !msgs *. 1024.0 /. elapsed /. 1_000_000.0);
  Printf.printf "Packets sent: %d\n" s_udp.packets_sent;
  Printf.printf "Packets recv: %d\n" r_udp.packets_recv;
  Printf.printf "Final delta: %d\n" (s_udp.packets_sent - r_udp.packets_recv)
