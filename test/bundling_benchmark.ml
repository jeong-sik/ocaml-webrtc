(** Bundling Benchmark - Tests chunk bundling with small packets

    With MTU=1280 and 128 byte packets:
    - Without bundling: 1 packet per UDP = 1 syscall
    - With bundling: ~8 packets per UDP = 8x fewer syscalls
*)

open Webrtc

let base_port = 26000
let packet_size = 128  (* Small packets to test bundling *)
let test_duration_sec = 5

let () =
  Eio_main.run @@ fun env ->
  let clock = Eio.Stdenv.clock env in

  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Bundling Benchmark - Small Packets (%d bytes)           ║\n" packet_size;
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";

  let shared_tsn =
    let r = Random.int32 0x7FFFFFFFl in
    if r = 0l then 1l else r
  in

  let sender = Eio_sctp_full_transport.create ~initial_tsn:shared_tsn ~host:"127.0.0.1" ~port:base_port () in
  let receiver = Eio_sctp_full_transport.create ~initial_tsn:shared_tsn ~host:"127.0.0.1" ~port:(base_port + 1) () in

  Eio_sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:(base_port + 1);
  Eio_sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:base_port;

  let data = Bytes.make packet_size 'X' in

  let msgs_sent = Atomic.make 0 in
  let bytes_sent = Atomic.make 0 in

  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in

  Eio.Fiber.all [
    (* Sender - sends small packets rapidly *)
    (fun () ->
      while Unix.gettimeofday () < end_time do
        let flight = Eio_sctp_full_transport.get_flight_size sender in
        let cwnd = Eio_sctp_full_transport.get_cwnd sender in
        if flight < cwnd then begin
          match Eio_sctp_full_transport.try_send_data sender ~stream_id:0 ~data with
          | Ok sent ->
            Atomic.incr msgs_sent;
            ignore (Atomic.fetch_and_add bytes_sent sent)
          | Error _ -> Eio.Fiber.yield ()
        end else
          Eio.Fiber.yield ()
      done
    );

    (* Sender tick *)
    (fun () ->
      while Unix.gettimeofday () < end_time do
        Eio_sctp_full_transport.tick sender;
        Eio.Fiber.yield ()
      done
    );

    (* Receiver tick *)
    (fun () ->
      while Unix.gettimeofday () < end_time do
        Eio_sctp_full_transport.tick receiver;
        Eio.Fiber.yield ()
      done
    );

    (* Stats *)
    (fun () ->
      while Unix.gettimeofday () < end_time do
        Eio.Time.sleep clock 1.0;
        let sent = Atomic.get msgs_sent in
        let recv = (Eio_sctp_full_transport.get_stats receiver).messages_recv in
        let rtx = (Eio_sctp_full_transport.get_stats sender).retransmissions in
        let ratio = if sent = 0 then 0.0 else 100.0 *. float recv /. float sent in
        Printf.printf "[%.1fs] sent=%d recv=%d (%.1f%%) rtx=%d\n%!"
          (Unix.gettimeofday () -. start_time) sent recv ratio rtx
      done
    );
  ];

  (* Drain phase *)
  Printf.printf "\nDraining...\n%!";
  let drain_end = Unix.gettimeofday () +. 2.0 in
  while Unix.gettimeofday () < drain_end do
    Eio_sctp_full_transport.tick sender;
    Eio_sctp_full_transport.tick receiver;
  done;

  let final_sent = Atomic.get msgs_sent in
  let final_bytes = Atomic.get bytes_sent in
  let sender_stats = Eio_sctp_full_transport.get_stats sender in
  let recv_stats = Eio_sctp_full_transport.get_stats receiver in
  let udp_sender = Udp_transport.get_stats (Eio_sctp_full_transport.get_udp_transport sender) in
  let udp_recv = Udp_transport.get_stats (Eio_sctp_full_transport.get_udp_transport receiver) in

  let elapsed = float_of_int test_duration_sec in
  let throughput = float final_bytes /. elapsed /. 1024.0 /. 1024.0 in
  let delivery_ratio = 100.0 *. float recv_stats.messages_recv /. float final_sent in
  let bundling_ratio = float final_sent /. float udp_sender.packets_sent in

  Printf.printf "\n═══ BUNDLING RESULTS ═══\n\n";
  Printf.printf "  SENDER:\n";
  Printf.printf "    Messages sent (SCTP):  %d\n" final_sent;
  Printf.printf "    UDP packets sent:      %d\n" udp_sender.packets_sent;
  Printf.printf "    Bundling ratio:        %.2fx (msgs/packet)\n" bundling_ratio;
  Printf.printf "    SACKs received:        %d\n" sender_stats.sacks_recv;
  Printf.printf "    Retransmissions:       %d\n" sender_stats.retransmissions;

  Printf.printf "\n  RECEIVER:\n";
  Printf.printf "    Messages recv (SCTP):  %d\n" recv_stats.messages_recv;
  Printf.printf "    UDP packets recv:      %d\n" udp_recv.packets_recv;
  Printf.printf "    SACKs sent:            %d\n" recv_stats.sacks_sent;

  Printf.printf "\n  ═══ METRICS ═══\n";
  Printf.printf "    Delivery ratio:        %.2f%%\n" delivery_ratio;
  Printf.printf "    Throughput:            %.2f MB/s\n" throughput;
  Printf.printf "    Syscall reduction:     %.1fx (via bundling)\n" bundling_ratio;

  if delivery_ratio >= 99.99 then
    Printf.printf "\n  ✓ Delivery is reliable (%.2f%%)\n" delivery_ratio
  else
    Printf.printf "\n  ✗ DELIVERY FAILURE: only %.2f%% delivered\n" delivery_ratio
