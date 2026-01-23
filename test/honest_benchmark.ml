(** HONEST Benchmark - Measures BOTH sent AND received

    Previous benchmark only measured "bytes sent" which is misleading.
    This benchmark measures actual end-to-end delivery.
*)

open Webrtc

let base_port = 25000
let packet_size = 1024
let test_duration_sec = 5

let () =
  Eio_main.run
  @@ fun env ->
  let clock = Eio.Stdenv.clock env in
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     HONEST Benchmark - Measuring ACTUAL Delivery             ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  (* Generate shared initial TSN - in production this comes from 4-way handshake
     RFC 4960 requires random TSN, so we generate one and share it *)
  let shared_tsn =
    let r = Random.int32 0x7FFFFFFFl in
    if r = 0l then 1l else r
  in
  (* Create pair with shared TSN *)
  let sender =
    Eio_sctp_full_transport.create
      ~initial_tsn:shared_tsn
      ~host:"127.0.0.1"
      ~port:base_port
      ()
  in
  let receiver =
    Eio_sctp_full_transport.create
      ~initial_tsn:shared_tsn
      ~host:"127.0.0.1"
      ~port:(base_port + 1)
      ()
  in
  Eio_sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:(base_port + 1);
  Eio_sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:base_port;
  let data = Bytes.make packet_size 'X' in
  (* Track BOTH sides *)
  let msgs_sent = Atomic.make 0 in
  let bytes_sent = Atomic.make 0 in
  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in
  Eio.Fiber.all
    [ (* Sender *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          let flight = Eio_sctp_full_transport.get_flight_size sender in
          let cwnd = Eio_sctp_full_transport.get_cwnd sender in
          if flight < cwnd
          then (
            match Eio_sctp_full_transport.try_send_data sender ~stream_id:0 ~data with
            | Ok sent ->
              Atomic.incr msgs_sent;
              ignore (Atomic.fetch_and_add bytes_sent sent)
            | Error _ -> Eio.Fiber.yield ())
          else Eio.Fiber.yield ()
        done)
    ; (* Sender tick *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          Eio_sctp_full_transport.tick sender;
          Eio.Fiber.yield ()
        done)
    ; (* Receiver tick *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          Eio_sctp_full_transport.tick receiver;
          Eio.Fiber.yield ()
        done)
    ; (* Stats *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          Eio.Time.sleep clock 1.0;
          let sent = Atomic.get msgs_sent in
          let sender_stats = Eio_sctp_full_transport.get_stats sender in
          let receiver_stats = Eio_sctp_full_transport.get_stats receiver in
          let elapsed = Unix.gettimeofday () -. start_time in
          Printf.printf
            "[%.1fs] sent=%d recv=%d (%.1f%%) rtx=%d\n%!"
            elapsed
            sent
            receiver_stats.messages_recv
            (if sent > 0
             then float_of_int receiver_stats.messages_recv /. float_of_int sent *. 100.0
             else 0.0)
            sender_stats.retransmissions
        done)
    ];
  (* Drain remaining - give receiver time to process *)
  Printf.printf "\nDraining...\n%!";
  for _ = 1 to 1000 do
    Eio_sctp_full_transport.tick sender;
    Eio_sctp_full_transport.tick receiver
  done;
  let elapsed = Unix.gettimeofday () -. start_time in
  let total_sent = Atomic.get msgs_sent in
  let total_bytes_sent = Atomic.get bytes_sent in
  let sender_stats = Eio_sctp_full_transport.get_stats sender in
  let receiver_stats = Eio_sctp_full_transport.get_stats receiver in
  let sender_udp = Eio_sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Eio_sctp_full_transport.get_udp_transport receiver in
  let sender_udp_stats = Udp_transport.get_stats sender_udp in
  let receiver_udp_stats = Udp_transport.get_stats receiver_udp in
  Printf.printf "\n═══ HONEST RESULTS ═══\n";
  Printf.printf "\n  SENDER:\n";
  Printf.printf "    Messages sent (SCTP):  %d\n" sender_stats.messages_sent;
  Printf.printf "    Bytes sent (SCTP):     %d\n" total_bytes_sent;
  Printf.printf "    UDP packets sent:      %d\n" sender_udp_stats.packets_sent;
  Printf.printf "    SACKs received:        %d\n" sender_stats.sacks_recv;
  Printf.printf "    Retransmissions:       %d\n" sender_stats.retransmissions;
  Printf.printf "    Fast RTX:              %d\n" sender_stats.fast_retransmissions;
  Printf.printf "\n  RECEIVER:\n";
  Printf.printf "    Messages recv (SCTP):  %d\n" receiver_stats.messages_recv;
  Printf.printf "    Bytes recv (SCTP):     %d\n" receiver_stats.bytes_recv;
  Printf.printf "    UDP packets recv:      %d\n" receiver_udp_stats.packets_recv;
  Printf.printf "    SACKs sent:            %d\n" receiver_stats.sacks_sent;
  let delivery_ratio =
    if total_sent > 0
    then float_of_int receiver_stats.messages_recv /. float_of_int total_sent *. 100.0
    else 0.0
  in
  Printf.printf "\n  ═══ DELIVERY METRICS ═══\n";
  Printf.printf "    Delivery ratio:        %.2f%%\n" delivery_ratio;
  Printf.printf
    "    Lost messages:         %d\n"
    (total_sent - receiver_stats.messages_recv);
  (* HONEST throughput = bytes RECEIVED / time *)
  let honest_throughput =
    float_of_int receiver_stats.bytes_recv /. elapsed /. 1_000_000.0
  in
  let sender_throughput = float_of_int total_bytes_sent /. elapsed /. 1_000_000.0 in
  Printf.printf "\n  ═══ THROUGHPUT (HONEST) ═══\n";
  Printf.printf
    "    Sender throughput:     %.2f MB/s (what we claimed before)\n"
    sender_throughput;
  Printf.printf
    "    ACTUAL throughput:     %.2f MB/s (bytes received/time)\n"
    honest_throughput;
  if delivery_ratio < 99.0
  then (
    Printf.printf "\n  ⚠️  WARNING: Delivery ratio < 99%%!\n";
    Printf.printf "      Previous benchmark was MISLEADING!\n")
  else if delivery_ratio >= 99.9
  then Printf.printf "\n  ✓ Delivery is reliable (%.2f%%)\n" delivery_ratio;
  Eio_sctp_full_transport.close sender;
  Eio_sctp_full_transport.close receiver
;;
