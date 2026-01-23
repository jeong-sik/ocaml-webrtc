(** Warmed SCTP Benchmark

    Previous benchmark showed only 2 MB/s because:
    1. Initial cwnd is only 4,380 bytes (4-5 packets)
    2. Slow Start requires waiting for SACKs to grow cwnd

    This benchmark:
    1. Warms up the connection first (grows cwnd)
    2. Then measures steady-state throughput
*)

open Webrtc

let packet_size = 1024
let warmup_duration_sec = 2
let test_duration_sec = 5

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Warmed SCTP Benchmark (Steady State Throughput)           ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  (* Create transport pair *)
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:33000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:33001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:33001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:33000;
  let data = Bytes.make packet_size 'X' in
  Printf.printf "═══ Before Warmup ═══\n";
  Printf.printf
    "  cwnd:     %d bytes (%d packets)\n"
    (Sctp_full_transport.get_cwnd sender)
    (Sctp_full_transport.get_cwnd sender / packet_size);
  Printf.printf "  ssthresh: %d bytes\n" (Sctp_full_transport.get_ssthresh sender);
  Printf.printf "\n";
  (* Phase 1: Warmup - grow cwnd *)
  Printf.printf "═══ Phase 1: Warming Up (%d seconds) ═══\n" warmup_duration_sec;
  let warmup_start = Unix.gettimeofday () in
  let warmup_end = warmup_start +. float_of_int warmup_duration_sec in
  let warmup_sends = ref 0 in
  while Unix.gettimeofday () < warmup_end do
    (* Try to send *)
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr warmup_sends
      | Error _ -> ());
    (* Process both sides *)
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  Printf.printf "  Warmup sends: %d\n" !warmup_sends;
  Printf.printf
    "  cwnd after warmup:     %d bytes (%d packets)\n"
    (Sctp_full_transport.get_cwnd sender)
    (Sctp_full_transport.get_cwnd sender / packet_size);
  Printf.printf
    "  ssthresh after warmup: %d bytes\n"
    (Sctp_full_transport.get_ssthresh sender);
  Printf.printf "\n";
  (* Phase 2: Actual benchmark at steady state *)
  Printf.printf "═══ Phase 2: Steady State Benchmark (%d seconds) ═══\n" test_duration_sec;
  let test_start = Unix.gettimeofday () in
  let test_end = test_start +. float_of_int test_duration_sec in
  let messages_sent = ref 0 in
  let bytes_sent = ref 0 in
  let blocked_count = ref 0 in
  while Unix.gettimeofday () < test_end do
    (* Try to send *)
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    then (
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok sent ->
        incr messages_sent;
        bytes_sent := !bytes_sent + sent
      | Error _ -> ())
    else incr blocked_count;
    (* Process both sides *)
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  let elapsed = Unix.gettimeofday () -. test_start in
  let throughput_mbps = float_of_int !bytes_sent /. elapsed /. 1_000_000.0 in
  let mps = float_of_int !messages_sent /. elapsed in
  Printf.printf "  Results:\n";
  Printf.printf "    Messages sent: %d\n" !messages_sent;
  Printf.printf "    Bytes sent:    %d\n" !bytes_sent;
  Printf.printf "    Blocked count: %d (times cwnd was full)\n" !blocked_count;
  Printf.printf "    Throughput:    %.2f MB/s\n" throughput_mbps;
  Printf.printf "    Messages/sec:  %.0f\n" mps;
  Printf.printf "  Final State:\n";
  Printf.printf
    "    cwnd:      %d bytes (%d packets)\n"
    (Sctp_full_transport.get_cwnd sender)
    (Sctp_full_transport.get_cwnd sender / packet_size);
  Printf.printf "    ssthresh:  %d bytes\n" (Sctp_full_transport.get_ssthresh sender);
  Printf.printf "    flight:    %d bytes\n" (Sctp_full_transport.get_flight_size sender);
  Printf.printf "    rto:       %.3f s\n" (Sctp_full_transport.get_rto sender);
  Printf.printf "\n";
  let stats = Sctp_full_transport.get_stats sender in
  Printf.printf "  Protocol Stats:\n";
  Printf.printf "    Retransmissions: %d\n" stats.retransmissions;
  Printf.printf "    Fast RTX:        %d\n" stats.fast_retransmissions;
  Printf.printf "    SACKs recv:      %d\n" stats.sacks_recv;
  Printf.printf "\n";
  (* Comparison *)
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║  COMPARISON (at 1KB packets):                                 ║\n";
  Printf.printf "║  - Pion (Go):          177.92 MB/s                            ║\n";
  Printf.printf
    "║  - OCaml SCTP Warmed:  %.2f MB/s                           ║\n"
    throughput_mbps;
  Printf.printf
    "║  - Ratio:              %.1fx                                   ║\n"
    (177.92 /. throughput_mbps);
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n"
;;
