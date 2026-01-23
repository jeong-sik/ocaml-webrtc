(* Eio SCTP Benchmark - Concurrent version using OCaml 5 Effect Handlers

   This benchmark uses Eio fibers for concurrent send/recv operations,
   similar to how Pion uses goroutines.

   Expected improvement: 10-50x over single-threaded version
   Target: Closer to Pion's ~150 MB/s
*)

open Webrtc

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Test Configuration *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let base_port = 22000
let packet_size = 1024
let test_duration_sec = 5

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Eio-based Transport Wrapper *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

type eio_pair =
  { sender : Sctp_full_transport.t
  ; receiver : Sctp_full_transport.t
  }

let create_pair ~id =
  let sender_port = base_port + (id * 2) in
  let recv_port = base_port + (id * 2) + 1 in
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:sender_port () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:recv_port () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:recv_port;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:sender_port;
  { sender; receiver }
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Concurrent Benchmark with Eio Fibers *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_eio_concurrent () =
  Eio_main.run
  @@ fun env ->
  let clock = Eio.Stdenv.clock env in
  Printf.printf "\n═══ Eio Concurrent SCTP Benchmark ═══\n";
  Printf.printf "  Packet size: %d bytes\n" packet_size;
  Printf.printf "  Duration: %d seconds\n" test_duration_sec;
  Printf.printf "  Mode: Concurrent fibers (like goroutines)\n";
  let pair = create_pair ~id:0 in
  let data = Bytes.make packet_size 'X' in
  let messages_sent = Atomic.make 0 in
  let bytes_sent = Atomic.make 0 in
  let running = Atomic.make true in
  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in
  (* Run fibers concurrently *)
  Eio.Fiber.all
    [ (* Fiber 1: Sender - sends as fast as cwnd allows *)
      (fun () ->
        while Atomic.get running do
          if
            Sctp_full_transport.get_flight_size pair.sender
            < Sctp_full_transport.get_cwnd pair.sender
          then (
            match Sctp_full_transport.send_data pair.sender ~stream_id:0 ~data with
            | Ok sent ->
              Atomic.incr messages_sent;
              ignore (Atomic.fetch_and_add bytes_sent sent)
            | Error _ -> ());
          (* Yield to other fibers *)
          Eio.Fiber.yield ()
        done)
    ; (* Fiber 2: Receiver tick - processes incoming DATA, sends SACKs *)
      (fun () ->
        while Atomic.get running do
          Sctp_full_transport.tick pair.receiver;
          Eio.Fiber.yield ()
        done)
    ; (* Fiber 3: Sender tick - processes incoming SACKs, updates cwnd *)
      (fun () ->
        while Atomic.get running do
          Sctp_full_transport.tick pair.sender;
          Eio.Fiber.yield ()
        done)
    ; (* Fiber 4: Timer - stops after duration *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          Eio.Time.sleep clock 0.001 (* 1ms granularity *)
        done;
        Atomic.set running false)
    ];
  let elapsed = Unix.gettimeofday () -. start_time in
  let total_bytes = Atomic.get bytes_sent in
  let total_msgs = Atomic.get messages_sent in
  let throughput_mbps = float_of_int total_bytes /. elapsed /. 1_000_000.0 in
  let mps = float_of_int total_msgs /. elapsed in
  Printf.printf "  Results:\n";
  Printf.printf "    Messages sent: %d\n" total_msgs;
  Printf.printf "    Bytes sent:    %d\n" total_bytes;
  Printf.printf "    Throughput:    %.2f MB/s\n" throughput_mbps;
  Printf.printf "    Messages/sec:  %.0f\n" mps;
  Printf.printf "  Congestion Control State:\n";
  Printf.printf "    cwnd:      %d bytes\n" (Sctp_full_transport.get_cwnd pair.sender);
  Printf.printf "    ssthresh:  %d bytes\n" (Sctp_full_transport.get_ssthresh pair.sender);
  let stats = Sctp_full_transport.get_stats pair.sender in
  Printf.printf "  Protocol Stats:\n";
  Printf.printf "    SACKs recv:   %d\n" stats.sacks_recv;
  Printf.printf "    Retransmits:  %d\n" stats.retransmissions;
  Sctp_full_transport.close pair.sender;
  Sctp_full_transport.close pair.receiver;
  throughput_mbps
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Multi-Domain Parallel Benchmark (True Parallelism) *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_multicore ~num_domains =
  Eio_main.run
  @@ fun env ->
  let dm = Eio.Stdenv.domain_mgr env in
  let num_domains = min num_domains (Domain.recommended_domain_count ()) in
  Printf.printf "\n═══ Multi-Domain Parallel SCTP (%d cores) ═══\n" num_domains;
  Printf.printf "  Packet size: %d bytes\n" packet_size;
  Printf.printf "  Duration: %d seconds\n" test_duration_sec;
  Printf.printf "  True parallelism across CPU cores\n";
  let total_bytes = Atomic.make 0 in
  let total_msgs = Atomic.make 0 in
  let running = Atomic.make true in
  let start_time = Unix.gettimeofday () in
  (* Run timer in main fiber *)
  let stop_after_duration () =
    Unix.sleepf (float_of_int test_duration_sec);
    Atomic.set running false
  in
  (* Worker function for each domain *)
  let worker domain_id () =
    let pair = create_pair ~id:(100 + domain_id) in
    let data = Bytes.make packet_size 'X' in
    let local_bytes = ref 0 in
    let local_msgs = ref 0 in
    while Atomic.get running do
      if
        Sctp_full_transport.get_flight_size pair.sender
        < Sctp_full_transport.get_cwnd pair.sender
      then (
        match Sctp_full_transport.send_data pair.sender ~stream_id:0 ~data with
        | Ok sent ->
          incr local_msgs;
          local_bytes := !local_bytes + sent
        | Error _ -> ());
      Sctp_full_transport.tick pair.receiver;
      Sctp_full_transport.tick pair.sender
    done;
    ignore (Atomic.fetch_and_add total_bytes !local_bytes);
    ignore (Atomic.fetch_and_add total_msgs !local_msgs);
    Sctp_full_transport.close pair.sender;
    Sctp_full_transport.close pair.receiver
  in
  (* Start timer thread *)
  let timer_domain = Domain.spawn stop_after_duration in
  (* Run workers in parallel domains *)
  Eio.Fiber.all
    (List.init num_domains (fun i -> fun () -> Eio.Domain_manager.run dm (worker i)));
  (* Wait for timer *)
  Domain.join timer_domain;
  let elapsed = Unix.gettimeofday () -. start_time in
  let bytes = Atomic.get total_bytes in
  let msgs = Atomic.get total_msgs in
  let throughput_mbps = float_of_int bytes /. elapsed /. 1_000_000.0 in
  let mps = float_of_int msgs /. elapsed in
  Printf.printf "  Results:\n";
  Printf.printf "    Messages sent: %d\n" msgs;
  Printf.printf "    Bytes sent:    %d\n" bytes;
  Printf.printf "    Throughput:    %.2f MB/s\n" throughput_mbps;
  Printf.printf "    Messages/sec:  %.0f\n" mps;
  Printf.printf
    "    Per-core avg:  %.2f MB/s\n"
    (throughput_mbps /. float_of_int num_domains);
  throughput_mbps
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Comparison with Single-threaded *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_single_thread () =
  Printf.printf "\n═══ Single-threaded SCTP (baseline) ═══\n";
  Printf.printf "  Packet size: %d bytes\n" packet_size;
  Printf.printf "  Duration: %d seconds\n" test_duration_sec;
  let pair = create_pair ~id:1 in
  let data = Bytes.make packet_size 'X' in
  let messages_sent = ref 0 in
  let bytes_sent = ref 0 in
  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in
  while Unix.gettimeofday () < end_time do
    if
      Sctp_full_transport.get_flight_size pair.sender
      < Sctp_full_transport.get_cwnd pair.sender
    then (
      match Sctp_full_transport.send_data pair.sender ~stream_id:0 ~data with
      | Ok sent ->
        incr messages_sent;
        bytes_sent := !bytes_sent + sent
      | Error _ -> ());
    Sctp_full_transport.tick pair.receiver;
    Sctp_full_transport.tick pair.sender
  done;
  let elapsed = Unix.gettimeofday () -. start_time in
  let throughput_mbps = float_of_int !bytes_sent /. elapsed /. 1_000_000.0 in
  Printf.printf "  Results:\n";
  Printf.printf "    Messages sent: %d\n" !messages_sent;
  Printf.printf "    Throughput:    %.2f MB/s\n" throughput_mbps;
  Sctp_full_transport.close pair.sender;
  Sctp_full_transport.close pair.receiver;
  throughput_mbps
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Eio SCTP Benchmark - OCaml 5 Effect Handlers              ║\n";
  Printf.printf "║     Fibers vs Domains vs Pion comparison                      ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";
  let recommended_cores = Domain.recommended_domain_count () in
  Printf.printf "\nSystem: %d available CPU cores\n" recommended_cores;
  let single = bench_single_thread () in
  let concurrent = bench_eio_concurrent () in
  let multicore = bench_multicore ~num_domains:recommended_cores in
  Printf.printf "\n";
  Printf.printf
    "╔════════════════════════════════════════════════════════════════════════╗\n";
  Printf.printf
    "║                    CONCURRENCY COMPARISON                              ║\n";
  Printf.printf
    "╠════════════════════════════════════════════════════════════════════════╣\n";
  Printf.printf
    "║  Mode                 │ Throughput │ Speedup │ Notes                   ║\n";
  Printf.printf
    "╠═══════════════════════╪════════════╪═════════╪═════════════════════════╣\n";
  Printf.printf
    "║  Single-threaded      │ %6.1f MB/s │   1.0x  │ Baseline                ║\n"
    single;
  Printf.printf
    "║  Eio Fibers (1 core)  │ %6.1f MB/s │  %4.1fx  │ Cooperative scheduling  ║\n"
    concurrent
    (concurrent /. single);
  Printf.printf
    "║  Eio Domains (%d cores)│ %6.1f MB/s │  %4.1fx  │ True parallelism        ║\n"
    recommended_cores
    multicore
    (multicore /. single);
  Printf.printf
    "║  Pion (Go goroutines) │ ~150.0 MB/s │  %4.0fx  │ M:N threading           ║\n"
    (150.0 /. single);
  Printf.printf
    "╚═══════════════════════╧════════════╧═════════╧═════════════════════════╝\n";
  Printf.printf "\n";
  Printf.printf "Analysis:\n";
  Printf.printf "  • Eio Fibers: No speedup (cooperative scheduling, single core)\n";
  Printf.printf
    "  • Eio Domains: %.1fx speedup (true parallelism across %d cores)\n"
    (multicore /. single)
    recommended_cores;
  Printf.printf
    "  • Pion gap: %.1fx difference (Go runtime + optimized data structures)\n"
    (150.0 /. multicore);
  Printf.printf "\n";
  Printf.printf "Remaining optimization opportunities:\n";
  Printf.printf "  1. Replace Hashtbl with array-based ring buffers\n";
  Printf.printf "  2. Batch SACK processing (less frequent, larger SACKs)\n";
  Printf.printf "  3. Inline TSN comparison functions\n";
  Printf.printf "  4. Use Cstruct pools to avoid allocations\n"
;;
