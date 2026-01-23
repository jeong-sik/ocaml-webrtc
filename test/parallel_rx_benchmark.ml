(** Parallel RX Benchmark

    Compares single-domain vs multi-domain SCTP packet processing.
    Uses Domain module directly to demonstrate parallel potential.
*)

open Webrtc

let packet_size = 1024
let num_packets = 500_000

(** Generate test packets *)
let generate_packets n =
  Array.init n (fun i ->
    let data = Bytes.make packet_size 'X' in
    Bytes.set_int32_be data 0 (Int32.of_int i);
    data)
;;

(** Domain-local stats (no Atomic on hot path) *)
type domain_stats =
  { mutable packets : int
  ; mutable bytes : int
  }

(** Benchmark 1: Single-domain baseline *)
let benchmark_single_domain packets =
  Printf.printf "\n=== Single-Domain Benchmark ===\n%!";
  let config = Sctp.default_config in
  let core = Sctp_core.create ~config () in
  let start_time = Unix.gettimeofday () in
  let processed = ref 0 in
  let bytes_processed = ref 0 in
  Array.iter
    (fun packet ->
       let _outputs = Sctp_core.handle core (Sctp_core.PacketReceived packet) in
       incr processed;
       bytes_processed := !bytes_processed + Bytes.length packet)
    packets;
  let elapsed = Unix.gettimeofday () -. start_time in
  let throughput_pps = float_of_int !processed /. elapsed in
  let throughput_mbps = float_of_int !bytes_processed /. elapsed /. 1_000_000.0 in
  Printf.printf "  Packets: %d in %.3fs\n" !processed elapsed;
  Printf.printf "  Throughput: %.0f pkt/s | %.2f MB/s\n%!" throughput_pps throughput_mbps;
  throughput_pps, throughput_mbps
;;

(** Benchmark 2: Multi-domain parallel processing *)
let benchmark_multi_domain packets ~num_domains =
  Printf.printf "\n=== %d-Domain Parallel Benchmark ===\n%!" num_domains;
  (* Split packets among domains *)
  let n = Array.length packets in
  let chunk_size = n / num_domains in
  let start_time = Unix.gettimeofday () in
  (* Spawn worker domains *)
  let domains =
    Array.init num_domains (fun i ->
      let start_idx = i * chunk_size in
      let end_idx = if i = num_domains - 1 then n else (i + 1) * chunk_size in
      Domain.spawn (fun () ->
        (* Each domain has its own SCTP core and mutable stats *)
        let config = Sctp.default_config in
        let core = Sctp_core.create ~config () in
        let stats = { packets = 0; bytes = 0 } in
        (* Process assigned packets - NO Atomics! *)
        for j = start_idx to end_idx - 1 do
          let packet = packets.(j) in
          let _outputs = Sctp_core.handle core (Sctp_core.PacketReceived packet) in
          stats.packets <- stats.packets + 1;
          stats.bytes <- stats.bytes + Bytes.length packet
        done;
        stats))
  in
  (* Join all domains and aggregate stats *)
  let total_packets = ref 0 in
  let total_bytes = ref 0 in
  Array.iter
    (fun d ->
       let stats = Domain.join d in
       total_packets := !total_packets + stats.packets;
       total_bytes := !total_bytes + stats.bytes)
    domains;
  let elapsed = Unix.gettimeofday () -. start_time in
  let throughput_pps = float_of_int !total_packets /. elapsed in
  let throughput_mbps = float_of_int !total_bytes /. elapsed /. 1_000_000.0 in
  Printf.printf "  Packets: %d in %.3fs\n" !total_packets elapsed;
  Printf.printf "  Throughput: %.0f pkt/s | %.2f MB/s\n%!" throughput_pps throughput_mbps;
  throughput_pps, throughput_mbps
;;

(** Main *)
let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Parallel RX Benchmark - OCaml 5.x Multicore               ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  Printf.printf "System: %d cores available\n" (Domain.recommended_domain_count ());
  Printf.printf "Test: %d packets @ %d bytes\n\n" num_packets packet_size;
  (* Generate test packets *)
  Printf.printf "Generating packets...\n%!";
  let packets = generate_packets num_packets in
  Printf.printf "Done.\n";
  (* Run benchmarks *)
  let single_pps, single_mbps = benchmark_single_domain packets in
  let results =
    [ 2, benchmark_multi_domain packets ~num_domains:2
    ; 4, benchmark_multi_domain packets ~num_domains:4
    ; 8, benchmark_multi_domain packets ~num_domains:8
    ]
  in
  (* Summary *)
  Printf.printf "\n═══ SUMMARY ═══\n\n";
  Printf.printf "| Domains | Packets/sec  | MB/s   | Speedup |\n";
  Printf.printf "|---------|--------------|--------|---------|\n";
  Printf.printf "| 1       | %12.0f | %6.2f | 1.00x   |\n" single_pps single_mbps;
  List.iter
    (fun (domains, (pps, mbps)) ->
       let speedup = pps /. single_pps in
       Printf.printf "| %d       | %12.0f | %6.2f | %.2fx   |\n" domains pps mbps speedup)
    results;
  Printf.printf "\n";
  Printf.printf "★ Insight: Domain-local mutable stats = NO memory barriers!\n";
  Printf.printf "  Each domain processes independently, aggregate only at end.\n";
  Printf.printf "\n✓ Benchmark complete\n"
;;
