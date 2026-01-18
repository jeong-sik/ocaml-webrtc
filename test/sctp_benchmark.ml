(* SCTP Performance Benchmark

   Measures throughput improvement from optimizations:
   - IW10 (Initial Window = 10 * MTU)
   - Larger receive window (256KB)
   - Batch chunk encoding
   - Efficient fragmentation
*)

open Webrtc

(* Timing utilities *)
let time_it name iterations f =
  let start = Unix.gettimeofday () in
  for _ = 1 to iterations do
    ignore (f ())
  done;
  let elapsed = Unix.gettimeofday () -. start in
  let per_op = elapsed /. float_of_int iterations in
  Printf.printf "  %-40s %8.3f ms/op (%d iterations)\n" name (per_op *. 1000.0) iterations

let time_throughput name data_size iterations f =
  let start = Unix.gettimeofday () in
  for _ = 1 to iterations do
    ignore (f ())
  done;
  let elapsed = Unix.gettimeofday () -. start in
  let total_bytes = data_size * iterations in
  let throughput_mbps = (float_of_int total_bytes /. elapsed) /. 1_000_000.0 in
  Printf.printf "  %-40s %8.2f MB/s (%.3fs for %d MB)\n"
    name throughput_mbps elapsed (total_bytes / 1_000_000)

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 1. DATA Chunk Encoding Benchmark *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_chunk_encoding () =
  Printf.printf "\n═══ 1. DATA Chunk Encoding ═══\n";

  (* Small chunk (typical WebRTC data channel message) *)
  let small_data = Bytes.make 256 'A' in
  let chunk_256 = Sctp.{
    tsn = 1000l;
    stream_id = 0;
    stream_seq = 0;
    ppid = 0x32l;
    flags = { begin_fragment = true; end_fragment = true; unordered = false; immediate = false };
    user_data = small_data;
  } in
  time_it "Encode 256B chunk" 100_000 (fun () -> Sctp.encode_data_chunk chunk_256);

  (* Medium chunk (1KB - common for structured data) *)
  let medium_data = Bytes.make 1024 'B' in
  let chunk_1k = { chunk_256 with user_data = medium_data } in
  time_it "Encode 1KB chunk" 50_000 (fun () -> Sctp.encode_data_chunk chunk_1k);

  (* Large chunk (MTU-sized) *)
  let mtu_data = Bytes.make 1200 'C' in
  let chunk_mtu = { chunk_256 with user_data = mtu_data } in
  time_it "Encode 1200B (MTU) chunk" 50_000 (fun () -> Sctp.encode_data_chunk chunk_mtu)

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 2. Batch Encoding Benchmark *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_batch_encoding () =
  Printf.printf "\n═══ 2. Batch Encoding (vs Individual) ═══\n";

  let base_chunk = Sctp.{
    tsn = 1000l;
    stream_id = 0;
    stream_seq = 0;
    ppid = 0x32l;
    flags = { begin_fragment = true; end_fragment = true; unordered = false; immediate = false };
    user_data = Bytes.make 200 'X';
  } in

  (* Create 5 chunks (typical batch) *)
  let chunks = List.init 5 (fun i ->
    { base_chunk with tsn = Int32.of_int (1000 + i) }
  ) in

  (* Individual encoding *)
  time_it "5 chunks individually" 20_000 (fun () ->
    List.iter (fun c -> ignore (Sctp.encode_data_chunk c)) chunks
  );

  (* Batch encoding *)
  time_it "5 chunks batched" 20_000 (fun () ->
    ignore (Sctp.encode_data_chunks_batch chunks ~mtu:1280)
  );

  (* Larger batch (10 chunks) *)
  let chunks_10 = List.init 10 (fun i ->
    { base_chunk with tsn = Int32.of_int (1000 + i) }
  ) in

  time_it "10 chunks individually" 10_000 (fun () ->
    List.iter (fun c -> ignore (Sctp.encode_data_chunk c)) chunks_10
  );

  time_it "10 chunks batched" 10_000 (fun () ->
    ignore (Sctp.encode_data_chunks_batch chunks_10 ~mtu:1280)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 3. Fragmentation Benchmark *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_fragmentation () =
  Printf.printf "\n═══ 3. Data Fragmentation ═══\n";

  (* 10KB message *)
  let data_10k = Bytes.make 10_000 'D' in
  time_it "Fragment 10KB → ~9 chunks" 10_000 (fun () ->
    ignore (Sctp.fragment_data ~data:data_10k ~stream_id:0 ~stream_seq:0
      ~ppid:0x32l ~start_tsn:1000l ~mtu:1280)
  );

  (* 64KB message (max WebRTC message size) *)
  let data_64k = Bytes.make 65_000 'E' in
  time_it "Fragment 64KB → ~52 chunks" 2_000 (fun () ->
    ignore (Sctp.fragment_data ~data:data_64k ~stream_id:0 ~stream_seq:0
      ~ppid:0x32l ~start_tsn:1000l ~mtu:1280)
  );

  (* 256KB message *)
  let data_256k = Bytes.make 262_144 'F' in
  time_it "Fragment 256KB → ~209 chunks" 500 (fun () ->
    ignore (Sctp.fragment_data ~data:data_256k ~stream_id:0 ~stream_seq:0
      ~ppid:0x32l ~start_tsn:1000l ~mtu:1280)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 4. Throughput Estimation *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_throughput () =
  Printf.printf "\n═══ 4. Throughput Estimation ═══\n";

  (* Simulate processing 1MB of data *)
  let data_1mb = Bytes.make 1_000_000 'G' in

  time_throughput "Fragment + Encode 1MB" 1_000_000 10 (fun () ->
    let chunks = Sctp.fragment_data ~data:data_1mb ~stream_id:0 ~stream_seq:0
      ~ppid:0x32l ~start_tsn:1000l ~mtu:1280 in
    List.iter (fun c -> ignore (Sctp.encode_data_chunk c)) chunks
  );

  time_throughput "Fragment + Batch Encode 1MB" 1_000_000 10 (fun () ->
    let chunks = Sctp.fragment_data ~data:data_1mb ~stream_id:0 ~stream_seq:0
      ~ppid:0x32l ~start_tsn:1000l ~mtu:1280 in
    ignore (Sctp.encode_data_chunks_batch chunks ~mtu:1280)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 5. Configuration Comparison *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_config () =
  Printf.printf "\n═══ 5. Configuration Parameters ═══\n";

  let config = Sctp.default_config in
  Printf.printf "  %-30s %d bytes\n" "MTU:" config.mtu;
  Printf.printf "  %-30s %d ms\n" "RTO Initial:" config.rto_initial_ms;
  Printf.printf "  %-30s %d ms\n" "RTO Min:" config.rto_min_ms;
  Printf.printf "  %-30s %d bytes (%.0f KB)\n" "Receive Window:" config.a_rwnd
    (float_of_int config.a_rwnd /. 1024.0);
  Printf.printf "  %-30s %d * MTU = %d bytes\n" "Initial cwnd (IW10):" 10 (10 * config.mtu);

  Printf.printf "\n  Performance implications:\n";
  Printf.printf "  - IW10 allows sending %d KB immediately\n" (10 * config.mtu / 1024);
  Printf.printf "  - 256KB rwnd supports ~%d in-flight 1KB messages\n" (config.a_rwnd / 1024);
  Printf.printf "  - 200ms RTO min enables faster retransmit on good networks\n"

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     SCTP Performance Benchmark (OCaml Pure Implementation)    ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";

  bench_chunk_encoding ();
  bench_batch_encoding ();
  bench_fragmentation ();
  bench_throughput ();
  bench_config ();

  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "Benchmark complete.\n";
  Printf.printf "═══════════════════════════════════════════════════════════════\n"
