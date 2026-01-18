(** Ring Buffer vs Hashtbl Microbenchmark

    Compares the performance of:
    1. Hashtbl-based retransmission queue (current implementation)
    2. Ring buffer-based queue (optimized)

    This isolates the data structure overhead from SCTP protocol logic.
*)

open Webrtc

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Configuration *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let iterations = 1_000_000
let buffer_size = 4096  (* Ring buffer capacity *)

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Hashtbl Benchmark *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

type htbl_entry = {
  chunk: Sctp.data_chunk;
  mutable sent_at: float;
  mutable retransmit_count: int;
} [@@warning "-69"]

let bench_hashtbl () =
  Printf.printf "\n═══ Hashtbl-based Queue ═══\n";

  let tbl : (int32, htbl_entry) Hashtbl.t = Hashtbl.create buffer_size in
  let data = Bytes.make 1024 'X' in

  (* Benchmark enqueue *)
  let start = Unix.gettimeofday () in
  for i = 0 to iterations - 1 do
    let tsn = Int32.of_int i in
    let entry = {
      chunk = {
        Sctp.flags = { end_fragment = true; begin_fragment = true; unordered = false; immediate = false };
        tsn;
        stream_id = 0;
        stream_seq = 0;
        ppid = 0l;
        user_data = data;  (* Share reference, no copy *)
      };
      sent_at = 0.0;
      retransmit_count = 0;
    } in
    Hashtbl.replace tbl tsn entry
  done;
  let enqueue_time = Unix.gettimeofday () -. start in

  (* Benchmark lookup + ack (remove) *)
  let start = Unix.gettimeofday () in
  for i = 0 to iterations - 1 do
    let tsn = Int32.of_int i in
    ignore (Hashtbl.find_opt tbl tsn);
    Hashtbl.remove tbl tsn
  done;
  let dequeue_time = Unix.gettimeofday () -. start in

  let total_time = enqueue_time +. dequeue_time in
  let ops_per_sec = float_of_int (iterations * 2) /. total_time in

  Printf.printf "  Iterations:  %d\n" iterations;
  Printf.printf "  Enqueue:     %.3f s (%.0f ops/s)\n"
    enqueue_time (float_of_int iterations /. enqueue_time);
  Printf.printf "  Dequeue:     %.3f s (%.0f ops/s)\n"
    dequeue_time (float_of_int iterations /. dequeue_time);
  Printf.printf "  Total:       %.3f s (%.0f ops/s)\n" total_time ops_per_sec;

  ops_per_sec

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Ring Buffer Benchmark *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_ring_buffer () =
  Printf.printf "\n═══ Ring Buffer Queue ═══\n";

  let rb = Sctp_ring_buffer.create ~capacity:buffer_size ~initial_tsn:0l () in
  let data = Bytes.make 1024 'X' in

  (* Benchmark enqueue *)
  let start = Unix.gettimeofday () in
  let enqueued = ref 0 in
  for _ = 0 to iterations - 1 do
    let chunk = {
      Sctp.flags = { end_fragment = true; begin_fragment = true; unordered = false; immediate = false };
      tsn = 0l;  (* Will be assigned by ring buffer *)
      stream_id = 0;
      stream_seq = 0;
      ppid = 0l;
      user_data = data;
    } in
    match Sctp_ring_buffer.enqueue rb chunk with
    | Some _ ->
      incr enqueued;
      (* Simulate window management: ack every 100 packets *)
      if !enqueued mod 100 = 0 then begin
        (* Ack the oldest packets *)
        for j = 0 to 99 do
          let tsn = Int32.of_int (!enqueued - 100 + j) in
          ignore (Sctp_ring_buffer.ack rb tsn)
        done;
        ignore (Sctp_ring_buffer.advance_head rb)
      end
    | None ->
      (* Buffer full - ack everything *)
      for j = 0 to buffer_size - 1 do
        let tsn = Int32.of_int (!enqueued - buffer_size + j) in
        ignore (Sctp_ring_buffer.ack rb tsn)
      done;
      ignore (Sctp_ring_buffer.advance_head rb)
  done;
  let enqueue_time = Unix.gettimeofday () -. start in

  (* For fair comparison, do explicit dequeue timing *)
  let rb2 = Sctp_ring_buffer.create ~capacity:buffer_size ~initial_tsn:0l () in
  for i = 0 to buffer_size - 1 do
    let chunk = {
      Sctp.flags = { end_fragment = true; begin_fragment = true; unordered = false; immediate = false };
      tsn = Int32.of_int i;
      stream_id = 0;
      stream_seq = 0;
      ppid = 0l;
      user_data = data;
    } in
    ignore (Sctp_ring_buffer.enqueue rb2 chunk)
  done;

  let start = Unix.gettimeofday () in
  for _ = 0 to iterations - 1 do
    let tsn = Int32.of_int (Random.int buffer_size) in
    ignore (Sctp_ring_buffer.get rb2 tsn);
    ignore (Sctp_ring_buffer.ack rb2 tsn)
  done;
  let dequeue_time = Unix.gettimeofday () -. start in

  let total_time = enqueue_time +. dequeue_time in
  let ops_per_sec = float_of_int (iterations * 2) /. total_time in

  Printf.printf "  Iterations:  %d\n" iterations;
  Printf.printf "  Enqueue:     %.3f s (%.0f ops/s)\n"
    enqueue_time (float_of_int iterations /. enqueue_time);
  Printf.printf "  Dequeue:     %.3f s (%.0f ops/s)\n"
    dequeue_time (float_of_int iterations /. dequeue_time);
  Printf.printf "  Total:       %.3f s (%.0f ops/s)\n" total_time ops_per_sec;

  ops_per_sec

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Buffer Pool Benchmark *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_buffer_pool () =
  Printf.printf "\n═══ Buffer Pool vs Bytes.create ═══\n";

  (* Benchmark Bytes.create (GC pressure) *)
  let start = Unix.gettimeofday () in
  for _ = 0 to iterations - 1 do
    let buf = Bytes.create 1024 in
    ignore (Bytes.length buf)
  done;
  let heap_time = Unix.gettimeofday () -. start in

  (* Benchmark Buffer Pool *)
  let pool = Buffer_pool.create
    ~config:{ Buffer_pool.buffer_size = 1024; pool_size = 1024 }
    ()
  in
  let start = Unix.gettimeofday () in
  for _ = 0 to iterations - 1 do
    let buf = Buffer_pool.alloc pool in
    ignore (Buffer_pool.get_len buf);
    Buffer_pool.free buf
  done;
  let pool_time = Unix.gettimeofday () -. start in

  let stats = Buffer_pool.get_stats pool in

  Printf.printf "  Iterations:    %d\n" iterations;
  Printf.printf "  Bytes.create:  %.3f s (%.0f ops/s)\n"
    heap_time (float_of_int iterations /. heap_time);
  Printf.printf "  Buffer Pool:   %.3f s (%.0f ops/s)\n"
    pool_time (float_of_int iterations /. pool_time);
  Printf.printf "  Speedup:       %.1fx\n" (heap_time /. pool_time);
  Printf.printf "  Pool stats:    %s\n" (Buffer_pool.stats_to_string stats);

  heap_time /. pool_time

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Data Structure Microbenchmark                             ║\n";
  Printf.printf "║     Ring Buffer vs Hashtbl | Buffer Pool vs Bytes.create     ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";

  let htbl_ops = bench_hashtbl () in
  let ring_ops = bench_ring_buffer () in
  let pool_speedup = bench_buffer_pool () in

  Printf.printf "\n";
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║                    OPTIMIZATION SUMMARY                       ║\n";
  Printf.printf "╠═══════════════════════════════════════════════════════════════╣\n";
  Printf.printf "║  Data Structure   │ Ops/sec     │ Improvement                 ║\n";
  Printf.printf "╠═══════════════════╪═════════════╪═════════════════════════════╣\n";
  Printf.printf "║  Hashtbl          │ %9.0f   │ baseline                    ║\n" htbl_ops;
  Printf.printf "║  Ring Buffer      │ %9.0f   │ %.1fx                        ║\n"
    ring_ops (ring_ops /. htbl_ops);
  Printf.printf "║  Buffer Pool      │      -      │ %.1fx vs heap alloc         ║\n"
    pool_speedup;
  Printf.printf "╚═══════════════════╧═════════════╧═════════════════════════════╝\n";
  Printf.printf "\n";
  Printf.printf "Key findings:\n";
  Printf.printf "  • Ring buffer: %.1fx faster than Hashtbl for SCTP queue ops\n"
    (ring_ops /. htbl_ops);
  Printf.printf "  • Buffer pool: %.1fx faster than heap allocation\n" pool_speedup;
  Printf.printf "  • Combined potential improvement: ~%.0fx\n"
    (ring_ops /. htbl_ops *. pool_speedup)
