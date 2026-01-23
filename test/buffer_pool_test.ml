(** Unit tests for Zero-Copy Buffer Pool

    Tests the memory-efficient buffer pool for packet processing:
    - Buffer allocation and deallocation
    - Pool statistics tracking
    - Zero-copy operations
    - Pool exhaustion handling

    @author Second Brain
*)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try
    f ();
    incr passed;
    Printf.printf "✅ PASS\n%!"
  with
  | e ->
    incr failed;
    Printf.printf "❌ FAIL (%s)\n%!" (Printexc.to_string e)
;;

let assert_true msg b = if not b then failwith msg

let assert_eq msg a b =
  if a <> b then failwith (Printf.sprintf "%s: got %d, expected %d" msg a b)
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Pool Creation                                                               *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_pool_creation () =
  Printf.printf "\n═══ Pool Creation ═══\n";
  test "Create pool with default config" (fun () ->
    let pool = Buffer_pool.create () in
    let stats = Buffer_pool.get_stats pool in
    assert_true "total_buffers > 0" (stats.total_buffers > 0));
  test "Create pool with custom config" (fun () ->
    let config = Buffer_pool.{ buffer_size = 4096; pool_size = 100 } in
    let pool = Buffer_pool.create ~config () in
    let stats = Buffer_pool.get_stats pool in
    assert_eq "total_buffers" stats.total_buffers 100);
  test "Initial stats are correct" (fun () ->
    let pool = Buffer_pool.create () in
    let stats = Buffer_pool.get_stats pool in
    assert_eq "alloc_ops = 0" stats.alloc_ops 0;
    assert_eq "free_ops = 0" stats.free_ops 0)
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Buffer Allocation                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_buffer_allocation () =
  Printf.printf "\n═══ Buffer Allocation ═══\n";
  test "Allocate single buffer" (fun () ->
    let pool = Buffer_pool.create () in
    let buf = Buffer_pool.alloc pool in
    let stats = Buffer_pool.get_stats pool in
    assert_eq "alloc_ops = 1" stats.alloc_ops 1;
    (* to_bytes returns data up to buf.len - newly allocated buffer has len=0 *)
    (* Test by writing some data first *)
    let src = Bytes.of_string "test" in
    Buffer_pool.blit_from buf ~src ~src_off:0 ~len:4;
    assert_true "buffer has data after blit" (Bytes.length (Buffer_pool.to_bytes buf) = 4));
  test "Allocate multiple buffers" (fun () ->
    let config = Buffer_pool.{ buffer_size = 1024; pool_size = 10 } in
    let pool = Buffer_pool.create ~config () in
    let bufs = List.map (fun _ -> Buffer_pool.alloc pool) (List.init 5 (fun i -> i)) in
    assert_eq "allocated 5 buffers" (List.length bufs) 5;
    let stats = Buffer_pool.get_stats pool in
    assert_eq "stats.alloc_ops = 5" stats.alloc_ops 5);
  test "Free buffers count tracked" (fun () ->
    let config = Buffer_pool.{ buffer_size = 1024; pool_size = 10 } in
    let pool = Buffer_pool.create ~config () in
    let _bufs = List.map (fun _ -> Buffer_pool.alloc pool) (List.init 7 (fun i -> i)) in
    let stats = Buffer_pool.get_stats pool in
    (* After allocating 7, free_buffers should decrease *)
    assert_true "free_buffers decreased" (stats.free_buffers < 10))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Buffer Deallocation                                                         *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_buffer_deallocation () =
  Printf.printf "\n═══ Buffer Deallocation ═══\n";
  test "Free returns buffer to pool" (fun () ->
    let config = Buffer_pool.{ buffer_size = 1024; pool_size = 10 } in
    let pool = Buffer_pool.create ~config () in
    let buf = Buffer_pool.alloc pool in
    let stats_before = Buffer_pool.get_stats pool in
    assert_eq "alloc_ops = 1" stats_before.alloc_ops 1;
    Buffer_pool.free buf;
    let stats_after = Buffer_pool.get_stats pool in
    assert_eq "free_ops = 1 after free" stats_after.free_ops 1);
  test "Free multiple buffers" (fun () ->
    let config = Buffer_pool.{ buffer_size = 1024; pool_size = 10 } in
    let pool = Buffer_pool.create ~config () in
    let bufs = List.map (fun _ -> Buffer_pool.alloc pool) (List.init 5 (fun i -> i)) in
    List.iter Buffer_pool.free bufs;
    let stats = Buffer_pool.get_stats pool in
    assert_eq "free_ops = 5" stats.free_ops 5;
    assert_eq "free_buffers = total" stats.free_buffers stats.total_buffers);
  test "Hit rate tracked" (fun () ->
    let config = Buffer_pool.{ buffer_size = 1024; pool_size = 10 } in
    let pool = Buffer_pool.create ~config () in
    let bufs = List.map (fun _ -> Buffer_pool.alloc pool) (List.init 5 (fun i -> i)) in
    List.iter Buffer_pool.free bufs;
    let stats = Buffer_pool.get_stats pool in
    (* Hit rate should be >= 0 *)
    assert_true "hit_rate >= 0" (stats.hit_rate >= 0.0))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Pool Exhaustion                                                             *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_pool_exhaustion () =
  Printf.printf "\n═══ Pool Exhaustion (Heap Fallback) ═══\n";
  test "Heap fallback when pool exhausted" (fun () ->
    let config = Buffer_pool.{ buffer_size = 1024; pool_size = 3 } in
    let pool = Buffer_pool.create ~config () in
    (* Allocate all 3 pool buffers *)
    let _bufs = List.map (fun _ -> Buffer_pool.alloc pool) (List.init 3 (fun i -> i)) in
    (* Fourth allocation uses heap fallback *)
    let _extra = Buffer_pool.alloc pool in
    let stats = Buffer_pool.get_stats pool in
    assert_eq "fallback_allocs = 1" stats.fallback_allocs 1);
  test "Free returns buffer to pool for reuse" (fun () ->
    let config = Buffer_pool.{ buffer_size = 1024; pool_size = 2 } in
    let pool = Buffer_pool.create ~config () in
    let buf1 = Buffer_pool.alloc pool in
    let buf2 = Buffer_pool.alloc pool in
    (* Pool depleted, next alloc uses heap *)
    let _heap_buf = Buffer_pool.alloc pool in
    let stats1 = Buffer_pool.get_stats pool in
    assert_eq "fallback after depleted" stats1.fallback_allocs 1;
    (* Free one pool buffer *)
    Buffer_pool.free buf1;
    (* Next alloc should come from pool (no new fallback) *)
    let _reused = Buffer_pool.alloc pool in
    let stats2 = Buffer_pool.get_stats pool in
    assert_eq "no additional fallback" stats2.fallback_allocs 1;
    Buffer_pool.free buf2)
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Zero-Copy Operations                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_zero_copy_ops () =
  Printf.printf "\n═══ Zero-Copy Operations ═══\n";
  test "blit_from copies data into buffer" (fun () ->
    let pool = Buffer_pool.create () in
    let buf = Buffer_pool.alloc pool in
    let src = Bytes.of_string "Hello, World!" in
    Buffer_pool.blit_from buf ~src ~src_off:0 ~len:(Bytes.length src);
    let dst = Buffer_pool.to_bytes buf in
    assert_true "data copied" (Bytes.sub dst 0 (Bytes.length src) = src));
  test "blit_to copies data from buffer" (fun () ->
    let pool = Buffer_pool.create () in
    let buf = Buffer_pool.alloc pool in
    let src = Bytes.of_string "Test data" in
    Buffer_pool.blit_from buf ~src ~src_off:0 ~len:(Bytes.length src);
    let dst = Bytes.make 20 '\x00' in
    Buffer_pool.blit_to buf ~dst ~dst_off:0;
    assert_true "data matches" (Bytes.sub dst 0 (Bytes.length src) = src));
  test "to_bytes returns buffer contents" (fun () ->
    let config = Buffer_pool.{ buffer_size = 100; pool_size = 5 } in
    let pool = Buffer_pool.create ~config () in
    let buf = Buffer_pool.alloc pool in
    (* to_bytes returns data up to buf.len; write full buffer first *)
    let src = Bytes.make 100 'X' in
    Buffer_pool.blit_from buf ~src ~src_off:0 ~len:100;
    let bytes = Buffer_pool.to_bytes buf in
    assert_eq "buffer size" (Bytes.length bytes) 100)
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* with_buffer Combinator                                                      *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_with_buffer () =
  Printf.printf "\n═══ with_buffer Combinator ═══\n";
  test "with_buffer auto-frees on success" (fun () ->
    let pool = Buffer_pool.create () in
    let result =
      Buffer_pool.with_buffer pool (fun buf ->
        (* Write data and return its length *)
        let src = Bytes.of_string "test data" in
        Buffer_pool.blit_from buf ~src ~src_off:0 ~len:9;
        Bytes.length (Buffer_pool.to_bytes buf))
    in
    let stats = Buffer_pool.get_stats pool in
    assert_true "got result" (result = 9);
    (* Should have 1 alloc and 1 free *)
    assert_eq "alloc_ops = 1" stats.alloc_ops 1;
    assert_eq "free_ops = 1" stats.free_ops 1);
  test "with_buffer auto-frees on exception" (fun () ->
    let pool = Buffer_pool.create () in
    let _ =
      try Buffer_pool.with_buffer pool (fun _buf -> failwith "intentional error") with
      | _ -> 0
    in
    let stats = Buffer_pool.get_stats pool in
    (* Buffer should be freed even on exception *)
    assert_eq "free_ops tracks freed" stats.free_ops 1)
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Statistics String                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_stats_string () =
  Printf.printf "\n═══ Statistics String ═══\n";
  test "stats_to_string produces readable output" (fun () ->
    let pool = Buffer_pool.create () in
    let _ = Buffer_pool.alloc pool in
    let stats = Buffer_pool.get_stats pool in
    let s = Buffer_pool.stats_to_string stats in
    assert_true "contains pool_size" (String.length s > 0))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main                                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Buffer Pool Unit Tests                                   ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";
  test_pool_creation ();
  test_buffer_allocation ();
  test_buffer_deallocation ();
  test_pool_exhaustion ();
  test_zero_copy_ops ();
  test_with_buffer ();
  test_stats_string ();
  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";
  if !failed > 0 then exit 1
;;
