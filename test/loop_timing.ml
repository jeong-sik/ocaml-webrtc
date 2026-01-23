(** Loop Timing Analysis

    Even with cwnd warmed up, we only get 927 msgs/s.
    Blocked count = 0, so cwnd is NOT the issue.
    Something in the loop is slow. Let's find it!
*)

open Webrtc

let packet_size = 1024
let iterations = 10000

let time_ns () =
  let t = Unix.gettimeofday () in
  Int64.of_float (t *. 1_000_000_000.0)
;;

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Loop Timing Analysis                                      ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  (* Create transport pair *)
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:34000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:34001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:34001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:34000;
  let data = Bytes.make packet_size 'X' in
  (* Time individual operations *)
  Printf.printf "═══ Individual Operation Timings ═══\n";
  (* 1. gettimeofday check *)
  let start = time_ns () in
  for _ = 1 to iterations do
    ignore (Unix.gettimeofday ())
  done;
  let elapsed =
    Int64.to_float (Int64.sub (time_ns ()) start) /. float_of_int iterations
  in
  Printf.printf "  Unix.gettimeofday:           %6.0f ns/op\n" elapsed;
  (* 2. get_flight_size + get_cwnd *)
  let start = time_ns () in
  for _ = 1 to iterations do
    ignore
      (Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender)
  done;
  let elapsed =
    Int64.to_float (Int64.sub (time_ns ()) start) /. float_of_int iterations
  in
  Printf.printf "  cwnd check (flight<cwnd):    %6.0f ns/op\n" elapsed;
  (* 3. send_data (with actual network) *)
  let send_count = ref 0 in
  let start = time_ns () in
  for _ = 1 to min iterations 1000 do
    (* Limit to avoid filling buffers *)
    match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
    | Ok _ -> incr send_count
    | Error _ -> ()
  done;
  let elapsed =
    Int64.to_float (Int64.sub (time_ns ()) start) /. float_of_int !send_count
  in
  Printf.printf "  send_data (actual send):     %6.0f ns/op (n=%d)\n" elapsed !send_count;
  (* 4. tick receiver (processes DATA, sends SACK) *)
  let start = time_ns () in
  for _ = 1 to 100 do
    Sctp_full_transport.tick receiver
  done;
  let elapsed = Int64.to_float (Int64.sub (time_ns ()) start) /. 100.0 in
  Printf.printf "  tick receiver (with data):   %6.0f ns/op\n" elapsed;
  (* 5. tick sender (processes SACK) *)
  let start = time_ns () in
  for _ = 1 to 100 do
    Sctp_full_transport.tick sender
  done;
  let elapsed = Int64.to_float (Int64.sub (time_ns ()) start) /. 100.0 in
  Printf.printf "  tick sender (after SACKs):   %6.0f ns/op\n" elapsed;
  (* 6. Complete loop iteration *)
  Printf.printf "\n═══ Complete Loop Analysis ═══\n";
  let total_time = ref 0.0 in
  let send_time = ref 0.0 in
  let recv_tick_time = ref 0.0 in
  let send_tick_time = ref 0.0 in
  let check_time = ref 0.0 in
  let loop_count = ref 0 in
  (* Warmup first *)
  for _ = 1 to 1000 do
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  let loop_iterations = 5000 in
  let outer_start = Unix.gettimeofday () in
  for _ = 1 to loop_iterations do
    (* Check *)
    let t0 = Unix.gettimeofday () in
    let can_send =
      Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
    in
    let t1 = Unix.gettimeofday () in
    check_time := !check_time +. (t1 -. t0);
    (* Send *)
    if can_send
    then (
      let t2 = Unix.gettimeofday () in
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
      let t3 = Unix.gettimeofday () in
      send_time := !send_time +. (t3 -. t2);
      incr loop_count);
    (* Tick receiver *)
    let t4 = Unix.gettimeofday () in
    Sctp_full_transport.tick receiver;
    let t5 = Unix.gettimeofday () in
    recv_tick_time := !recv_tick_time +. (t5 -. t4);
    (* Tick sender *)
    let t6 = Unix.gettimeofday () in
    Sctp_full_transport.tick sender;
    let t7 = Unix.gettimeofday () in
    send_tick_time := !send_tick_time +. (t7 -. t6)
  done;
  let outer_elapsed = Unix.gettimeofday () -. outer_start in
  total_time := outer_elapsed;
  Printf.printf "  Loop iterations: %d\n" loop_iterations;
  Printf.printf "  Successful sends: %d\n" !loop_count;
  Printf.printf "  Total time: %.3f s\n" !total_time;
  Printf.printf "\n";
  Printf.printf "  Time breakdown:\n";
  Printf.printf
    "    Check (cwnd):       %6.3f ms (%4.1f%%)\n"
    (!check_time *. 1000.0)
    (!check_time /. !total_time *. 100.0);
  Printf.printf
    "    Send:               %6.3f ms (%4.1f%%)\n"
    (!send_time *. 1000.0)
    (!send_time /. !total_time *. 100.0);
  Printf.printf
    "    Tick receiver:      %6.3f ms (%4.1f%%)\n"
    (!recv_tick_time *. 1000.0)
    (!recv_tick_time /. !total_time *. 100.0);
  Printf.printf
    "    Tick sender:        %6.3f ms (%4.1f%%)\n"
    (!send_tick_time *. 1000.0)
    (!send_tick_time /. !total_time *. 100.0);
  let overhead =
    !total_time -. !check_time -. !send_time -. !recv_tick_time -. !send_tick_time
  in
  Printf.printf
    "    Loop overhead:      %6.3f ms (%4.1f%%)\n"
    (overhead *. 1000.0)
    (overhead /. !total_time *. 100.0);
  Printf.printf "\n";
  let msgs_per_sec = float_of_int !loop_count /. !total_time in
  let throughput = msgs_per_sec *. float_of_int packet_size /. 1_000_000.0 in
  Printf.printf "  Effective rate: %.0f msgs/s = %.2f MB/s\n" msgs_per_sec throughput;
  Printf.printf "\n";
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║  BOTTLENECK IDENTIFICATION:                                   ║\n";
  Printf.printf "║  Look for the operation with highest %% of time               ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n"
;;
