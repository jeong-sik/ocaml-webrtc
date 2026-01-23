(** Eio Concurrent SCTP Benchmark - True Parallel Fibers

    Tests the performance of concurrent send/recv fibers
    using Eio effect handlers (like Pion's goroutines).

    Target: Match or exceed Pion's ~150 MB/s throughput.
*)

open Webrtc

let base_port = 23000
let packet_size = 1024
let test_duration_sec = 5

(** Create a connected pair for testing *)
let create_pair ~id =
  let sender_port = base_port + (id * 2) in
  let recv_port = base_port + (id * 2) + 1 in
  let sender = Eio_sctp_full_transport.create ~host:"127.0.0.1" ~port:sender_port () in
  let receiver = Eio_sctp_full_transport.create ~host:"127.0.0.1" ~port:recv_port () in
  Eio_sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:recv_port;
  Eio_sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:sender_port;
  sender, receiver
;;

(** Benchmark with concurrent fibers *)
let bench_concurrent () =
  Eio_main.run
  @@ fun env ->
  let clock = Eio.Stdenv.clock env in
  Printf.printf "\n╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Eio Concurrent SCTP Benchmark (Fiber-based)              ║\n";
  Printf.printf "║     Target: Match Pion's ~150 MB/s                           ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  Printf.printf "═══ Single Connection (Concurrent Fibers) ═══\n";
  Printf.printf "  Packet size: %d bytes\n" packet_size;
  Printf.printf "  Duration: %d seconds\n" test_duration_sec;
  Printf.printf "  Mode: 3 concurrent fibers (sender + receiver + timer)\n\n";
  let sender, receiver = create_pair ~id:0 in
  let data = Bytes.make packet_size 'X' in
  let messages_sent = Atomic.make 0 in
  let bytes_sent = Atomic.make 0 in
  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in
  (* Run concurrent fibers *)
  Eio.Fiber.all
    [ (* SENDER Fiber - sends as fast as cwnd allows *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          let flight = Eio_sctp_full_transport.get_flight_size sender in
          let cwnd = Eio_sctp_full_transport.get_cwnd sender in
          if flight < cwnd
          then (
            match Eio_sctp_full_transport.try_send_data sender ~stream_id:0 ~data with
            | Ok sent ->
              Atomic.incr messages_sent;
              ignore (Atomic.fetch_and_add bytes_sent sent)
            | Error _ -> Eio.Fiber.yield ())
          else Eio.Fiber.yield ()
        done;
        Eio_sctp_full_transport.stop sender)
    ; (* SENDER TICK Fiber - process sender's protocol *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          Eio_sctp_full_transport.tick sender;
          Eio.Fiber.yield ()
        done)
    ; (* RECEIVER Fiber - process incoming and send SACKs *)
      (fun () ->
        while Unix.gettimeofday () < end_time do
          Eio_sctp_full_transport.tick receiver;
          Eio.Fiber.yield ()
        done;
        Eio_sctp_full_transport.stop receiver)
    ; (* STATS Fiber - periodic progress report *)
      (fun () ->
        let last_msgs = ref 0 in
        while Unix.gettimeofday () < end_time do
          Eio.Time.sleep clock 1.0;
          let msgs = Atomic.get messages_sent in
          let delta = msgs - !last_msgs in
          last_msgs := msgs;
          let bytes = Atomic.get bytes_sent in
          let elapsed = Unix.gettimeofday () -. start_time in
          let throughput = float_of_int bytes /. elapsed /. 1_000_000.0 in
          Printf.printf
            "  [%.1fs] msgs=%d (+%d/s) throughput=%.1f MB/s cwnd=%d\n%!"
            elapsed
            msgs
            delta
            throughput
            (Eio_sctp_full_transport.get_cwnd sender)
        done)
    ];
  (* Final stats *)
  let total_msgs = Atomic.get messages_sent in
  let total_bytes = Atomic.get bytes_sent in
  let elapsed = Unix.gettimeofday () -. start_time in
  let throughput = float_of_int total_bytes /. elapsed /. 1_000_000.0 in
  Printf.printf "\n  Results:\n";
  Printf.printf "    Messages sent: %d\n" total_msgs;
  Printf.printf "    Bytes sent:    %d\n" total_bytes;
  Printf.printf "    Throughput:    %.2f MB/s\n" throughput;
  Printf.printf
    "    Messages/sec:  %d\n"
    (int_of_float (float_of_int total_msgs /. elapsed));
  let sender_stats = Eio_sctp_full_transport.get_stats sender in
  Printf.printf "  Protocol Stats:\n";
  Printf.printf "    SACKs recv:   %d\n" sender_stats.sacks_recv;
  Printf.printf "    Retransmits:  %d\n" sender_stats.retransmissions;
  Printf.printf "    Fast RTX:     %d\n" sender_stats.fast_retransmissions;
  Printf.printf "  Congestion Control Final:\n";
  Printf.printf "    cwnd:      %d bytes\n" (Eio_sctp_full_transport.get_cwnd sender);
  Printf.printf "    ssthresh:  %d bytes\n" (Eio_sctp_full_transport.get_ssthresh sender);
  Printf.printf
    "    flight:    %d bytes\n"
    (Eio_sctp_full_transport.get_flight_size sender);
  Eio_sctp_full_transport.close sender;
  Eio_sctp_full_transport.close receiver;
  throughput
;;

(** Multi-connection benchmark *)
let bench_multi_connection ~num_connections =
  Eio_main.run
  @@ fun env ->
  let clock = Eio.Stdenv.clock env in
  Printf.printf "\n═══ %d Connections (Concurrent Fibers) ═══\n" num_connections;
  let pairs = Array.init num_connections (fun i -> create_pair ~id:i) in
  let data = Bytes.make packet_size 'X' in
  let total_bytes = Atomic.make 0 in
  let total_msgs = Atomic.make 0 in
  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in
  (* Create fiber list for all connections *)
  let fibers =
    List.concat_map
      (fun (sender, receiver) ->
         [ (* Sender *)
           (fun () ->
             while Unix.gettimeofday () < end_time do
               let flight = Eio_sctp_full_transport.get_flight_size sender in
               let cwnd = Eio_sctp_full_transport.get_cwnd sender in
               if flight < cwnd
               then (
                 match
                   Eio_sctp_full_transport.try_send_data sender ~stream_id:0 ~data
                 with
                 | Ok sent ->
                   Atomic.incr total_msgs;
                   ignore (Atomic.fetch_and_add total_bytes sent)
                 | Error _ -> Eio.Fiber.yield ())
               else Eio.Fiber.yield ()
             done;
             Eio_sctp_full_transport.stop sender)
         ; (* Sender tick *)
           (fun () ->
             while Unix.gettimeofday () < end_time do
               Eio_sctp_full_transport.tick sender;
               Eio.Fiber.yield ()
             done)
         ; (* Receiver *)
           (fun () ->
             while Unix.gettimeofday () < end_time do
               Eio_sctp_full_transport.tick receiver;
               Eio.Fiber.yield ()
             done;
             Eio_sctp_full_transport.stop receiver)
         ])
      (Array.to_list pairs)
  in
  (* Add stats fiber *)
  let fibers =
    fibers
    @ [ (fun () ->
          while Unix.gettimeofday () < end_time do
            Eio.Time.sleep clock 1.0;
            let bytes = Atomic.get total_bytes in
            let elapsed = Unix.gettimeofday () -. start_time in
            let throughput = float_of_int bytes /. elapsed /. 1_000_000.0 in
            Printf.printf "  [%.1fs] throughput=%.1f MB/s\n%!" elapsed throughput
          done)
      ]
  in
  Eio.Fiber.all fibers;
  let bytes = Atomic.get total_bytes in
  let msgs = Atomic.get total_msgs in
  let elapsed = Unix.gettimeofday () -. start_time in
  let throughput = float_of_int bytes /. elapsed /. 1_000_000.0 in
  Printf.printf "\n  Results:\n";
  Printf.printf "    Total messages: %d\n" msgs;
  Printf.printf "    Total bytes:    %d\n" bytes;
  Printf.printf "    Throughput:     %.2f MB/s\n" throughput;
  (* Cleanup *)
  Array.iter
    (fun (s, r) ->
       Eio_sctp_full_transport.close s;
       Eio_sctp_full_transport.close r)
    pairs;
  throughput
;;

let () =
  Printf.printf
    "╔═══════════════════════════════════════════════════════════════════════╗\n";
  Printf.printf
    "║              Eio Concurrent SCTP Benchmark Suite                      ║\n";
  Printf.printf
    "╚═══════════════════════════════════════════════════════════════════════╝\n";
  let single_tp = bench_concurrent () in
  let multi_tp = bench_multi_connection ~num_connections:10 in
  Printf.printf
    "\n╔═══════════════════════════════════════════════════════════════════════╗\n";
  Printf.printf
    "║                           COMPARISON                                 ║\n";
  Printf.printf
    "╠═══════════════════════════════════════════════════════════════════════╣\n";
  Printf.printf
    "║  Implementation       │ Single Conn │ 10 Conn  │ Model       │ Lang  ║\n";
  Printf.printf
    "╠═══════════════════════╪═════════════╪══════════╪═════════════╪═══════╣\n";
  Printf.printf
    "║  OCaml (Eio Fibers)   │  %6.1f MB/s │ %6.1f MB/s │ Concurrent  │ OCaml ║\n"
    single_tp
    multi_tp;
  Printf.printf
    "║  OCaml (Blocking)     │   117.1 MB/s │  115.7 MB/s │ Single-thrd │ OCaml ║\n";
  Printf.printf
    "║  Pion (Go)            │  ~150.0 MB/s │  177.9 MB/s │ Goroutines  │ Go    ║\n";
  Printf.printf
    "║  RustRTC (Rust)       │  ~180.0 MB/s │  213.4 MB/s │ Async       │ Rust  ║\n";
  Printf.printf
    "╚═══════════════════════╧═════════════╧══════════╧═════════════╧═══════╝\n"
;;
