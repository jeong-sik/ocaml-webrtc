(** Eio UDP vs Unix UDP Benchmark

    Compares raw UDP throughput:
    1. Unix.sendto/recvfrom (current implementation)
    2. Eio.Net.send/recv (io_uring on Linux, kqueue on macOS)

    This isolates the I/O layer from SCTP protocol overhead.
*)

let packet_size = 1024
let test_duration_sec = 3
let base_port = 25000

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Unix UDP Benchmark (current implementation)                                 *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_unix_udp () =
  Printf.printf "\n═══ Unix UDP (raw syscalls) ═══\n";

  let sender = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  let receiver = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in

  (* Increase buffer sizes *)
  (try Unix.setsockopt_int sender Unix.SO_SNDBUF (4 * 1024 * 1024) with _ -> ());
  (try Unix.setsockopt_int receiver Unix.SO_RCVBUF (4 * 1024 * 1024) with _ -> ());

  Unix.bind receiver (Unix.ADDR_INET (Unix.inet_addr_loopback, base_port));
  Unix.set_nonblock receiver;

  let dest = Unix.ADDR_INET (Unix.inet_addr_loopback, base_port) in
  let data = Bytes.make packet_size 'X' in
  let recv_buf = Bytes.create 65536 in

  let packets_sent = ref 0 in
  let packets_recv = ref 0 in

  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in

  while Unix.gettimeofday () < end_time do
    (* Send *)
    (try
      ignore (Unix.sendto sender data 0 packet_size [] dest);
      incr packets_sent
    with _ -> ());

    (* Receive (drain all) *)
    let rec drain () =
      try
        ignore (Unix.recvfrom receiver recv_buf 0 65536 []);
        incr packets_recv;
        drain ()
      with Unix.Unix_error (Unix.EAGAIN, _, _) -> ()
    in
    drain ()
  done;

  let elapsed = Unix.gettimeofday () -. start_time in
  let throughput = float_of_int (!packets_sent * packet_size) /. elapsed /. 1_000_000.0 in

  Printf.printf "  Packets sent: %d\n" !packets_sent;
  Printf.printf "  Packets recv: %d\n" !packets_recv;
  Printf.printf "  Throughput:   %.2f MB/s\n" throughput;
  Printf.printf "  PPS:          %.0f\n" (float_of_int !packets_sent /. elapsed);

  Unix.close sender;
  Unix.close receiver;

  throughput

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Eio UDP Benchmark                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench_eio_udp () =
  Printf.printf "\n═══ Eio UDP (io_uring/kqueue) ═══\n";

  Eio_main.run @@ fun env ->
  let net = Eio.Stdenv.net env in

  Eio.Switch.run @@ fun sw ->

  (* Create sender and receiver sockets *)
  let loopback = Eio.Net.Ipaddr.V4.loopback in
  let recv_addr = `Udp (loopback, base_port + 1) in
  let receiver = Eio.Net.datagram_socket ~sw net recv_addr in

  let sender = Eio.Net.datagram_socket ~sw net `UdpV4 in
  let dest = `Udp (loopback, base_port + 1) in

  let data = Cstruct.create packet_size in
  let recv_buf = Cstruct.create 65536 in

  let packets_sent = Atomic.make 0 in
  let packets_recv = Atomic.make 0 in
  let running = Atomic.make true in

  let start_time = Unix.gettimeofday () in

  (* Run sender and receiver in parallel fibers *)
  Eio.Fiber.all [
    (* Sender fiber *)
    (fun () ->
      while Atomic.get running do
        Eio.Net.send sender ~dst:dest [data];
        Atomic.incr packets_sent
      done
    );
    (* Receiver fiber *)
    (fun () ->
      while Atomic.get running do
        ignore (Eio.Net.recv receiver recv_buf);
        Atomic.incr packets_recv
      done
    );
    (* Timer fiber *)
    (fun () ->
      Eio.Time.sleep (Eio.Stdenv.clock env) (float_of_int test_duration_sec);
      Atomic.set running false
    );
  ];

  let elapsed = Unix.gettimeofday () -. start_time in
  let sent = Atomic.get packets_sent in
  let recv = Atomic.get packets_recv in
  let throughput = float_of_int (sent * packet_size) /. elapsed /. 1_000_000.0 in

  Printf.printf "  Packets sent: %d\n" sent;
  Printf.printf "  Packets recv: %d\n" recv;
  Printf.printf "  Throughput:   %.2f MB/s\n" throughput;
  Printf.printf "  PPS:          %.0f\n" (float_of_int sent /. elapsed);

  throughput

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main                                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     UDP I/O Layer Benchmark                                   ║\n";
  Printf.printf "║     Unix syscalls vs Eio (io_uring/kqueue)                    ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";
  Printf.printf "\n  Packet size: %d bytes\n" packet_size;
  Printf.printf "  Duration: %d seconds each\n" test_duration_sec;

  let unix_tp = bench_unix_udp () in
  let eio_tp = bench_eio_udp () in

  Printf.printf "\n";
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║                    COMPARISON                                 ║\n";
  Printf.printf "╠═══════════════════════════════════════════════════════════════╣\n";
  Printf.printf "║  Unix UDP:  %6.2f MB/s                                       ║\n" unix_tp;
  Printf.printf "║  Eio UDP:   %6.2f MB/s                                       ║\n" eio_tp;
  Printf.printf "║  Speedup:   %.1fx                                             ║\n" (eio_tp /. unix_tp);
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n"
