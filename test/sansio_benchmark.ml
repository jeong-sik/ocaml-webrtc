(** Sans-IO SCTP Benchmark

    Tests the new Sans-IO architecture (sctp_core.ml + sctp_eio.ml)
    to ensure it matches or exceeds the old sctp_full_transport.ml performance.

    Uses single-process, bidirectional communication similar to honest_benchmark.

    Goals:
    - 100% delivery ratio (no lost messages)
    - Throughput >= old implementation
    - Memory efficiency (smaller state)
*)

open Webrtc

let base_port = 26000
let packet_size = 1024
let test_duration_sec = 5

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     Sans-IO Benchmark - Phase 3 Architecture                  ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";

  (* Generate shared initial TSN *)
  Random.self_init ();
  let initial_tsn = Int32.of_int (1000 + Random.int 10000) in

  (* Create Sans-IO sender and receiver *)
  let sender = Sctp_eio.create ~initial_tsn ~host:"127.0.0.1" ~port:base_port () in
  let receiver = Sctp_eio.create ~initial_tsn ~host:"127.0.0.1" ~port:(base_port + 1) () in

  (* Connect bidirectionally *)
  let sender_ep = Sctp_eio.local_endpoint sender in
  let receiver_ep = Sctp_eio.local_endpoint receiver in
  Printf.printf "Sender: %s:%d\n" sender_ep.Udp_transport.host sender_ep.port;
  Printf.printf "Receiver: %s:%d\n\n" receiver_ep.Udp_transport.host receiver_ep.port;

  Sctp_eio.connect sender ~host:receiver_ep.host ~port:receiver_ep.port;
  Sctp_eio.connect receiver ~host:sender_ep.host ~port:sender_ep.port;

  (* Track received messages *)
  let recv_count = ref 0 in
  let recv_bytes = ref 0 in

  Sctp_eio.on_data receiver (fun _stream_id data ->
    incr recv_count;
    recv_bytes := !recv_bytes + Bytes.length data
  );

  (* Run benchmark *)
  let data = Bytes.make packet_size 'X' in
  let start_time = Unix.gettimeofday () in
  let last_progress = ref start_time in
  let send_count = ref 0 in
  let send_bytes = ref 0 in

  while (Unix.gettimeofday () -. start_time) < float_of_int test_duration_sec do
    (* Try to send *)
    begin match Sctp_eio.send sender ~stream_id:0 ~data with
    | Ok n ->
      incr send_count;
      send_bytes := !send_bytes + n
    | Error _ ->
      (* Congestion window full - just tick *)
      ()
    end;

    (* Tick both sides - process packets and timers *)
    Sctp_eio.tick sender;
    Sctp_eio.tick receiver;

    (* Progress report every second *)
    let now = Unix.gettimeofday () in
    if now -. !last_progress >= 1.0 then begin
      let elapsed = now -. start_time in
      let sender_stats = Sctp_eio.get_stats sender in
      Printf.printf "[%.1fs] sent=%d recv=%d (%.1f%%) rtx=%d\n%!"
        elapsed !send_count !recv_count
        (if !send_count > 0
         then 100.0 *. float_of_int !recv_count /. float_of_int !send_count
         else 0.0)
        sender_stats.Sctp_core.retransmissions;
      last_progress := now
    end
  done;

  (* Drain remaining packets *)
  Printf.printf "\nDraining...\n%!";
  let drain_start = Unix.gettimeofday () in
  while (Unix.gettimeofday () -. drain_start) < 2.0 do
    Sctp_eio.tick sender;
    Sctp_eio.tick receiver;
    Unix.sleepf 0.001
  done;

  let elapsed = Unix.gettimeofday () -. start_time in
  let sender_stats = Sctp_eio.get_stats sender in
  let sender_udp_stats = Udp_transport.get_stats (Sctp_eio.get_udp_transport sender) in
  let receiver_udp_stats = Udp_transport.get_stats (Sctp_eio.get_udp_transport receiver) in

  (* Print results *)
  Printf.printf "\n═══ SANS-IO RESULTS ═══\n\n";

  Printf.printf "  SENDER:\n";
  Printf.printf "    Messages sent (SCTP):  %d\n" sender_stats.messages_sent;
  Printf.printf "    Bytes sent (SCTP):     %d\n" sender_stats.bytes_sent;
  Printf.printf "    UDP packets sent:      %d\n" sender_udp_stats.packets_sent;
  Printf.printf "    SACKs received:        %d\n" sender_stats.sacks_recv;
  Printf.printf "    Retransmissions:       %d\n" sender_stats.retransmissions;
  Printf.printf "    Fast RTX:              %d\n" sender_stats.fast_retransmissions;

  Printf.printf "\n  RECEIVER:\n";
  Printf.printf "    Messages recv (SCTP):  %d\n" !recv_count;
  Printf.printf "    Bytes recv (SCTP):     %d\n" !recv_bytes;
  Printf.printf "    UDP packets recv:      %d\n" receiver_udp_stats.packets_recv;
  Printf.printf "    SACKs sent:            %d\n" (Sctp_eio.get_stats receiver).sacks_sent;

  Printf.printf "\n  ═══ DELIVERY METRICS ═══\n";
  let delivery_ratio =
    if sender_stats.messages_sent > 0 then
      100.0 *. float_of_int !recv_count /. float_of_int sender_stats.messages_sent
    else 0.0
  in
  Printf.printf "    Delivery ratio:        %.2f%%\n" delivery_ratio;
  Printf.printf "    Lost messages:         %d\n" (sender_stats.messages_sent - !recv_count);

  Printf.printf "\n  ═══ THROUGHPUT (HONEST) ═══\n";
  let send_throughput = float_of_int sender_stats.bytes_sent /. elapsed /. 1024.0 /. 1024.0 in
  let recv_throughput = float_of_int !recv_bytes /. elapsed /. 1024.0 /. 1024.0 in
  Printf.printf "    Sender throughput:     %.2f MB/s (what we claimed before)\n" send_throughput;
  Printf.printf "    ACTUAL throughput:     %.2f MB/s (bytes received/time)\n" recv_throughput;

  Printf.printf "\n  ═══ ARCHITECTURE ═══\n";
  Printf.printf "    Pattern:               Sans-IO (Pure State Machine)\n";
  Printf.printf "    Core:                  sctp_core.ml\n";
  Printf.printf "    I/O Adapter:           sctp_eio.ml\n";

  (* Verdict *)
  if delivery_ratio >= 99.9 then
    Printf.printf "\n  ✓ Delivery is reliable (%.2f%%)\n" delivery_ratio
  else
    Printf.printf "\n  ✗ Delivery FAILED (%.2f%% < 99.9%%)\n" delivery_ratio;

  (* Cleanup *)
  Sctp_eio.close sender;
  Sctp_eio.close receiver
