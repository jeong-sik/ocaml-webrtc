(** Full SCTP Path Profiling

    Profiles the COMPLETE send path to find the 85x bottleneck.
    Raw UDP: 170 MB/s, SCTP: 2 MB/s - something adds 85x overhead!
*)

open Webrtc

let iterations = 10_000
let packet_size = 1024

(* Timing helper with sub-millisecond precision *)
let time_ns () =
  let t = Unix.gettimeofday () in
  Int64.of_float (t *. 1_000_000_000.0)
;;

let bench name f =
  let start = time_ns () in
  for _ = 0 to iterations - 1 do
    ignore (f ())
  done;
  let elapsed_ns = Int64.sub (time_ns ()) start in
  let elapsed_s = Int64.to_float elapsed_ns /. 1_000_000_000.0 in
  let ops_per_sec = float_of_int iterations /. elapsed_s in
  let ns_per_op = Int64.to_float elapsed_ns /. float_of_int iterations in
  Printf.printf "  %-40s %8.0f ops/s (%6.0f ns/op)\n" name ops_per_sec ns_per_op
;;

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf
    "║     Full SCTP Path Profiling (%d iterations)             ║\n"
    iterations;
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  (* Setup UDP transport pair *)
  let sender_udp = Udp_transport.create ~host:"127.0.0.1" ~port:30000 () in
  let _receiver_udp = Udp_transport.create ~host:"127.0.0.1" ~port:30001 () in
  Udp_transport.connect sender_udp ~host:"127.0.0.1" ~port:30001;
  let data = Bytes.make packet_size 'X' in
  (* ═══════════════════════════════════════════════════════════════ *)
  Printf.printf "═══ Raw Operations ═══\n";
  bench "Unix.gettimeofday" (fun () -> Unix.gettimeofday ());
  bench "Bytes.create 1024" (fun () -> Bytes.create 1024);
  (* ═══════════════════════════════════════════════════════════════ *)
  Printf.printf "\n═══ SCTP Encoding ═══\n";
  let chunk =
    { Sctp.flags =
        { end_fragment = true
        ; begin_fragment = true
        ; unordered = false
        ; immediate = false
        }
    ; tsn = 1000l
    ; stream_id = 0
    ; stream_seq = 0
    ; ppid = 0x32l
    ; user_data = data
    }
  in
  bench "Sctp.encode_data_chunk" (fun () -> Sctp.encode_data_chunk chunk);
  let encoded = Sctp.encode_data_chunk chunk in
  bench "Sctp.decode_data_chunk" (fun () -> Sctp.decode_data_chunk encoded);
  (* Fragment data *)
  bench "Sctp.fragment_data (1KB → 1 chunk)" (fun () ->
    Sctp.fragment_data
      ~data
      ~stream_id:0
      ~stream_seq:0
      ~ppid:0x32l
      ~start_tsn:1000l
      ~mtu:1200);
  (* ═══════════════════════════════════════════════════════════════ *)
  Printf.printf "\n═══ Ring Buffer ═══\n";
  let rb = Sctp_ring_buffer.create ~capacity:4096 ~initial_tsn:1000l () in
  bench "Ring buffer: enqueue + ack + advance" (fun () ->
    ignore (Sctp_ring_buffer.enqueue rb chunk);
    let tsn = Int32.pred (Sctp_ring_buffer.next_tsn rb) in
    ignore (Sctp_ring_buffer.ack rb tsn);
    ignore (Sctp_ring_buffer.advance_head rb);
    ());
  (* Fresh buffer for realistic benchmark *)
  let rb2 = Sctp_ring_buffer.create ~capacity:4096 ~initial_tsn:1000l () in
  bench "Ring buffer: enqueue only" (fun () ->
    ignore (Sctp_ring_buffer.enqueue rb2 chunk));
  (* ═══════════════════════════════════════════════════════════════ *)
  Printf.printf "\n═══ Reliable Layer Operations ═══\n";
  let reliable = Sctp_reliable.create () in
  bench "Sctp_reliable.can_send" (fun () -> Sctp_reliable.can_send reliable);
  bench "Sctp_reliable.alloc_tsn" (fun () -> Sctp_reliable.alloc_tsn reliable);
  bench "Sctp_reliable.queue_data" (fun () -> Sctp_reliable.queue_data reliable chunk);
  bench "Sctp_reliable.get_cwnd" (fun () -> Sctp_reliable.get_cwnd reliable);
  bench "Sctp_reliable.get_flight_size" (fun () -> Sctp_reliable.get_flight_size reliable);
  (* ═══════════════════════════════════════════════════════════════ *)
  Printf.printf "\n═══ UDP Transport ═══\n";
  bench "Udp_transport.send_connected (1KB)" (fun () ->
    Udp_transport.send_connected sender_udp ~data:encoded);
  (* ═══════════════════════════════════════════════════════════════ *)
  Printf.printf "\n═══ Full SCTP Transport Path ═══\n";
  (* Create full transport *)
  let full_transport = Sctp_full_transport.create ~host:"127.0.0.1" ~port:30100 () in
  Sctp_full_transport.connect full_transport ~host:"127.0.0.1" ~port:30001;
  (* Measure tick (this might be the hidden cost!) *)
  bench "Sctp_full_transport.tick (idle)" (fun () ->
    Sctp_full_transport.tick full_transport);
  (* send_data with fresh transport each time to avoid cwnd blocking *)
  let send_count = ref 0 in
  bench "Sctp_full_transport.send_data (1KB)" (fun () ->
    (* Create fresh transport to avoid cwnd limits *)
    let t =
      Sctp_full_transport.create
        ~host:"127.0.0.1"
        ~port:(31000 + (!send_count mod 1000))
        ()
    in
    Sctp_full_transport.connect t ~host:"127.0.0.1" ~port:30001;
    incr send_count;
    match Sctp_full_transport.send_data t ~stream_id:0 ~data with
    | Ok _ -> ()
    | Error _ -> ());
  (* Cleanup *)
  Udp_transport.close sender_udp;
  (* Summary *)
  Printf.printf "\n";
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║  Target: 166K ops/s (170 MB/s at 1KB packets)                 ║\n";
  Printf.printf "║  Anything below 166K is a bottleneck!                         ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n"
;;
