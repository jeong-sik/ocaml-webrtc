(** cwnd Analysis - Understanding congestion window behavior

    The profiling shows UDP send can do 287K ops/s (287 MB/s),
    but full SCTP benchmark only shows 2 MB/s.

    Hypothesis: cwnd fills up immediately, blocking sends until SACK arrives.
    Since SACK processing requires round-trip, we're limited by RTT!
*)

open Webrtc

let packet_size = 1024

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     cwnd Analysis - Why SCTP is slow                          ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  (* Create transport pair *)
  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:32000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:32001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:32001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:32000;
  let data = Bytes.make packet_size 'X' in
  Printf.printf "═══ Initial State ═══\n";
  Printf.printf "  cwnd:        %d bytes\n" (Sctp_full_transport.get_cwnd sender);
  Printf.printf "  ssthresh:    %d bytes\n" (Sctp_full_transport.get_ssthresh sender);
  Printf.printf "  flight_size: %d bytes\n" (Sctp_full_transport.get_flight_size sender);
  Printf.printf
    "  packets that fit in cwnd: %d\n"
    (Sctp_full_transport.get_cwnd sender / packet_size);
  Printf.printf "\n";
  (* Try to send as many packets as possible *)
  Printf.printf "═══ Send Until cwnd Full ═══\n";
  let sent_count = ref 0 in
  let start = Unix.gettimeofday () in
  while
    Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender
  do
    match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
    | Ok _ -> incr sent_count
    | Error e ->
      Printf.printf "  Error after %d sends: %s\n" !sent_count e;
      (* Force break *)
      sent_count := 1000000
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Printf.printf "  Packets sent before cwnd full: %d\n" !sent_count;
  Printf.printf "  Time to fill cwnd: %.6f seconds\n" elapsed;
  Printf.printf
    "  Instantaneous throughput: %.2f MB/s\n"
    (float_of_int (!sent_count * packet_size) /. elapsed /. 1_000_000.0);
  Printf.printf "\n";
  Printf.printf "═══ After Filling cwnd ═══\n";
  Printf.printf "  cwnd:        %d bytes\n" (Sctp_full_transport.get_cwnd sender);
  Printf.printf "  flight_size: %d bytes\n" (Sctp_full_transport.get_flight_size sender);
  Printf.printf
    "  can_send:    %b\n"
    (Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender);
  Printf.printf "\n";
  (* Now try to process receiver to get SACK *)
  Printf.printf "═══ Processing Receiver (to generate SACK) ═══\n";
  let sacks_before = (Sctp_full_transport.get_stats sender).sacks_recv in
  for _ = 1 to 10 do
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender
  done;
  let sacks_after = (Sctp_full_transport.get_stats sender).sacks_recv in
  Printf.printf "  SACKs received: %d (was %d)\n" sacks_after sacks_before;
  Printf.printf
    "  flight_size after ticks: %d bytes\n"
    (Sctp_full_transport.get_flight_size sender);
  Printf.printf
    "  can_send after ticks: %b\n"
    (Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender);
  Printf.printf "\n";
  (* Measure tick overhead *)
  Printf.printf "═══ tick() Overhead Analysis ═══\n";
  let iterations = 10000 in
  let start = Unix.gettimeofday () in
  for _ = 1 to iterations do
    Sctp_full_transport.tick sender
  done;
  let elapsed = Unix.gettimeofday () -. start in
  Printf.printf "  %d ticks in %.6f s\n" iterations elapsed;
  Printf.printf "  tick rate: %.0f ticks/s\n" (float_of_int iterations /. elapsed);
  Printf.printf
    "  ns per tick: %.0f\n"
    (elapsed /. float_of_int iterations *. 1_000_000_000.0);
  Printf.printf "\n";
  (* Key insight *)
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║  ANALYSIS:                                                    ║\n";
  Printf.printf
    "║  - Initial cwnd = %d bytes (%d packets)               ║\n"
    (Sctp_full_transport.get_cwnd sender)
    (Sctp_full_transport.get_cwnd sender / packet_size);
  Printf.printf
    "║  - We can only send %d packets before blocking!          ║\n"
    !sent_count;
  Printf.printf "║  - SACK must arrive to clear flight_size                     ║\n";
  Printf.printf "║  - Loopback RTT ~0.1ms, but we're checking every tick        ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n"
;;
