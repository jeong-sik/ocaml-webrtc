(** HONEST Blocking Benchmark - Compare with Eio version *)

open Webrtc

let base_port = 26000
let packet_size = 1024
let test_duration_sec = 5

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     HONEST BLOCKING Benchmark - For Fair Comparison          ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:base_port () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:(base_port + 1) () in

  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:(base_port + 1);
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:base_port;

  let data = Bytes.make packet_size 'X' in
  let msgs_sent = ref 0 in
  let bytes_sent = ref 0 in

  let start_time = Unix.gettimeofday () in
  let end_time = start_time +. float_of_int test_duration_sec in
  let last_report = ref start_time in

  while Unix.gettimeofday () < end_time do
    (* Send if cwnd allows *)
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok sent ->
        incr msgs_sent;
        bytes_sent := !bytes_sent + sent
      | Error _ -> ()
    end;

    (* Tick both *)
    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;

    (* Progress report every second *)
    let now = Unix.gettimeofday () in
    if now -. !last_report >= 1.0 then begin
      let sender_stats = Sctp_full_transport.get_stats sender in
      let receiver_stats = Sctp_full_transport.get_stats receiver in
      let elapsed = now -. start_time in
      Printf.printf "[%.1fs] sent=%d recv=%d (%.1f%%) rtx=%d\n%!"
        elapsed
        !msgs_sent
        receiver_stats.messages_recv
        (if !msgs_sent > 0 then float_of_int receiver_stats.messages_recv /. float_of_int !msgs_sent *. 100.0 else 0.0)
        sender_stats.retransmissions;
      last_report := now
    end
  done;

  (* Drain *)
  Printf.printf "\nDraining...\n%!";
  for _ = 1 to 1000 do
    Sctp_full_transport.tick sender;
    Sctp_full_transport.tick receiver;
  done;

  let elapsed = Unix.gettimeofday () -. start_time in
  let sender_stats = Sctp_full_transport.get_stats sender in
  let receiver_stats = Sctp_full_transport.get_stats receiver in

  Printf.printf "\n═══ HONEST BLOCKING RESULTS ═══\n";
  Printf.printf "\n  SENDER:\n";
  Printf.printf "    Messages sent:         %d\n" sender_stats.messages_sent;
  Printf.printf "    Bytes sent:            %d\n" !bytes_sent;
  Printf.printf "    Retransmissions:       %d\n" sender_stats.retransmissions;
  Printf.printf "    Fast RTX:              %d\n" sender_stats.fast_retransmissions;

  Printf.printf "\n  RECEIVER:\n";
  Printf.printf "    Messages recv:         %d\n" receiver_stats.messages_recv;
  Printf.printf "    Bytes recv:            %d\n" receiver_stats.bytes_recv;

  let delivery_ratio = if !msgs_sent > 0
    then float_of_int receiver_stats.messages_recv /. float_of_int !msgs_sent *. 100.0
    else 0.0 in

  Printf.printf "\n  ═══ DELIVERY & THROUGHPUT ═══\n";
  Printf.printf "    Delivery ratio:        %.2f%%\n" delivery_ratio;
  Printf.printf "    Retransmission rate:   %.2f%%\n"
    (if !msgs_sent > 0 then float_of_int sender_stats.retransmissions /. float_of_int !msgs_sent *. 100.0 else 0.0);

  let honest_throughput = float_of_int receiver_stats.bytes_recv /. elapsed /. 1_000_000.0 in
  Printf.printf "    ACTUAL throughput:     %.2f MB/s\n" honest_throughput;

  Sctp_full_transport.close sender;
  Sctp_full_transport.close receiver
