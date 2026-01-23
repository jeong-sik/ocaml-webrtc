(** SCTP Component Profiling

    Isolates each SCTP component to find the 85x bottleneck.
*)

open Webrtc

let iterations = 100_000
let packet_size = 1024

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Component Benchmarks                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let bench name f =
  let start = Unix.gettimeofday () in
  for _ = 0 to iterations - 1 do
    ignore (f ())
  done;
  let elapsed = Unix.gettimeofday () -. start in
  let ops_per_sec = float_of_int iterations /. elapsed in
  Printf.printf "  %-30s %8.0f ops/s (%.3f s)\n" name ops_per_sec elapsed
;;

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     SCTP Component Profiling (%d iterations)          ║\n" iterations;
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  let data = Bytes.make packet_size 'X' in
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
  (* Encode chunk to bytes *)
  let encoded = ref (Bytes.create 0) in
  Printf.printf "═══ Encoding ═══\n";
  bench "encode_data_chunk" (fun () ->
    encoded := Sctp.encode_data_chunk chunk;
    ());
  (* Decode bytes back to chunk *)
  Printf.printf "\n═══ Decoding ═══\n";
  bench "decode_data_chunk" (fun () ->
    ignore (Sctp.decode_data_chunk !encoded);
    ());
  (* Full packet encode (with header) *)
  let raw_chunk =
    { Sctp.chunk_type = 0
    ; (* DATA chunk type *)
      chunk_flags = 0x03
    ; (* B + E flags *)
      chunk_length = 4 + Bytes.length !encoded
    ; chunk_value = !encoded
    }
  in
  let packet_record =
    { Sctp.header =
        { source_port = 5000; dest_port = 5001; verification_tag = 12345l; checksum = 0l }
    ; chunks = [ raw_chunk ]
    }
  in
  let packet = Sctp.encode_packet packet_record in
  Printf.printf "\n═══ Full Packet ═══\n";
  bench "encode_packet" (fun () ->
    ignore (Sctp.encode_packet packet_record);
    ());
  bench "decode_packet" (fun () ->
    ignore (Sctp.decode_packet packet);
    ());
  (* Ring buffer operations *)
  Printf.printf "\n═══ Ring Buffer ═══\n";
  let rb = Sctp_ring_buffer.create ~capacity:4096 ~initial_tsn:1000l () in
  bench "ring_buffer_enqueue" (fun () ->
    ignore (Sctp_ring_buffer.enqueue rb chunk);
    (* Ack immediately to prevent full *)
    let tsn = Int32.pred (Sctp_ring_buffer.next_tsn rb) in
    ignore (Sctp_ring_buffer.ack rb tsn);
    ignore (Sctp_ring_buffer.advance_head rb);
    ());
  (* SACK processing *)
  Printf.printf "\n═══ SACK Processing ═══\n";
  let rb2 = Sctp_ring_buffer.create ~capacity:4096 ~initial_tsn:1000l () in
  (* Fill with some entries *)
  for _ = 0 to 99 do
    ignore (Sctp_ring_buffer.enqueue rb2 chunk)
  done;
  let cum_tsn = 1050l in
  bench "process_cumulative_ack" (fun () ->
    ignore (Sctp_ring_buffer.process_cumulative_ack rb2 cum_tsn (Unix.gettimeofday ()));
    ());
  (* gettimeofday overhead *)
  Printf.printf "\n═══ Time Functions ═══\n";
  bench "Unix.gettimeofday" (fun () ->
    ignore (Unix.gettimeofday ());
    ());
  (* Bytes allocation *)
  Printf.printf "\n═══ Memory Allocation ═══\n";
  bench "Bytes.create 1024" (fun () ->
    ignore (Bytes.create 1024);
    ());
  bench "Bytes.make 1024 'X'" (fun () ->
    ignore (Bytes.make 1024 'X');
    ());
  (* CRC32c checksum - computed inline with Digestif *)
  Printf.printf "\n═══ Checksum ═══\n";
  let packet_bytes = Bytes.make 1040 'X' in
  let packet_str = Bytes.to_string packet_bytes in
  bench "Digestif.SHA256 (reference)" (fun () ->
    ignore (Digestif.SHA256.digest_string packet_str);
    ());
  (* Summary *)
  Printf.printf "\n";
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║  To achieve 170 MB/s (166K pps), need ~166K ops/s minimum     ║\n";
  Printf.printf "║  Any component below this is a bottleneck!                    ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n"
;;
