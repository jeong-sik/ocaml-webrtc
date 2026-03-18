(** Fault injection tests for Sctp_core Sans-IO state machine

    Verifies that the state machine handles malformed inputs gracefully:
    - No crashes on corrupted packets
    - Error outputs (not exceptions) for truncated packets
    - Graceful handling of out-of-order timers

    @since 0.3.0
*)

open Webrtc

let test_count = ref 0
let pass_count = ref 0
let fail_count = ref 0

let check name cond =
  incr test_count;
  if cond
  then (
    incr pass_count;
    Printf.printf "  PASS: %s\n" name)
  else (
    incr fail_count;
    Printf.printf "  FAIL: %s\n" name)
;;

let fresh_core () = Sctp_core.create ~src_port:5000 ~dst_port:5000 ()

(* --- Corrupted packet tests --- *)

let () =
  Printf.printf "=== Corrupted Packets ===\n";
  (* Garbage bytes should not crash *)
  let t = fresh_core () in
  check
    "garbage 1 byte no crash"
    (Fault_injection.did_not_crash (fun () ->
       Sctp_core.handle t (PacketReceived (Fault_injection.garbage_packet ~len:1))));
  let t = fresh_core () in
  check
    "garbage 100 bytes no crash"
    (Fault_injection.did_not_crash (fun () ->
       Sctp_core.handle t (PacketReceived (Fault_injection.garbage_packet ~len:100))));
  let t = fresh_core () in
  check
    "garbage 1000 bytes no crash"
    (Fault_injection.did_not_crash (fun () ->
       Sctp_core.handle t (PacketReceived (Fault_injection.garbage_packet ~len:1000))));
  (* Empty packet *)
  let t = fresh_core () in
  check
    "empty packet no crash"
    (Fault_injection.did_not_crash (fun () ->
       Sctp_core.handle t (PacketReceived Bytes.empty)));
  let t = fresh_core () in
  let outputs = Sctp_core.handle t (PacketReceived Bytes.empty) in
  check "empty packet returns Error" (Fault_injection.has_error outputs);
  ()
;;

(* --- Truncated packet tests --- *)

let () =
  Printf.printf "\n=== Truncated Packets ===\n";
  (* Too-short header *)
  let t = fresh_core () in
  let outputs =
    Sctp_core.handle t (PacketReceived (Fault_injection.too_short_header ()))
  in
  check "3-byte header returns Error" (Fault_injection.has_error outputs);
  check "3-byte header no crash" true;
  (* Header-only (no chunks) *)
  let t = fresh_core () in
  let header = Fault_injection.valid_header () in
  check
    "12-byte header-only no crash"
    (Fault_injection.did_not_crash (fun () -> Sctp_core.handle t (PacketReceived header)));
  (* Progressively truncated packets *)
  for len = 1 to 20 do
    let t = fresh_core () in
    let packet = Fault_injection.garbage_packet ~len:100 in
    let truncated = Fault_injection.truncate_packet ~len packet in
    check
      (Printf.sprintf "truncated %d bytes no crash" len)
      (Fault_injection.did_not_crash (fun () ->
         Sctp_core.handle t (PacketReceived truncated)))
  done;
  ()
;;

(* --- Bit-flip corruption tests --- *)

let () =
  Printf.printf "\n=== Bit-Flip Corruption ===\n";
  (* Create a valid-looking header and flip bits in various positions *)
  let header = Fault_injection.valid_header ~vtag:0x12345678l () in
  for pos = 0 to 11 do
    for bit = 0 to 7 do
      let t = fresh_core () in
      let corrupted = Fault_injection.flip_bit ~pos ~bit header in
      check
        (Printf.sprintf "flip byte %d bit %d no crash" pos bit)
        (Fault_injection.did_not_crash (fun () ->
           Sctp_core.handle t (PacketReceived corrupted)))
    done
  done;
  ()
;;

(* --- CRC manipulation tests --- *)

let () =
  Printf.printf "\n=== CRC Manipulation ===\n";
  let t = fresh_core () in
  let header = Fault_injection.valid_header () in
  let zeroed = Fault_injection.zero_checksum header in
  check
    "zeroed CRC no crash"
    (Fault_injection.did_not_crash (fun () -> Sctp_core.handle t (PacketReceived zeroed)));
  (* Corrupt CRC specifically *)
  let t = fresh_core () in
  let bad_crc = Fault_injection.corrupt_byte ~pos:8 ~value:0xFF header in
  check
    "bad CRC byte no crash"
    (Fault_injection.did_not_crash (fun () -> Sctp_core.handle t (PacketReceived bad_crc)));
  ()
;;

(* --- Timer order tests --- *)

let () =
  Printf.printf "\n=== Timer Order ===\n";
  (* All timers on fresh state should not crash *)
  let t = fresh_core () in
  check
    "fire all timers on Closed no crash"
    (Fault_injection.did_not_crash (fun () -> ignore (Fault_injection.fire_all_timers t)));
  (* Reversed timer order *)
  let t = fresh_core () in
  check
    "reversed timers no crash"
    (Fault_injection.did_not_crash (fun () ->
       ignore (Fault_injection.fire_timers_reversed t)));
  (* Double-fire same timer *)
  let t = fresh_core () in
  check
    "double T3Rtx no crash"
    (Fault_injection.did_not_crash (fun () ->
       ignore (Sctp_core.handle t (TimerFired T3Rtx));
       ignore (Sctp_core.handle t (TimerFired T3Rtx))));
  (* Timer fire after UserClose *)
  let t = fresh_core () in
  check
    "timer after UserClose no crash"
    (Fault_injection.did_not_crash (fun () ->
       ignore (Sctp_core.handle t UserClose);
       ignore (Fault_injection.fire_all_timers t)));
  ()
;;

(* --- Oas_error integration --- *)

let () =
  Printf.printf "\n=== Oas_error Integration ===\n";
  let t = fresh_core () in
  let outputs = Sctp_core.handle t (PacketReceived Bytes.empty) in
  let errors = Fault_injection.errors_of outputs in
  List.iter
    (fun msg ->
       let err = Oas_error.of_string msg in
       check
         (Printf.sprintf "classify '%s' = %s" msg (Oas_error.show_error_class err.cls))
         (err.cls = Protocol || err.cls = Fatal))
    errors;
  ()
;;

(* --- Summary --- *)

let () =
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "%d/%d passed (%d failed)\n" !pass_count !test_count !fail_count;
  if !fail_count > 0 then exit 1
;;
