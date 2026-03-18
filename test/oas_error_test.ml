(** Tests for Oas_error — structured error classification *)

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

(* --- classify tests --- *)

let () =
  Printf.printf "=== Oas_error.classify ===\n";
  (* Fatal errors *)
  check
    "abort is Fatal"
    (Oas_error.classify "Association aborted by peer (T-bit=false, 4 error cause bytes)"
     = Fatal);
  check "shutdown timeout is Fatal" (Oas_error.classify "Shutdown timeout" = Fatal);
  check
    "handshake timeout is Fatal"
    (Oas_error.classify "Handshake timeout: max retransmits exceeded" = Fatal);
  check "max retransmits is Fatal" (Oas_error.classify "Max retransmits exceeded" = Fatal);
  check
    "AES-GCM auth failure is Fatal"
    (Oas_error.classify "AES-GCM authentication failed" = Fatal);
  (* Transient errors *)
  check "congestion is Transient" (Oas_error.classify "Congestion window full" = Transient);
  check
    "unexpected heartbeat-ack is Transient"
    (Oas_error.classify "Unexpected HEARTBEAT-ACK" = Transient);
  (* Config errors *)
  check
    "wrong state is Config"
    (Oas_error.classify "RE-CONFIG requires Established state" = Config);
  check
    "unexpected state is Config"
    (Oas_error.classify "Received COOKIE-ACK in unexpected state" = Config);
  check
    "no handshake is Config"
    (Oas_error.classify "Received INIT-ACK but no handshake in progress" = Config);
  check
    "unknown channel is Config"
    (Oas_error.classify "ACK for unknown channel 5" = Config);
  (* Protocol errors (decode failures, malformed packets) *)
  check
    "DATA decode is Protocol"
    (Oas_error.classify "DATA decode: invalid length" = Protocol);
  check "SACK decode is Protocol" (Oas_error.classify "SACK decode: truncated" = Protocol);
  check "CRC mismatch is Protocol" (Oas_error.classify "CRC32c mismatch" = Protocol);
  check
    "packet too short is Protocol"
    (Oas_error.classify "Packet too short for SCTP header" = Protocol);
  check
    "unknown string defaults to Protocol"
    (Oas_error.classify "some unknown error" = Protocol);
  ()
;;

(* --- of_string tests --- *)

let () =
  Printf.printf "\n=== Oas_error.of_string ===\n";
  let e = Oas_error.of_string "DATA decode: invalid length" in
  check "of_string cls" (e.cls = Protocol);
  check "of_string message preserved" (e.message = "DATA decode: invalid length");
  check "of_string module hint" (e.module_hint = "DATA");
  let e2 = Oas_error.of_string "Congestion window full" in
  check "transient of_string cls" (e2.cls = Transient);
  check "transient module hint" (e2.module_hint = "sctp_core");
  let e3 =
    Oas_error.of_string "Association aborted by peer (T-bit=false, 0 error cause bytes)"
  in
  check "fatal of_string cls" (e3.cls = Fatal);
  check "fatal module hint" (e3.module_hint = "sctp_core");
  ()
;;

(* --- is_retryable / is_fatal tests --- *)

let () =
  Printf.printf "\n=== Oas_error predicates ===\n";
  let transient = Oas_error.of_string "Congestion window full" in
  let protocol = Oas_error.of_string "CRC32c mismatch" in
  let fatal = Oas_error.of_string "Shutdown timeout" in
  let config = Oas_error.of_string "RE-CONFIG requires Established state" in
  check "transient is retryable" (Oas_error.is_retryable transient = true);
  check "protocol not retryable" (Oas_error.is_retryable protocol = false);
  check "fatal not retryable" (Oas_error.is_retryable fatal = false);
  check "config not retryable" (Oas_error.is_retryable config = false);
  check "fatal is_fatal" (Oas_error.is_fatal fatal = true);
  check "transient not is_fatal" (Oas_error.is_fatal transient = false);
  check "protocol not is_fatal" (Oas_error.is_fatal protocol = false);
  ()
;;

(* --- to_string tests --- *)

let () =
  Printf.printf "\n=== Oas_error.to_string ===\n";
  let e = Oas_error.of_string "Congestion window full" in
  let s = Oas_error.to_string e in
  check
    "to_string contains TRANSIENT"
    (String.length s > 0
     &&
     let sub = "[TRANSIENT]" in
     let sub_len = String.length sub in
     let s_len = String.length s in
     sub_len <= s_len && String.sub s 0 sub_len = sub);
  check
    "to_string contains message"
    (let msg = "Congestion window full" in
     let msg_len = String.length msg in
     let s_len = String.length s in
     msg_len <= s_len
     &&
     let rec find i =
       if i > s_len - msg_len
       then false
       else if String.sub s i msg_len = msg
       then true
       else find (i + 1)
     in
     find 0);
  ()
;;

(* --- eq / show (ppx_deriving) tests --- *)

let () =
  Printf.printf "\n=== ppx_deriving ===\n";
  check "equal_error_class same" (Oas_error.equal_error_class Transient Transient);
  check "equal_error_class diff" (not (Oas_error.equal_error_class Transient Fatal));
  check "show_error_class" (String.length (Oas_error.show_error_class Fatal) > 0);
  check
    "equal_t same"
    (let e = Oas_error.of_string "test" in
     Oas_error.equal e e);
  check
    "show_t"
    (let e = Oas_error.of_string "test" in
     String.length (Oas_error.show e) > 0);
  ()
;;

(* --- Summary --- *)

let () =
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "%d/%d passed (%d failed)\n" !pass_count !test_count !fail_count;
  if !fail_count > 0 then exit 1
;;
