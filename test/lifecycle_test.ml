(** Tests for Lifecycle — connection phase management and cleanup *)

open Webrtc

let test_count = ref 0
let pass_count = ref 0
let fail_count = ref 0

let check name cond =
  incr test_count;
  if cond then (
    incr pass_count;
    Printf.printf "  PASS: %s\n" name)
  else (
    incr fail_count;
    Printf.printf "  FAIL: %s\n" name)

(* Track cleanup calls *)
let cleanup_log : string list ref = ref []
let reset_log () = cleanup_log := []
let make_cleanup label () = cleanup_log := !cleanup_log @ [label]

(* --- Phase transitions --- *)

let () =
  Printf.printf "=== Phase Transitions ===\n";

  let lc = Lifecycle.create () in
  check "starts at Init"
    (Lifecycle.current_phase lc = Init);

  check "advance to Ice_gathering"
    (Lifecycle.advance lc ~phase:Ice_gathering ~cleanup:(fun () -> ()) = Ok ());
  check "current is Ice_gathering"
    (Lifecycle.current_phase lc = Ice_gathering);

  check "advance to Dtls_handshake"
    (Lifecycle.advance lc ~phase:Dtls_handshake ~cleanup:(fun () -> ()) = Ok ());

  check "advance to Sctp_association"
    (Lifecycle.advance lc ~phase:Sctp_association ~cleanup:(fun () -> ()) = Ok ());

  check "advance to Data_channel"
    (Lifecycle.advance lc ~phase:Data_channel ~cleanup:(fun () -> ()) = Ok ());

  check "advance to Established"
    (Lifecycle.advance lc ~phase:Established ~cleanup:(fun () -> ()) = Ok ());

  check "is_established"
    (Lifecycle.is_established lc);

  check "completed phases count"
    (List.length (Lifecycle.completed_phases lc) = 5);
  ()

(* --- Invalid transitions --- *)

let () =
  Printf.printf "\n=== Invalid Transitions ===\n";

  let lc = Lifecycle.create () in
  (* Skip Ice_gathering *)
  check "skip phase returns Error"
    (Result.is_error
       (Lifecycle.advance lc ~phase:Dtls_handshake ~cleanup:(fun () -> ())));

  (* Double advance to same phase *)
  let lc2 = Lifecycle.create () in
  let _ = Lifecycle.advance lc2 ~phase:Ice_gathering ~cleanup:(fun () -> ()) in
  check "same phase again returns Error"
    (Result.is_error
       (Lifecycle.advance lc2 ~phase:Ice_gathering ~cleanup:(fun () -> ())));

  ()

(* --- Cleanup on failure --- *)

let () =
  Printf.printf "\n=== Cleanup on Failure ===\n";
  reset_log ();

  let lc = Lifecycle.create () in
  let _ = Lifecycle.advance lc ~phase:Ice_gathering
    ~cleanup:(make_cleanup "ice") in
  let _ = Lifecycle.advance lc ~phase:Dtls_handshake
    ~cleanup:(make_cleanup "dtls") in
  let _ = Lifecycle.advance lc ~phase:Sctp_association
    ~cleanup:(make_cleanup "sctp") in

  let failure = Lifecycle.fail lc ~error:"Handshake timeout" in

  check "cleanup reverse order (newest first)"
    (!cleanup_log = ["sctp"; "dtls"; "ice"]);

  check "failed_phase is Sctp_association"
    (failure.failed_phase = Sctp_association);

  check "error classified as Fatal"
    (failure.error.cls = Fatal);

  check "cleaned 3 phases"
    (List.length failure.cleaned_phases = 3);

  check "is_failed"
    (Lifecycle.is_failed lc);

  check "not established after failure"
    (not (Lifecycle.is_established lc));

  ()

(* --- Cleanup exception safety --- *)

let () =
  Printf.printf "\n=== Cleanup Exception Safety ===\n";
  reset_log ();

  let lc = Lifecycle.create () in
  let _ = Lifecycle.advance lc ~phase:Ice_gathering
    ~cleanup:(make_cleanup "ice") in
  let _ = Lifecycle.advance lc ~phase:Dtls_handshake
    ~cleanup:(fun () ->
      make_cleanup "dtls_before_exn" ();
      failwith "cleanup error") in
  let _ = Lifecycle.advance lc ~phase:Sctp_association
    ~cleanup:(make_cleanup "sctp") in

  let failure = Lifecycle.fail lc ~error:"some error" in

  check "all cleanups ran despite exception"
    (List.length !cleanup_log = 3);

  check "sctp cleanup ran"
    (List.mem "sctp" !cleanup_log);
  check "dtls cleanup ran (before exn)"
    (List.mem "dtls_before_exn" !cleanup_log);
  check "ice cleanup ran after dtls exn"
    (List.mem "ice" !cleanup_log);

  check "cleaned 3 phases"
    (List.length failure.cleaned_phases = 3);

  ()

(* --- Advance after failure --- *)

let () =
  Printf.printf "\n=== Advance After Failure ===\n";

  let lc = Lifecycle.create () in
  let _ = Lifecycle.advance lc ~phase:Ice_gathering ~cleanup:(fun () -> ()) in
  let _ = Lifecycle.fail lc ~error:"test" in

  check "advance after failure returns Error"
    (Result.is_error
       (Lifecycle.advance lc ~phase:Dtls_handshake ~cleanup:(fun () -> ())));

  ()

(* --- Phase index ordering --- *)

let () =
  Printf.printf "\n=== Phase Index ===\n";

  check "Init = 0" (Lifecycle.phase_index Init = 0);
  check "Ice_gathering = 1" (Lifecycle.phase_index Ice_gathering = 1);
  check "Dtls_handshake = 2" (Lifecycle.phase_index Dtls_handshake = 2);
  check "Sctp_association = 3" (Lifecycle.phase_index Sctp_association = 3);
  check "Data_channel = 4" (Lifecycle.phase_index Data_channel = 4);
  check "Established = 5" (Lifecycle.phase_index Established = 5);

  ()

(* --- ppx_deriving --- *)

let () =
  Printf.printf "\n=== ppx_deriving ===\n";

  check "show_phase"
    (String.length (Lifecycle.show_phase Init) > 0);
  check "equal_phase"
    (Lifecycle.equal_phase Init Init);
  check "not equal_phase"
    (not (Lifecycle.equal_phase Init Established));

  ()

(* --- Summary --- *)

let () =
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "%d/%d passed (%d failed)\n" !pass_count !test_count !fail_count;
  if !fail_count > 0 then exit 1
