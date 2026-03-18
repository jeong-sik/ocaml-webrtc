(** E2E harness integration test

    Combines all harness modules in a single scenario:
    1. Lifecycle: advance through phases
    2. Fault injection: feed corrupted packets
    3. Error classification: verify error categories
    4. Replay: verify determinism
    5. Lifecycle failure: cleanup on error

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

let cleanup_log : string list ref = ref []
let make_cleanup label () = cleanup_log := !cleanup_log @ [ label ]

(* --- Scenario 1: Normal lifecycle with fault injection --- *)

let () =
  Printf.printf "=== Scenario 1: Lifecycle + Fault Injection ===\n";
  cleanup_log := [];
  (* Create lifecycle *)
  let lc = Lifecycle.create () in
  let _ =
    Lifecycle.advance lc ~phase:Lifecycle.Ice_gathering ~cleanup:(make_cleanup "ice")
  in
  let _ =
    Lifecycle.advance lc ~phase:Lifecycle.Dtls_handshake ~cleanup:(make_cleanup "dtls")
  in
  let _ =
    Lifecycle.advance lc ~phase:Lifecycle.Sctp_association ~cleanup:(make_cleanup "sctp")
  in
  check
    "lifecycle at Sctp_association"
    (Lifecycle.current_phase lc = Lifecycle.Sctp_association);
  (* Create SCTP core and feed it garbage *)
  let t = Sctp_core.create ~src_port:5000 ~dst_port:5000 () in
  let garbage = Fault_injection.garbage_packet ~len:500 in
  let outputs = Sctp_core.handle t (PacketReceived garbage) in
  check "garbage packet no crash" true;
  (* Classify any errors *)
  let errors = Fault_injection.errors_of outputs in
  List.iter
    (fun msg ->
       let err = Oas_error.of_string msg in
       check
         (Printf.sprintf "error '%s' classified" msg)
         (err.cls = Protocol || err.cls = Fatal || err.cls = Transient || err.cls = Config))
    errors;
  (* Simulate SCTP failure *)
  let failure = Lifecycle.fail lc ~error:"CRC32c mismatch" in
  check "failure classified as Protocol" (failure.error.cls = Protocol);
  check "3 cleanups ran" (List.length !cleanup_log = 3);
  check "cleanup order: sctp, dtls, ice" (!cleanup_log = [ "sctp"; "dtls"; "ice" ]);
  ()
;;

(* --- Scenario 2: Replay through fault injection --- *)

let () =
  Printf.printf "\n=== Scenario 2: Replay + Fault Injection ===\n";
  let inputs =
    Sctp_core.
      [ PacketReceived (Fault_injection.garbage_packet ~len:10)
      ; PacketReceived (Fault_injection.too_short_header ())
      ; PacketReceived Bytes.empty
      ; TimerFired T3Rtx
      ; PacketReceived (Fault_injection.garbage_packet ~len:200)
      ; UserClose
      ]
  in
  let trace =
    Replay_harness.record
      ~src_port:5000
      ~dst_port:5000
      ~initial_tsn:999l
      ~my_vtag:0xCAFEBABEl
      inputs
  in
  check "6 steps recorded" (List.length trace.steps = 6);
  (* Verify determinism *)
  (match Replay_harness.verify trace with
   | Ok () -> check "fault injection replay deterministic" true
   | Error (idx, _, _) -> check (Printf.sprintf "replay failed at step %d" idx) false);
  (* Verify all errors are properly classified *)
  let all_errors =
    List.concat_map
      (fun step -> Fault_injection.errors_of step.Replay_harness.outputs)
      trace.steps
  in
  check "some errors produced" (List.length all_errors > 0);
  List.iter
    (fun msg ->
       let err = Oas_error.of_string msg in
       check
         (Printf.sprintf
            "replay error classified: %s"
            (Oas_error.show_error_class err.cls))
         true)
    all_errors;
  ()
;;

(* --- Scenario 3: Lifecycle phases with error classification --- *)

let () =
  Printf.printf "\n=== Scenario 3: Phase failure classification ===\n";
  let test_cases =
    [ "Association aborted by peer", Oas_error.Fatal
    ; "Congestion window full", Oas_error.Transient
    ; "CRC32c mismatch", Oas_error.Protocol
    ; "RE-CONFIG requires Established state", Oas_error.Config
    ]
  in
  List.iter
    (fun (error_msg, expected_cls) ->
       cleanup_log := [];
       let lc = Lifecycle.create () in
       let _ =
         Lifecycle.advance lc ~phase:Lifecycle.Ice_gathering ~cleanup:(make_cleanup "ice")
       in
       let failure = Lifecycle.fail lc ~error:error_msg in
       check
         (Printf.sprintf "'%s' → %s" error_msg (Oas_error.show_error_class expected_cls))
         (failure.error.cls = expected_cls);
       check (Printf.sprintf "'%s' cleanup ran" error_msg) (List.length !cleanup_log = 1))
    test_cases;
  ()
;;

(* --- Scenario 4: Full stack from Init to failure --- *)

let () =
  Printf.printf "\n=== Scenario 4: Full lifecycle + SCTP + replay ===\n";
  cleanup_log := [];
  let lc = Lifecycle.create () in
  let phases =
    [ Lifecycle.Ice_gathering, "ice"
    ; Lifecycle.Dtls_handshake, "dtls"
    ; Lifecycle.Sctp_association, "sctp"
    ; Lifecycle.Data_channel, "dcep"
    ; Lifecycle.Established, "established"
    ]
  in
  List.iter
    (fun (phase, label) ->
       match Lifecycle.advance lc ~phase ~cleanup:(make_cleanup label) with
       | Ok () -> check (Printf.sprintf "advance to %s" label) true
       | Error e -> check (Printf.sprintf "advance to %s: %s" label e) false)
    phases;
  check "is established" (Lifecycle.is_established lc);
  (* Run SCTP with various inputs *)
  let t = Sctp_core.create ~src_port:5000 ~dst_port:5000 () in
  for i = 0 to 9 do
    let packet = Fault_injection.garbage_packet ~len:((i * 50) + 1) in
    let _ = Sctp_core.handle t (PacketReceived packet) in
    ()
  done;
  check "10 garbage packets survived" true;
  (* Fatal failure tears down *)
  let failure = Lifecycle.fail lc ~error:"Shutdown timeout" in
  check "fatal failure" (failure.error.cls = Fatal);
  check "5 cleanups ran" (List.length !cleanup_log = 5);
  check
    "cleanup order newest first"
    (!cleanup_log = [ "established"; "dcep"; "sctp"; "dtls"; "ice" ]);
  ()
;;

(* --- Summary --- *)

let () =
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "%d/%d passed (%d failed)\n" !pass_count !test_count !fail_count;
  if !fail_count > 0 then exit 1
;;
