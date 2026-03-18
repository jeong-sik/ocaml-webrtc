(** Replay tests — verifying Sctp_core determinism *)

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

let config =
  { Replay_harness.src_port = 5000
  ; dst_port = 5000
  ; initial_tsn = 1000l
  ; my_vtag = 0x12345678l
  ; steps = []
  }
;;

(* --- Empty sequence --- *)

let () =
  Printf.printf "=== Empty Sequence ===\n";
  let trace =
    Replay_harness.record
      ~src_port:5000
      ~dst_port:5000
      ~initial_tsn:1000l
      ~my_vtag:0x12345678l
      []
  in
  check "empty trace records 0 steps" (List.length trace.steps = 0);
  check "empty trace replays OK" (Replay_harness.verify trace = Ok ());
  ()
;;

(* --- Initiate handshake --- *)

let () =
  Printf.printf "\n=== Initiate Handshake ===\n";
  let t =
    Sctp_core.create
      ~src_port:5000
      ~dst_port:5000
      ~initial_tsn:1000l
      ~my_vtag:0x12345678l
      ()
  in
  Sctp_core.set_now t 0.0;
  let init_outputs = Sctp_core.initiate t in
  check "initiate produces outputs" (List.length init_outputs > 0);
  (* The initiate outputs contain a SendPacket — use that as replay input *)
  let init_packet =
    List.find_map
      (fun o ->
         match o with
         | Sctp_core.SendPacket p -> Some p
         | _ -> None)
      init_outputs
  in
  check "initiate sends a packet" (Option.is_some init_packet);
  ()
;;

(* --- Timer fire replay --- *)

let () =
  Printf.printf "\n=== Timer Fire Replay ===\n";
  let inputs =
    Sctp_core.[ TimerFired T3Rtx; TimerFired DelayedAck; TimerFired Heartbeat ]
  in
  let trace =
    Replay_harness.record
      ~src_port:5000
      ~dst_port:5000
      ~initial_tsn:1000l
      ~my_vtag:0x12345678l
      inputs
  in
  check "3 steps recorded" (List.length trace.steps = 3);
  (match Replay_harness.verify trace with
   | Ok () -> check "timer replay deterministic" true
   | Error (idx, _, _) ->
     check (Printf.sprintf "timer replay failed at step %d" idx) false);
  ()
;;

(* --- Packet input replay --- *)

let () =
  Printf.printf "\n=== Packet Input Replay ===\n";
  let inputs =
    [ Sctp_core.PacketReceived Bytes.empty
    ; Sctp_core.PacketReceived (Fault_injection.garbage_packet ~len:50)
    ; Sctp_core.PacketReceived (Fault_injection.too_short_header ())
    ; Sctp_core.PacketReceived (Fault_injection.valid_header ())
    ]
  in
  let trace =
    Replay_harness.record
      ~src_port:5000
      ~dst_port:5000
      ~initial_tsn:1000l
      ~my_vtag:0x12345678l
      inputs
  in
  check "4 steps recorded" (List.length trace.steps = 4);
  (match Replay_harness.verify trace with
   | Ok () -> check "packet replay deterministic" true
   | Error (idx, _, _) ->
     check (Printf.sprintf "packet replay failed at step %d" idx) false);
  ()
;;

(* --- Mixed inputs replay --- *)

let () =
  Printf.printf "\n=== Mixed Inputs Replay ===\n";
  let inputs =
    Sctp_core.
      [ PacketReceived Bytes.empty
      ; TimerFired T3Rtx
      ; PacketReceived (Bytes.of_string "hello")
      ; TimerFired DelayedAck
      ; UserSend { stream_id = 0; data = Bytes.of_string "test" }
      ; TimerFired Heartbeat
      ; PacketReceived (Fault_injection.garbage_packet ~len:200)
      ; UserClose
      ]
  in
  let trace =
    Replay_harness.record
      ~src_port:5000
      ~dst_port:5000
      ~initial_tsn:42l
      ~my_vtag:0xDEADBEEFl
      inputs
  in
  check "8 steps recorded" (List.length trace.steps = 8);
  (match Replay_harness.verify trace with
   | Ok () -> check "mixed replay deterministic" true
   | Error (idx, _, _) ->
     check (Printf.sprintf "mixed replay failed at step %d" idx) false);
  ()
;;

(* --- Triple replay (replay 3 times, all match) --- *)

let () =
  Printf.printf "\n=== Triple Replay ===\n";
  let inputs =
    Sctp_core.
      [ PacketReceived (Fault_injection.garbage_packet ~len:100)
      ; TimerFired T3Rtx
      ; TimerFired Shutdown
      ]
  in
  let trace =
    Replay_harness.record ~src_port:5000 ~dst_port:5000 ~initial_tsn:1l ~my_vtag:1l inputs
  in
  let r1 = Replay_harness.verify trace in
  let r2 = Replay_harness.verify trace in
  let r3 = Replay_harness.verify trace in
  check "replay 1 OK" (r1 = Ok ());
  check "replay 2 OK" (r2 = Ok ());
  check "replay 3 OK" (r3 = Ok ());
  ()
;;

(* --- output_equal unit tests --- *)

let () =
  Printf.printf "\n=== Output Equality ===\n";
  check
    "SendPacket equal"
    (Replay_harness.output_equal
       (SendPacket (Bytes.of_string "abc"))
       (SendPacket (Bytes.of_string "abc")));
  check
    "SendPacket diff"
    (not
       (Replay_harness.output_equal
          (SendPacket (Bytes.of_string "abc"))
          (SendPacket (Bytes.of_string "xyz"))));
  check "Error equal" (Replay_harness.output_equal (Error "x") (Error "x"));
  check "Error diff" (not (Replay_harness.output_equal (Error "x") (Error "y")));
  check
    "cross-type diff"
    (not (Replay_harness.output_equal ConnectionEstablished ConnectionClosed));
  check "pp_divergence" (String.length (Replay_harness.pp_divergence 0 [] []) > 0);
  ignore config;
  ()
;;

(* --- Summary --- *)

let () =
  Printf.printf "\n=== Summary ===\n";
  Printf.printf "%d/%d passed (%d failed)\n" !pass_count !test_count !fail_count;
  if !fail_count > 0 then exit 1
;;
