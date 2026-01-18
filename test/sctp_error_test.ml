(** Unit tests for SCTP ERROR Chunk (RFC 4960 §3.2, §3.3.10)

    Tests unknown chunk handling rules and ERROR encoding

    @author Second Brain
*)

(* Use open Webrtc pattern like other tests *)
open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try
    f ();
    incr passed;
    Printf.printf "✅ PASS\n%!"
  with e ->
    incr failed;
    Printf.printf "❌ FAIL (%s)\n%!" (Printexc.to_string e)

let assert_true msg b = if not b then failwith msg
let assert_eq msg a b = if a <> b then failwith (Printf.sprintf "%s: got %d, expected %d" msg a b)

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Unknown Chunk Action (RFC 4960 §3.2)                                       *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_action_determination () =
  Printf.printf "\n═══ Unknown Chunk Action (RFC 4960 §3.2) ═══\n";

  test "Chunk type 0x00-0x3F -> StopDiscard" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 0x15 in
    assert_true "StopDiscard" (action = Sctp_error.StopDiscard)
  );

  test "Chunk type 0x40-0x7F -> StopDiscardReport" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 0x55 in
    assert_true "StopDiscardReport" (action = Sctp_error.StopDiscardReport)
  );

  test "Chunk type 0x80-0xBF -> SkipContinue" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 0x95 in
    assert_true "SkipContinue" (action = Sctp_error.SkipContinue)
  );

  test "Chunk type 0xC0-0xFF -> SkipContinueReport" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 0xD5 in
    assert_true "SkipContinueReport" (action = Sctp_error.SkipContinueReport)
  );

  test "FORWARD-TSN (0xC0) -> SkipContinueReport" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 192 in
    assert_true "FORWARD-TSN is 11" (action = Sctp_error.SkipContinueReport)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Should Report / Should Stop                                                 *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_should_report () =
  Printf.printf "\n═══ Should Report / Should Stop ═══\n";

  test "00 -> not report, should stop" (fun () ->
    assert_true "not report" (not (Sctp_error.should_report 0x10));
    assert_true "should stop" (Sctp_error.should_stop 0x10)
  );

  test "01 -> should report, should stop" (fun () ->
    assert_true "should report" (Sctp_error.should_report 0x50);
    assert_true "should stop" (Sctp_error.should_stop 0x50)
  );

  test "10 -> not report, not stop" (fun () ->
    assert_true "not report" (not (Sctp_error.should_report 0x90));
    assert_true "not stop" (not (Sctp_error.should_stop 0x90))
  );

  test "11 -> should report, not stop" (fun () ->
    assert_true "should report" (Sctp_error.should_report 0xD0);
    assert_true "not stop" (not (Sctp_error.should_stop 0xD0))
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* ERROR Chunk Encoding                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_error_encoding () =
  Printf.printf "\n═══ ERROR Chunk Encoding ═══\n";

  test "encode_unrecognized_chunk_cause produces valid cause" (fun () ->
    let unknown_chunk = Bytes.make 8 '\xAA' in
    let cause = Sctp_error.encode_unrecognized_chunk_cause ~unrecognized_chunk:unknown_chunk in
    assert_true "cause len >= 12" (Bytes.length cause >= 12);
    let cause_code = Bytes.get_uint16_be cause 0 in
    assert_eq "cause code = 6" cause_code 6
  );

  test "encode_error_chunk produces valid chunk" (fun () ->
    let unknown_chunk = Bytes.make 8 '\xBB' in
    let cause = Sctp_error.encode_unrecognized_chunk_cause ~unrecognized_chunk:unknown_chunk in
    let error_chunk = Sctp_error.encode_error_chunk ~causes:[cause] in
    let chunk_type = Bytes.get_uint8 error_chunk 0 in
    assert_eq "chunk type = 9" chunk_type 9
  );

  test "make_unrecognized_chunk_error convenience function" (fun () ->
    let unknown_chunk = Bytes.of_string "\xFF\x00\x00\x08TEST" in
    let error = Sctp_error.make_unrecognized_chunk_error ~unrecognized_chunk:unknown_chunk in
    let chunk_type = Bytes.get_uint8 error 0 in
    assert_eq "type = ERROR" chunk_type 9
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Boundary Cases                                                              *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_boundary_cases () =
  Printf.printf "\n═══ Boundary Cases ═══\n";

  test "Max chunk type 255 -> SkipContinueReport" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 255 in
    assert_true "255 is 11 bits" (action = Sctp_error.SkipContinueReport)
  );

  test "Chunk type 64 boundary -> StopDiscardReport" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 64 in
    assert_true "64 is 01 bits" (action = Sctp_error.StopDiscardReport)
  );

  test "Chunk type 128 boundary -> SkipContinue" (fun () ->
    let action = Sctp_error.action_for_unknown_chunk 128 in
    assert_true "128 is 10 bits" (action = Sctp_error.SkipContinue)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* String Representation                                                       *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_string_repr () =
  Printf.printf "\n═══ String Representation ═══\n";

  test "string_of_action for all actions" (fun () ->
    let actions = [
      Sctp_error.StopDiscard;
      Sctp_error.StopDiscardReport;
      Sctp_error.SkipContinue;
      Sctp_error.SkipContinueReport;
    ] in
    List.iter (fun action ->
      let s = Sctp_error.string_of_action action in
      assert_true ("action string: " ^ s) (String.length s > 0)
    ) actions
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main                                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     SCTP ERROR Unit Tests (RFC 4960 §3.2, §3.3.10)           ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";

  test_action_determination ();
  test_should_report ();
  test_error_encoding ();
  test_boundary_cases ();
  test_string_repr ();

  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";

  if !failed > 0 then exit 1
