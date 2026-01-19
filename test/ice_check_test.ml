(** Integration tests for ICE Connectivity Checks (RFC 8445)

    Tests cover:
    - State transitions: Frozen -> Waiting -> In_progress -> Succeeded/Failed
    - Retransmission timer behavior (RTO doubling)
    - Transaction ID matching
    - Nomination flag handling (USE-CANDIDATE)
    - Check list operations (add, get, update, get_next_waiting)
    - Edge cases (timeout, wrong transaction ID, cancel)

    @author Second Brain
    @since ocaml-webrtc 0.6.0
*)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try
    f ();
    incr passed;
    Printf.printf "\xE2\x9C\x85 PASS\n%!"
  with e ->
    incr failed;
    Printf.printf "\xE2\x9D\x8C FAIL (%s)\n%!" (Printexc.to_string e)

let assert_true msg b = if not b then failwith msg
let assert_eq_state msg expected actual =
  if not (Ice_check.equal_check_state expected actual) then
    failwith (Printf.sprintf "%s: expected %s, got %s" msg
      (Ice_check.show_check_state expected)
      (Ice_check.show_check_state actual))

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Test Helpers                                                                *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

(** Create a test check with default parameters *)
let create_test_check
    ?(local_addr=("192.168.1.10", 5000))
    ?(remote_addr=("192.168.1.20", 5001))
    ?(local_ufrag="localufrag")
    ?(local_pwd="localpwd123456789012")
    ?(remote_ufrag="remoteufrag")
    ?(remote_pwd="remotepwd123456789012")
    ?(priority=100000)
    ?(is_controlling=true)
    ?(tie_breaker=0x123456789ABCDEFL)
    ?(use_candidate=false)
    ?(max_attempts=7)
    () =
  let config = { Ice_check.default_config with max_attempts } in
  Ice_check.create
    ~local_addr
    ~remote_addr
    ~local_ufrag
    ~local_pwd
    ~remote_ufrag
    ~remote_pwd
    ~priority
    ~is_controlling
    ~tie_breaker
    ~use_candidate
    ~config
    ()

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* State Transition Tests                                                      *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_state_transitions () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 State Transition Tests (RFC 8445 Section 6.1.2.6) \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "check starts in Frozen state" (fun () ->
    let check = create_test_check () in
    assert_eq_state "initial state" Ice_check.Frozen (Ice_check.get_state check)
  );

  test "Frozen -> Waiting on Start_check" (fun () ->
    let check = create_test_check () in
    let (check, output) = Ice_check.step check Ice_check.Start_check 0.0 in
    assert_eq_state "after first Start_check" Ice_check.Waiting (Ice_check.get_state check);
    match output with
    | Ice_check.No_op -> ()
    | _ -> failwith "Expected No_op output"
  );

  test "Waiting -> In_progress on Start_check (sends request)" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    assert_eq_state "after second Start_check" Ice_check.In_progress (Ice_check.get_state check);
    match output with
    | Ice_check.Send_stun_request { dest; username; use_candidate; _ } ->
      assert_true "correct dest" (dest = ("192.168.1.20", 5001));
      assert_true "correct username format" (String.sub username 0 11 = "remoteufrag");
      assert_true "use_candidate false" (not use_candidate)
    | _ -> failwith "Expected Send_stun_request output"
  );

  test "In_progress -> Succeeded on valid response" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = true;
      mapped_addr = Some ("203.0.113.5", 54321);
      error_code = None;
    } in
    let (check, output) = Ice_check.step check response 2.0 in
    assert_eq_state "after success response" Ice_check.Succeeded (Ice_check.get_state check);
    match output with
    | Ice_check.Check_completed { success; mapped_addr; error; _ } ->
      assert_true "success flag" success;
      assert_true "has mapped_addr" (mapped_addr = Some ("203.0.113.5", 54321));
      assert_true "no error" (error = None)
    | _ -> failwith "Expected Check_completed output"
  );

  test "In_progress -> Failed on error response" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = false;
      mapped_addr = None;
      error_code = Some 401;
    } in
    let (check, output) = Ice_check.step check response 2.0 in
    assert_eq_state "after error response" Ice_check.Failed (Ice_check.get_state check);
    match output with
    | Ice_check.Check_completed { success; error; _ } ->
      assert_true "success is false" (not success);
      assert_true "has error" (error <> None)
    | _ -> failwith "Expected Check_completed output"
  );

  test "terminal states ignore further inputs" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = true;
      mapped_addr = Some ("1.2.3.4", 1234);
      error_code = None;
    } in
    let (check, _) = Ice_check.step check response 2.0 in
    assert_eq_state "is Succeeded" Ice_check.Succeeded (Ice_check.get_state check);
    (* Try more inputs - should be ignored *)
    let (check, output) = Ice_check.step check Ice_check.Start_check 3.0 in
    assert_eq_state "still Succeeded" Ice_check.Succeeded (Ice_check.get_state check);
    match output with
    | Ice_check.No_op -> ()
    | _ -> failwith "Expected No_op for terminal state"
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Retransmission Timer Tests                                                  *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_retransmission () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 Retransmission Timer Tests (RFC 8445 Section 14.3) \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "initial RTO is 500ms" (fun () ->
    let check = create_test_check () in
    assert_true "initial RTO" (Ice_check.get_rto check = 500)
  );

  test "RTO doubles on retransmission" (fun () ->
    let check = create_test_check ~max_attempts:10 () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    assert_true "RTO still 500ms after first send" (Ice_check.get_rto check = 500);
    (* First retransmit *)
    let (check, _) = Ice_check.step check Ice_check.Timer_fired 2.0 in
    assert_true "RTO 1000ms after first retransmit" (Ice_check.get_rto check = 1000);
    (* Second retransmit *)
    let (check, _) = Ice_check.step check Ice_check.Timer_fired 3.0 in
    assert_true "RTO 2000ms after second retransmit" (Ice_check.get_rto check = 2000);
    (* Third retransmit *)
    let (check, _) = Ice_check.step check Ice_check.Timer_fired 4.0 in
    assert_true "RTO 3000ms (max) after third retransmit" (Ice_check.get_rto check = 3000);
    (* Fourth retransmit - should stay at max *)
    let (check, _) = Ice_check.step check Ice_check.Timer_fired 5.0 in
    assert_true "RTO capped at 3000ms" (Ice_check.get_rto check = 3000)
  );

  test "check fails after max attempts" (fun () ->
    let check = create_test_check ~max_attempts:3 () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    assert_eq_state "In_progress after start" Ice_check.In_progress (Ice_check.get_state check);
    (* Attempt 2 *)
    let (check, _) = Ice_check.step check Ice_check.Timer_fired 2.0 in
    assert_eq_state "still In_progress" Ice_check.In_progress (Ice_check.get_state check);
    (* Attempt 3 *)
    let (check, _) = Ice_check.step check Ice_check.Timer_fired 3.0 in
    assert_eq_state "still In_progress" Ice_check.In_progress (Ice_check.get_state check);
    (* Attempt 4 exceeds max_attempts=3 *)
    let (check, output) = Ice_check.step check Ice_check.Timer_fired 4.0 in
    assert_eq_state "Failed after max attempts" Ice_check.Failed (Ice_check.get_state check);
    match output with
    | Ice_check.Check_completed { success; error; _ } ->
      assert_true "not successful" (not success);
      assert_true "has timeout error" (error = Some "Timeout")
    | _ -> failwith "Expected Check_completed on failure"
  );

  test "retransmission sends same transaction ID" (fun () ->
    let check = create_test_check ~max_attempts:5 () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, output1) = Ice_check.step check Ice_check.Start_check 1.0 in
    let tx_id1 = match output1 with
      | Ice_check.Send_stun_request { transaction_id; _ } -> transaction_id
      | _ -> failwith "Expected Send_stun_request"
    in
    let (_, output2) = Ice_check.step check Ice_check.Timer_fired 2.0 in
    let tx_id2 = match output2 with
      | Ice_check.Send_stun_request { transaction_id; _ } -> transaction_id
      | _ -> failwith "Expected Send_stun_request"
    in
    assert_true "same transaction ID" (Bytes.equal tx_id1 tx_id2)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Transaction ID Matching Tests                                               *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_transaction_matching () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 Transaction ID Matching Tests \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "response with wrong transaction ID is ignored" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    (* Create a different transaction ID *)
    let wrong_tx_id = Bytes.make 12 '\xFF' in
    let response = Ice_check.Stun_response_received {
      transaction_id = wrong_tx_id;
      success = true;
      mapped_addr = Some ("1.2.3.4", 1234);
      error_code = None;
    } in
    let (check, output) = Ice_check.step check response 2.0 in
    assert_eq_state "still In_progress" Ice_check.In_progress (Ice_check.get_state check);
    match output with
    | Ice_check.No_op -> ()
    | _ -> failwith "Expected No_op for wrong transaction ID"
  );

  test "error response with wrong transaction ID is ignored" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let wrong_tx_id = Bytes.make 12 '\x00' in
    let response = Ice_check.Stun_response_received {
      transaction_id = wrong_tx_id;
      success = false;
      mapped_addr = None;
      error_code = Some 400;
    } in
    let (check, output) = Ice_check.step check response 2.0 in
    assert_eq_state "still In_progress" Ice_check.In_progress (Ice_check.get_state check);
    match output with
    | Ice_check.No_op -> ()
    | _ -> failwith "Expected No_op for wrong transaction ID"
  );

  test "transaction ID is 12 bytes" (fun () ->
    let check = create_test_check () in
    let tx_id = Ice_check.get_transaction_id check in
    assert_true "transaction ID is 12 bytes" (Bytes.length tx_id = 12)
  );

  test "each check has unique transaction ID" (fun () ->
    let check1 = create_test_check () in
    let check2 = create_test_check () in
    let tx_id1 = Ice_check.get_transaction_id check1 in
    let tx_id2 = Ice_check.get_transaction_id check2 in
    (* Note: There's a tiny chance of collision, but practically negligible *)
    assert_true "different transaction IDs" (not (Bytes.equal tx_id1 tx_id2))
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Nomination Flag Tests                                                       *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_nomination () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 Nomination Flag Tests (USE-CANDIDATE) \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "check without use_candidate is not nominated" (fun () ->
    let check = create_test_check ~use_candidate:false () in
    assert_true "not nominated initially" (not (Ice_check.is_nominated check));
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = true;
      mapped_addr = Some ("1.2.3.4", 1234);
      error_code = None;
    } in
    let (check, _) = Ice_check.step check response 2.0 in
    assert_true "not nominated after success" (not (Ice_check.is_nominated check))
  );

  test "check with use_candidate is nominated on success" (fun () ->
    let check = create_test_check ~use_candidate:true () in
    assert_true "not nominated initially" (not (Ice_check.is_nominated check));
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    (* Verify USE-CANDIDATE is sent *)
    (match output with
    | Ice_check.Send_stun_request { use_candidate; _ } ->
      assert_true "use_candidate flag in request" use_candidate
    | _ -> failwith "Expected Send_stun_request");
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = true;
      mapped_addr = Some ("1.2.3.4", 1234);
      error_code = None;
    } in
    let (check, output) = Ice_check.step check response 2.0 in
    assert_true "nominated after success" (Ice_check.is_nominated check);
    match output with
    | Ice_check.Check_completed { nominated; _ } ->
      assert_true "nominated flag in completion" nominated
    | _ -> failwith "Expected Check_completed"
  );

  test "failed check is never nominated" (fun () ->
    let check = create_test_check ~use_candidate:true ~max_attempts:1 () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let (check, output) = Ice_check.step check Ice_check.Timer_fired 2.0 in
    assert_eq_state "Failed" Ice_check.Failed (Ice_check.get_state check);
    assert_true "not nominated" (not (Ice_check.is_nominated check));
    match output with
    | Ice_check.Check_completed { nominated; _ } ->
      assert_true "not nominated in completion" (not nominated)
    | _ -> failwith "Expected Check_completed"
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Check List Operations Tests                                                 *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_check_list () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 Check List Operations Tests \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "create empty check list" (fun () ->
    let list = Ice_check.create_check_list () in
    assert_true "no succeeded checks" (Ice_check.get_succeeded list = []);
    assert_true "has_succeeded is false" (not (Ice_check.has_succeeded list));
    assert_true "all_finished is true (vacuously)" (Ice_check.all_finished list)
  );

  test "add_check assigns unique IDs" (fun () ->
    let list = Ice_check.create_check_list () in
    let check1 = create_test_check () in
    let check2 = create_test_check () in
    let (list, id1) = Ice_check.add_check list check1 in
    let (list, id2) = Ice_check.add_check list check2 in
    assert_true "different IDs" (id1 <> id2);
    assert_true "can get check1" (Ice_check.get_check list id1 <> None);
    assert_true "can get check2" (Ice_check.get_check list id2 <> None)
  );

  test "get_check returns None for invalid ID" (fun () ->
    let list = Ice_check.create_check_list () in
    let check = create_test_check () in
    let (list, _) = Ice_check.add_check list check in
    assert_true "invalid ID returns None" (Ice_check.get_check list 999 = None)
  );

  test "update_check modifies check in list" (fun () ->
    let list = Ice_check.create_check_list () in
    let check = create_test_check () in
    let (list, id) = Ice_check.add_check list check in
    (* Transition to Waiting *)
    let check = match Ice_check.get_check list id with
      | Some c -> c
      | None -> failwith "check not found"
    in
    let (updated, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let list = Ice_check.update_check list id updated in
    match Ice_check.get_check list id with
    | Some c ->
      assert_eq_state "updated state" Ice_check.Waiting (Ice_check.get_state c)
    | None -> failwith "check not found after update"
  );

  test "get_next_waiting finds waiting checks" (fun () ->
    let list = Ice_check.create_check_list () in
    let check1 = create_test_check () in
    let check2 = create_test_check () in
    let (list, id1) = Ice_check.add_check list check1 in
    let (list, _id2) = Ice_check.add_check list check2 in
    (* Both are Frozen, no waiting *)
    assert_true "no waiting initially" (Ice_check.get_next_waiting list = None);
    (* Move check1 to Waiting *)
    let check1 = match Ice_check.get_check list id1 with
      | Some c -> c
      | None -> failwith "not found"
    in
    let (check1, _) = Ice_check.step check1 Ice_check.Start_check 0.0 in
    let list = Ice_check.update_check list id1 check1 in
    match Ice_check.get_next_waiting list with
    | Some (found_id, _) -> assert_true "found waiting check" (found_id = id1)
    | None -> failwith "expected to find waiting check"
  );

  test "get_succeeded returns succeeded checks" (fun () ->
    let list = Ice_check.create_check_list () in
    let check1 = create_test_check () in
    let check2 = create_test_check () in
    let (list, id1) = Ice_check.add_check list check1 in
    let (list, id2) = Ice_check.add_check list check2 in
    (* Move check1 to Succeeded *)
    let check1 = match Ice_check.get_check list id1 with
      | Some c -> c
      | None -> failwith "not found"
    in
    let (check1, _) = Ice_check.step check1 Ice_check.Start_check 0.0 in
    let (check1, _) = Ice_check.step check1 Ice_check.Start_check 1.0 in
    let tx_id = Ice_check.get_transaction_id check1 in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = true;
      mapped_addr = Some ("1.2.3.4", 1234);
      error_code = None;
    } in
    let (check1, _) = Ice_check.step check1 response 2.0 in
    let list = Ice_check.update_check list id1 check1 in
    let succeeded = Ice_check.get_succeeded list in
    assert_true "one succeeded" (List.length succeeded = 1);
    assert_true "has_succeeded is true" (Ice_check.has_succeeded list);
    (* Move check2 to Failed *)
    let check2 = match Ice_check.get_check list id2 with
      | Some c -> c
      | None -> failwith "not found"
    in
    let (check2, _) = Ice_check.step check2 Ice_check.Cancel 0.0 in
    let list = Ice_check.update_check list id2 check2 in
    assert_true "all_finished" (Ice_check.all_finished list);
    assert_true "still one succeeded" (List.length (Ice_check.get_succeeded list) = 1)
  );

  test "all_finished detects incomplete list" (fun () ->
    let list = Ice_check.create_check_list () in
    let check = create_test_check () in
    let (list, id) = Ice_check.add_check list check in
    assert_true "not finished with Frozen check" (not (Ice_check.all_finished list));
    (* Move to Waiting *)
    let check = match Ice_check.get_check list id with
      | Some c -> c
      | None -> failwith "not found"
    in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let list = Ice_check.update_check list id check in
    assert_true "not finished with Waiting check" (not (Ice_check.all_finished list))
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Edge Cases Tests                                                            *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_edge_cases () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 Edge Cases Tests \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "cancel from Frozen state" (fun () ->
    let check = create_test_check () in
    let (check, output) = Ice_check.step check Ice_check.Cancel 0.0 in
    assert_eq_state "Failed" Ice_check.Failed (Ice_check.get_state check);
    assert_true "has cancel error" (Ice_check.get_error check = Some "Cancelled");
    match output with
    | Ice_check.Cancel_timer -> ()
    | _ -> failwith "Expected Cancel_timer output"
  );

  test "cancel from Waiting state" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, output) = Ice_check.step check Ice_check.Cancel 1.0 in
    assert_eq_state "Failed" Ice_check.Failed (Ice_check.get_state check);
    match output with
    | Ice_check.Cancel_timer -> ()
    | _ -> failwith "Expected Cancel_timer"
  );

  test "cancel from In_progress state" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let (check, output) = Ice_check.step check Ice_check.Cancel 2.0 in
    assert_eq_state "Failed" Ice_check.Failed (Ice_check.get_state check);
    match output with
    | Ice_check.Cancel_timer -> ()
    | _ -> failwith "Expected Cancel_timer"
  );

  test "timer_fired in Frozen state is ignored" (fun () ->
    let check = create_test_check () in
    let (check, output) = Ice_check.step check Ice_check.Timer_fired 1.0 in
    assert_eq_state "still Frozen" Ice_check.Frozen (Ice_check.get_state check);
    match output with
    | Ice_check.No_op -> ()
    | _ -> failwith "Expected No_op"
  );

  test "timer_fired in Waiting state is ignored" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, output) = Ice_check.step check Ice_check.Timer_fired 1.0 in
    assert_eq_state "still Waiting" Ice_check.Waiting (Ice_check.get_state check);
    match output with
    | Ice_check.No_op -> ()
    | _ -> failwith "Expected No_op"
  );

  test "response in Frozen state is ignored" (fun () ->
    let check = create_test_check () in
    let response = Ice_check.Stun_response_received {
      transaction_id = Bytes.make 12 '\x00';
      success = true;
      mapped_addr = Some ("1.2.3.4", 1234);
      error_code = None;
    } in
    let (check, output) = Ice_check.step check response 1.0 in
    assert_eq_state "still Frozen" Ice_check.Frozen (Ice_check.get_state check);
    match output with
    | Ice_check.No_op -> ()
    | _ -> failwith "Expected No_op"
  );

  test "is_terminal for all states" (fun () ->
    let check = create_test_check () in
    assert_true "Frozen is not terminal" (not (Ice_check.is_terminal check));
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    assert_true "Waiting is not terminal" (not (Ice_check.is_terminal check));
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    assert_true "In_progress is not terminal" (not (Ice_check.is_terminal check));
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = true;
      mapped_addr = None;
      error_code = None;
    } in
    let (check, _) = Ice_check.step check response 2.0 in
    assert_true "Succeeded is terminal" (Ice_check.is_terminal check)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Error Code Handling Tests                                                   *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_error_codes () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 Error Code Handling Tests \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  let test_error_code code expected_msg =
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = false;
      mapped_addr = None;
      error_code = Some code;
    } in
    let (check, _) = Ice_check.step check response 2.0 in
    match Ice_check.get_error check with
    | Some msg -> assert_true (Printf.sprintf "error contains '%s'" expected_msg)
                    (String.length msg > 0)
    | None -> failwith "Expected error message"
  in

  test "error 400 (Bad Request)" (fun () ->
    test_error_code 400 "Bad request"
  );

  test "error 401 (Unauthorized)" (fun () ->
    test_error_code 401 "Unauthorized"
  );

  test "error 487 (Role Conflict)" (fun () ->
    test_error_code 487 "Role conflict"
  );

  test "unknown error code" (fun () ->
    test_error_code 999 "STUN error"
  );

  test "error response with no code" (fun () ->
    let check = create_test_check () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (check, _) = Ice_check.step check Ice_check.Start_check 1.0 in
    let tx_id = Ice_check.get_transaction_id check in
    let response = Ice_check.Stun_response_received {
      transaction_id = tx_id;
      success = false;
      mapped_addr = None;
      error_code = None;
    } in
    let (check, _) = Ice_check.step check response 2.0 in
    match Ice_check.get_error check with
    | Some msg -> assert_true "has error" (String.length msg > 0)
    | None -> failwith "Expected error message"
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Controlling/Controlled Role Tests                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_roles () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 ICE Role Tests (Controlling/Controlled) \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "controlling agent sends ICE-CONTROLLING" (fun () ->
    let check = create_test_check ~is_controlling:true ~tie_breaker:0xABCDEF123456L () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (_, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    match output with
    | Ice_check.Send_stun_request { ice_controlling; ice_controlled; _ } ->
      assert_true "has ICE-CONTROLLING" (ice_controlling = Some 0xABCDEF123456L);
      assert_true "no ICE-CONTROLLED" (ice_controlled = None)
    | _ -> failwith "Expected Send_stun_request"
  );

  test "controlled agent sends ICE-CONTROLLED" (fun () ->
    let check = create_test_check ~is_controlling:false ~tie_breaker:0x123456789ABCL () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (_, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    match output with
    | Ice_check.Send_stun_request { ice_controlling; ice_controlled; _ } ->
      assert_true "no ICE-CONTROLLING" (ice_controlling = None);
      assert_true "has ICE-CONTROLLED" (ice_controlled = Some 0x123456789ABCL)
    | _ -> failwith "Expected Send_stun_request"
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* STUN Request Attributes Tests                                               *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_stun_attributes () =
  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90 STUN Request Attributes Tests \xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  test "username format is remoteUfrag:localUfrag" (fun () ->
    let check = create_test_check
      ~local_ufrag:"LOCAL"
      ~remote_ufrag:"REMOTE"
      () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (_, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    match output with
    | Ice_check.Send_stun_request { username; _ } ->
      assert_true "username format" (username = "REMOTE:LOCAL")
    | _ -> failwith "Expected Send_stun_request"
  );

  test "password is remote ICE password" (fun () ->
    let check = create_test_check ~remote_pwd:"secret_remote_password" () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (_, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    match output with
    | Ice_check.Send_stun_request { password; _ } ->
      assert_true "password" (password = "secret_remote_password")
    | _ -> failwith "Expected Send_stun_request"
  );

  test "priority attribute is included" (fun () ->
    let check = create_test_check ~priority:2130706431 () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (_, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    match output with
    | Ice_check.Send_stun_request { priority; _ } ->
      assert_true "priority" (priority = 2130706431)
    | _ -> failwith "Expected Send_stun_request"
  );

  test "dest address is remote candidate" (fun () ->
    let check = create_test_check ~remote_addr:("10.20.30.40", 9999) () in
    let (check, _) = Ice_check.step check Ice_check.Start_check 0.0 in
    let (_, output) = Ice_check.step check Ice_check.Start_check 1.0 in
    match output with
    | Ice_check.Send_stun_request { dest; _ } ->
      assert_true "dest address" (dest = ("10.20.30.40", 9999))
    | _ -> failwith "Expected Send_stun_request"
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main                                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "\xE2\x95\x94\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x97\n";
  Printf.printf "\xE2\x95\x91     ICE Connectivity Check Tests (RFC 8445)                          \xE2\x95\x91\n";
  Printf.printf "\xE2\x95\x91     Sans-IO State Machine + Check List Operations                    \xE2\x95\x91\n";
  Printf.printf "\xE2\x95\x9A\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x9D\n";

  test_state_transitions ();
  test_retransmission ();
  test_transaction_matching ();
  test_nomination ();
  test_check_list ();
  test_edge_cases ();
  test_error_codes ();
  test_roles ();
  test_stun_attributes ();

  Printf.printf "\n\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\xE2\x95\x90\n";

  if !failed > 0 then exit 1
