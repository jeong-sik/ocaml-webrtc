(** Trickle ICE lifecycle tests (RFC 8838)

    Focus:
    - Local candidate callbacks
    - Remote candidate injection
    - End-of-candidates signaling
    - Restart resets Trickle state
*)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try
    f ();
    incr passed;
    Printf.printf "PASS\n%!"
  with e ->
    incr failed;
    Printf.printf "FAIL (%s)\n%!" (Printexc.to_string e)

let assert_true msg b = if not b then failwith msg

let make_candidate ~foundation ~priority ~address ~port ~cand_type =
  Ice.
    {
      foundation;
      component = 1;
      transport = UDP;
      priority;
      address;
      port;
      cand_type;
      base_address = None;
      base_port = None;
      related_address = None;
      related_port = None;
      extensions = [];
    }

let make_relay_candidate ~foundation ~priority ~address ~port ~base_address ~base_port =
  Ice.
    {
      foundation;
      component = 1;
      transport = UDP;
      priority;
      address;
      port;
      cand_type = Relay;
      base_address = Some base_address;
      base_port = Some base_port;
      related_address = Some base_address;
      related_port = Some base_port;
      extensions = [];
    }

let test_candidate_callbacks () =
  Printf.printf "\n=== Trickle ICE callbacks ===\n";

  test "add_local_candidate triggers callback" (fun () ->
    let agent = Ice.create Ice.default_config in
    let seen = ref [] in
    Ice.on_candidate agent (fun c -> seen := c :: !seen);
    let c1 = make_candidate ~foundation:"f1" ~priority:100
      ~address:"10.0.0.1" ~port:5000 ~cand_type:Host in
    let c2 = make_candidate ~foundation:"f2" ~priority:90
      ~address:"10.0.0.2" ~port:5001 ~cand_type:Host in
    Ice.add_local_candidate agent c1;
    Ice.add_local_candidate agent c2;
    assert_true "two callbacks" (List.length !seen = 2);
    assert_true "agent has candidates" (List.length agent.local_candidates = 2)
  )

let test_remote_injection_and_ordering () =
  Printf.printf "\n=== Remote candidate injection ===\n";

  test "add_remote_candidate creates pairs" (fun () ->
    let agent = Ice.create Ice.default_config in
    let local = make_candidate ~foundation:"l1" ~priority:100
      ~address:"10.0.0.1" ~port:5000 ~cand_type:Host in
    Ice.add_local_candidate agent local;
    let remote = make_candidate ~foundation:"r1" ~priority:120
      ~address:"203.0.113.1" ~port:6000 ~cand_type:Host in
    Ice.add_remote_candidate agent remote;
    assert_true "pair created" (List.length agent.pairs = 1);
    let pair = List.hd agent.pairs in
    let expected = Ice.calculate_pair_priority
      ~controlling_priority:local.priority
      ~controlled_priority:remote.priority
      ~role:(Ice.get_config agent).role
    in
    assert_true "pair priority matches" (pair.pair_priority = expected)
  );

  test "mid-check candidate injection reorders pairs" (fun () ->
    let agent = Ice.create Ice.default_config in
    let local = make_candidate ~foundation:"l1" ~priority:100
      ~address:"10.0.0.1" ~port:5000 ~cand_type:Host in
    Ice.add_local_candidate agent local;
    let r1 = make_candidate ~foundation:"r1" ~priority:100
      ~address:"203.0.113.1" ~port:6000 ~cand_type:Host in
    let r2 = make_candidate ~foundation:"r2" ~priority:200
      ~address:"203.0.113.2" ~port:6002 ~cand_type:Host in
    Ice.add_remote_candidate agent r1;
    Ice.add_remote_candidate agent r2;
    assert_true "two pairs" (List.length agent.pairs = 2);
    let top = List.hd agent.pairs in
    assert_true "higher priority remote first" (top.remote.address = r2.address)
  )

let test_end_of_candidates () =
  Printf.printf "\n=== End-of-candidates ===\n";

  test "set_end_of_candidates fires callback" (fun () ->
    let agent = Ice.create Ice.default_config in
    let called = ref false in
    Ice.on_gathering_complete agent (fun () -> called := true);
    Ice.set_end_of_candidates agent;
    assert_true "callback called" !called;
    assert_true "gathering complete" (Ice.get_gathering_state agent = Ice.Gathering_complete)
  );

  test "remote end-of-candidates resets on restart" (fun () ->
    let agent = Ice.create Ice.default_config in
    let local = make_candidate ~foundation:"l1" ~priority:100
      ~address:"10.0.0.1" ~port:5000 ~cand_type:Host in
    let relay = make_relay_candidate ~foundation:"rly" ~priority:1
      ~address:"192.0.2.10" ~port:7000 ~base_address:"10.0.0.1" ~base_port:5000 in
    Ice.add_local_candidate agent local;
    Ice.add_remote_candidate agent relay;
    Ice.set_remote_end_of_candidates agent;
    assert_true "remote end-of-candidates set" agent.remote_end_of_candidates;
    Ice.restart agent;
    assert_true "remote end-of-candidates reset" (not agent.remote_end_of_candidates);
    assert_true "candidates cleared" (agent.local_candidates = [] && agent.remote_candidates = [])
  )

let () =
  test_candidate_callbacks ();
  test_remote_injection_and_ordering ();
  test_end_of_candidates ();
  Printf.printf "\nTrickle ICE tests: %d passed, %d failed\n" !passed !failed;
  if !failed > 0 then exit 1
