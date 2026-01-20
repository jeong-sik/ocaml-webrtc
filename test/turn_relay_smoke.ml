(** TURN relay smoke test (interop, opt-in)

    Usage:
      TURN_SERVER=host:port dune exec ./test/turn_relay_smoke.exe

    Notes:
      - Uses unauthenticated TURN Allocate via STUN (no-auth TURN server).
      - Skips when TURN_SERVER is not set.
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

let normalize_turn_url raw =
  if String.length raw >= 5 && String.sub raw 0 5 = "turn:" then raw
  else if String.length raw >= 6 && String.sub raw 0 6 = "turns:" then raw
  else "turn:" ^ raw

let () =
  match Sys.getenv_opt "TURN_SERVER" with
  | None ->
    Printf.printf "SKIP: TURN_SERVER not set\n";
    exit 0
  | Some server ->
    let turn_url = normalize_turn_url server in
    let username = Sys.getenv_opt "TURN_USERNAME" in
    let credential = Sys.getenv_opt "TURN_PASSWORD" in

    Printf.printf "TURN relay smoke: %s\n" turn_url;

    let config = { Ice.default_config with
      ice_servers = [ { Ice.urls = [turn_url]; username; credential } ];
    } in
    let agent = Ice.create config in

    test "gather relay candidate" (fun () ->
      let found = ref None in
      Ice.on_candidate agent (fun c ->
        if c.Ice.cand_type = Ice.Relay then found := Some c
      );
      Lwt_main.run (Ice.gather_candidates_full agent);
      match !found with
      | None -> failwith "No relay candidate (TURN server may require auth)"
      | Some relay ->
        let sdp_cand = Sdp.ice_candidate_of_ice relay in
        let line = Sdp.candidate_to_string sdp_cand in
        Printf.printf "  Relay candidate: a=%s\n" line;
        assert_true "relay type" (sdp_cand.cand_type = "relay")
    );

    Printf.printf "\nTURN relay smoke: %d passed, %d failed\n" !passed !failed;
    if !failed > 0 then exit 1
