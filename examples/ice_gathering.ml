(** Example: ICE Candidate Gathering

    This example demonstrates ICE candidate discovery:
    - Host candidates (local network interfaces)
    - Server-reflexive candidates (via STUN servers)

    Usage:
      dune exec examples/ice_gathering.exe

    The example gathers candidates and prints them in SDP format.
*)

open Webrtc

let () =
  (* Initialize RNG (new API) *)
  Mirage_crypto_rng_unix.use_default ();

  Printf.printf "=== ICE Candidate Gathering Example ===\n\n";

  (* Configure ICE with Google's STUN servers *)
  let config = {
    Ice.default_config with
    ice_servers = [
      { urls = ["stun:stun.l.google.com:19302"; "stun:stun1.l.google.com:19302"];
        username = None;
        credential = None };
    ];
    role = Ice.Controlling;
  } in

  (* Create ICE agent *)
  let agent = Ice.create config in

  let (ufrag, pwd) = Ice.get_local_credentials agent in
  Printf.printf "Local credentials:\n";
  Printf.printf "  ufrag: %s\n" ufrag;
  Printf.printf "  pwd: %s\n\n" pwd;

  (* Set callback for new candidates *)
  Ice.on_candidate agent (fun candidate ->
    Printf.printf "📦 New candidate: %s\n"
      (Ice.candidate_to_string candidate)
  );

  (* Set callback for gathering complete *)
  Ice.on_gathering_complete agent (fun () ->
    Printf.printf "\n✅ Gathering complete!\n"
  );

  Printf.printf "Gathering candidates...\n\n";

  (* First gather host candidates (fast) *)
  Printf.printf "--- Host Candidates ---\n";
  Lwt_main.run (Ice.gather_candidates agent);

  let host_candidates = Ice.get_local_candidates agent in
  Printf.printf "Found %d host candidate(s)\n\n"
    (List.length host_candidates);

  (* Then gather server-reflexive candidates (requires network) *)
  Printf.printf "--- Server-Reflexive Candidates (STUN) ---\n";
  Lwt_main.run (Ice.gather_candidates_full agent);

  let all_candidates = Ice.get_local_candidates agent in
  let srflx_count = List.length all_candidates - List.length host_candidates in
  Printf.printf "Found %d server-reflexive candidate(s)\n\n" srflx_count;

  (* Print all candidates in SDP a=candidate format *)
  Printf.printf "=== All Candidates (SDP format) ===\n\n";
  List.iter (fun c ->
    Printf.printf "a=candidate:%s\n" (Ice.candidate_to_string c)
  ) all_candidates;

  Printf.printf "\nTotal: %d candidate(s)\n" (List.length all_candidates);

  (* Print gathering state *)
  Printf.printf "\nGathering state: %s\n"
    (Ice.string_of_gathering_state (Ice.get_gathering_state agent))
