(** ICE Candidate Gathering Example

    RFC 8445 - Interactive Connectivity Establishment (ICE)

    This example demonstrates:
    - Creating an ICE agent
    - Gathering host candidates (local interfaces)
    - Gathering server-reflexive candidates (via STUN)
    - Trickle ICE candidate callback

    Usage: dune exec ./examples/ice_gathering.exe

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

open Webrtc

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║         ICE Candidate Gathering (RFC 8445)                   ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";

  (* Create ICE agent with default config *)
  let config = Ice.default_config in
  let agent = Ice.create config in

  (* Get local credentials *)
  let (ufrag, pwd) = Ice.get_local_credentials agent in
  Printf.printf "Local ICE Credentials:\n";
  Printf.printf "  ice-ufrag: %s\n" ufrag;
  Printf.printf "  ice-pwd:   %s\n\n" pwd;

  (* Set up Trickle ICE callback *)
  Ice.on_candidate agent (fun candidate ->
    Printf.printf "★ New Candidate Found:\n";
    Printf.printf "   Type:      %s\n" (Ice.string_of_candidate_type candidate.Ice.cand_type);
    Printf.printf "   Address:   %s:%d\n" candidate.address candidate.port;
    Printf.printf "   Priority:  %d\n" candidate.priority;
    Printf.printf "   Foundation: %s\n" candidate.foundation;
    begin match candidate.related_address with
    | Some raddr ->
      Printf.printf "   Related:   %s:%d\n"
        raddr (Option.value ~default:0 candidate.related_port)
    | None -> ()
    end;
    Printf.printf "\n"
  );

  Ice.on_gathering_complete agent (fun () ->
    Printf.printf "════════════════════════════════════════════════════════════════\n";
    Printf.printf "ICE Gathering Complete!\n";
    Printf.printf "════════════════════════════════════════════════════════════════\n\n"
  );

  Printf.printf "Starting candidate gathering...\n\n";

  (* Gather candidates (using Lwt for async operations) *)
  Lwt_main.run (Ice.gather_candidates agent);

  (* Get all gathered candidates *)
  let candidates = Ice.get_local_candidates agent in

  Printf.printf "════════════════════════════════════════════════════════════════\n";
  Printf.printf "Summary: %d candidates gathered\n" (List.length candidates);
  Printf.printf "════════════════════════════════════════════════════════════════\n\n";

  (* Print candidates in SDP format *)
  Printf.printf "SDP Candidate Lines (a=candidate:...):\n";
  Printf.printf "───────────────────────────────────────────────────────────────\n";
  List.iter (fun c ->
    Printf.printf "%s\n" (Ice.candidate_to_string c)
  ) candidates;

  Printf.printf "\n";
  Printf.printf "Tip: Copy these lines to share with remote peer\n"
