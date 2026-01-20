(** SDP Test Suite (RFC 4566/8866/3264/8839/8841) *)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  try
    f ();
    incr passed;
    Printf.printf "  %s... PASS\n%!" name
  with e ->
    incr failed;
    Printf.printf "  %s... FAIL: %s\n%!" name (Printexc.to_string e)

let section title =
  Printf.printf "\n=== %s ===\n%!" title

let assert_eq what expected actual =
  if expected <> actual then
    failwith (Printf.sprintf "%s: expected %d, got %d" what expected actual)

let assert_eq_i64 what expected actual =
  if expected <> actual then
    failwith (Printf.sprintf "%s: expected %Ld, got %Ld" what expected actual)

let assert_eq_str what expected actual =
  if expected <> actual then
    failwith (Printf.sprintf "%s: expected %s, got %s" what expected actual)

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)

let contains haystack needle =
  let len_h = String.length haystack in
  let len_n = String.length needle in
  let rec loop i =
    if len_n = 0 then true
    else if i + len_n > len_h then false
    else if String.sub haystack i len_n = needle then true
    else loop (i + 1)
  in
  loop 0

let sample_fingerprint value =
  { Sdp.hash_func = "sha-256"; fingerprint = value }

let () =
  Printf.printf "===============================================================\n";
  Printf.printf "SDP Test Suite\n";
  Printf.printf "===============================================================\n";

  section "Offer/Answer";

  test "create_datachannel_offer basics" (fun () ->
    let fp = sample_fingerprint "AA:BB:CC" in
    let offer = Sdp.create_datachannel_offer
      ~ice_ufrag:"ufrag" ~ice_pwd:"pwd"
      ~fingerprint:fp ~sctp_port:5000
    in
    assert_true "has_datachannel" (Sdp.has_datachannel offer);
    match Sdp.find_media_by_type offer Sdp.Application with
    | None -> failwith "missing application media"
    | Some m ->
      assert_true "protocol" (m.protocol = Sdp.UDP_DTLS_SCTP);
      (match m.sctpmap with
       | None -> failwith "missing sctpmap"
       | Some sm ->
         assert_eq "sctp port" 5000 sm.port;
         assert_eq_str "sctp proto" "webrtc-datachannel" sm.protocol);
      (match Sdp.resolve_sctp_port m with
       | None -> failwith "resolve_sctp_port none"
       | Some port -> assert_eq "resolved sctp port" 5000 port);
      (match Sdp.resolve_ice_credentials offer m with
       | None -> failwith "missing ice credentials"
       | Some (ufrag, pwd) ->
         assert_eq_str "ufrag" "ufrag" ufrag;
         assert_eq_str "pwd" "pwd" pwd)
  );

  test "create_answer updates session + setup" (fun () ->
    let fp = sample_fingerprint "11:22" in
    let offer = Sdp.create_datachannel_offer
      ~ice_ufrag:"o" ~ice_pwd:"p" ~fingerprint:fp ~sctp_port:6000
    in
    let answer = Sdp.create_answer
      ~offer ~ice_ufrag:"o2" ~ice_pwd:"p2" ~fingerprint:(sample_fingerprint "33:44")
    in
    assert_eq_i64 "sess_version" (Int64.succ offer.origin.sess_version) answer.origin.sess_version;
    (match answer.ice_ufrag with
     | None -> failwith "missing answer ufrag"
     | Some v -> assert_eq_str "answer ufrag" "o2" v);
    (match answer.media with
     | [] -> failwith "missing media"
     | m :: _ ->
       assert_true "setup active" (m.setup = Some "active"))
  );

  section "Parse/Serialize";

  test "to_string -> parse roundtrip (datachannel)" (fun () ->
    let fp = sample_fingerprint "AA:BB" in
    let offer = Sdp.create_datachannel_offer
      ~ice_ufrag:"uf1" ~ice_pwd:"pw1" ~fingerprint:fp ~sctp_port:7000
    in
    let sdp = Sdp.to_string offer in
    match Sdp.parse sdp with
    | Error e -> failwith e
    | Ok parsed ->
      assert_true "has_datachannel" (Sdp.has_datachannel parsed);
      (match Sdp.find_media_by_index parsed 0 with
       | None -> failwith "missing media"
       | Some m ->
         (match Sdp.resolve_sctp_port m with
          | None -> failwith "missing sctp port"
          | Some port -> assert_eq "sctp port" 7000 port))
  );

  section "Candidate";

  test "candidate parse" (fun () ->
    let cand : Sdp.ice_candidate = {
      foundation = "1";
      component_id = 1;
      transport = "UDP";
      priority = 2130706431L;
      address = "10.0.0.1";
      port = 5000;
      cand_type = "host";
      rel_addr = Some "1.2.3.4";
      rel_port = Some 3478;
      extensions = [("generation", "0")];
    } in
    let line = Sdp.candidate_to_string cand in
    match Sdp.parse_candidate line with
    | Error e -> failwith e
    | Ok parsed ->
      assert_eq_str "foundation" cand.foundation parsed.foundation;
      assert_eq "component" cand.component_id parsed.component_id;
      assert_eq_str "transport" "UDP" parsed.transport;
      assert_eq "port" cand.port parsed.port;
      (match parsed.rel_addr, parsed.rel_port with
       | Some ra, Some rp ->
         assert_eq_str "rel_addr" "1.2.3.4" ra;
         assert_eq "rel_port" 3478 rp
       | _ -> failwith "missing rel_addr/rel_port")
  );

  section "ICE options + Trickle";

  test "to_string includes ice-options and end-of-candidates" (fun () ->
    let fp = sample_fingerprint "AA:EE" in
    let offer = Sdp.create_datachannel_offer
      ~ice_ufrag:"u1" ~ice_pwd:"p1" ~fingerprint:fp ~sctp_port:9000
    in
    let media =
      match Sdp.find_media_by_index offer 0 with
      | None -> failwith "missing media"
      | Some m ->
        { m with
          ice_options = ["trickle"];
          other_attrs = [("end-of-candidates", None)];
        }
    in
    let offer = { offer with ice_options = ["trickle"]; media = [media] } in
    let sdp = Sdp.to_string offer in
    assert_true "has ice-options" (contains sdp "a=ice-options:trickle");
    assert_true "has end-of-candidates" (contains sdp "a=end-of-candidates")
  );

  section "ICE ↔ SDP Conversion";

  test "ice_candidate_of_ice (relay) roundtrip" (fun () ->
    let relay : Ice.candidate = {
      foundation = "2";
      component = 1;
      transport = Ice.UDP;
      priority = 10;
      address = "192.0.2.10";
      port = 6000;
      cand_type = Ice.Relay;
      base_address = Some "10.0.0.1";
      base_port = Some 5000;
      related_address = Some "10.0.0.1";
      related_port = Some 5000;
      extensions = [];
    } in
    let sdp_cand = Sdp.ice_candidate_of_ice relay in
    let line = Sdp.candidate_to_string sdp_cand in
    match Sdp.parse_candidate line with
    | Error e -> failwith e
    | Ok parsed ->
      assert_eq_str "type" "relay" parsed.cand_type;
      (match parsed.rel_addr, parsed.rel_port with
       | Some ra, Some rp ->
         assert_eq_str "raddr" "10.0.0.1" ra;
         assert_eq "rport" 5000 rp
       | _ -> failwith "missing raddr/rport")
  );

  test "ice_candidate_to_ice (relay)" (fun () ->
    let cand : Sdp.ice_candidate = {
      foundation = "3";
      component_id = 1;
      transport = "UDP";
      priority = 42L;
      address = "192.0.2.11";
      port = 6001;
      cand_type = "relay";
      rel_addr = Some "10.0.0.2";
      rel_port = Some 5001;
      extensions = [];
    } in
    match Sdp.ice_candidate_to_ice cand with
    | Error e -> failwith e
    | Ok ice ->
      assert_true "relay type" (ice.cand_type = Ice.Relay);
      assert_eq_str "rel addr" "10.0.0.2" (Option.value ~default:"" ice.related_address);
      assert_eq "rel port" 5001 (Option.value ~default:0 ice.related_port)
  );

  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
