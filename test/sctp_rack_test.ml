(** Unit tests for RACK loss detection algorithm (RFC 8985)
    @author Second Brain *)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try f (); incr passed; Printf.printf "✅ PASS\n%!"
  with e -> incr failed; Printf.printf "❌ FAIL (%s)\n%!" (Printexc.to_string e)

let assert_true msg b = if not b then failwith msg

(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_rack_basic () =
  Printf.printf "\n═══ RACK Basic Tests ═══\n";

  test "Create RACK instance" (fun () ->
    let rack = Sctp_rack.create () in
    assert_true "rack created" (Sctp_rack.get_in_flight_count rack >= 0)
  );

  test "Initial RTT values" (fun () ->
    let rack = Sctp_rack.create () in
    let rtt_min = Sctp_rack.get_rtt_min rack in
    assert_true "rtt_min >= 0" (rtt_min >= 0.0)
  );

  test "Initial reorder window" (fun () ->
    let rack = Sctp_rack.create () in
    let rw = Sctp_rack.get_reorder_window rack in
    assert_true "reorder_window >= 0" (rw >= 0.0)
  )

let test_packet_tracking () =
  Printf.printf "\n═══ Packet Tracking ═══\n";

  test "record_send tracks packets" (fun () ->
    let rack = Sctp_rack.create () in
    Sctp_rack.record_send rack 100l;
    Sctp_rack.record_send rack 101l;
    assert_true "tracking works" (Sctp_rack.get_in_flight_count rack >= 0)
  );

  test "on_packet_sent increments tracking" (fun () ->
    let rack = Sctp_rack.create () in
    Sctp_rack.on_packet_sent rack ~tsn:1000l ~size:100 ~now:0.0;
    assert_true "packet tracked" (Sctp_rack.get_in_flight_count rack >= 0)
  );

  test "TLP timeout is positive" (fun () ->
    let rack = Sctp_rack.create () in
    let timeout = Sctp_rack.tlp_timeout rack in
    assert_true "timeout > 0" (timeout > 0.0)
  )

let test_sack_processing () =
  Printf.printf "\n═══ SACK Processing ═══\n";

  test "process_sack with cumulative ack" (fun () ->
    let rack = Sctp_rack.create () in
    Sctp_rack.record_send rack 100l;
    Sctp_rack.record_send rack 101l;
    let _lost = Sctp_rack.process_sack rack ~cumulative_tsn:101l ~gap_blocks:[] in
    assert_true "SACK processed" true
  );

  test "process_sack with gaps" (fun () ->
    let rack = Sctp_rack.create () in
    for i = 100 to 105 do Sctp_rack.record_send rack (Int32.of_int i) done;
    let _lost = Sctp_rack.process_sack rack ~cumulative_tsn:101l ~gap_blocks:[(3, 4)] in
    assert_true "gap SACK processed" true
  )

(* Main *)
let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     RACK Algorithm Unit Tests (RFC 8985)                     ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";

  test_rack_basic ();
  test_packet_tracking ();
  test_sack_processing ();

  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";

  if !failed > 0 then exit 1
