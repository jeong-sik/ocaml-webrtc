(** RTP Test Suite

    Minimal encode/decode tests for RTP header handling.
*)

let passed = ref 0
let failed = ref 0

let test name f =
  try
    f ();
    incr passed;
    Printf.printf "  %s... ✅ PASS\n%!" name
  with e ->
    incr failed;
    Printf.printf "  %s... ❌ FAIL: %s\n%!" name (Printexc.to_string e)

let section title =
  Printf.printf "\n═══ %s ═══\n%!" title

let assert_eq what expected actual =
  if expected <> actual then
    failwith (Printf.sprintf "%s: expected %s, got %s" what
      (string_of_int expected) (string_of_int actual))

let assert_eq_i32 what expected actual =
  if expected <> actual then
    failwith (Printf.sprintf "%s: expected %ld, got %ld" what expected actual)

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║               RTP Test Suite (RFC 3550)                       ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";

  section "Roundtrip";

  test "encode/decode roundtrip" (fun () ->
    let payload = Bytes.of_string "hello-rtp" in
    let base = Webrtc.Rtp.default_header
      ~payload_type:111 ~sequence:42 ~timestamp:12345l ~ssrc:0x11111111l ()
    in
    let header = { base with
      marker = true;
      csrc = [0x22222222l; 0x33333333l];
    } in
    match Webrtc.Rtp.encode header ~payload with
    | Error e -> failwith e
    | Ok data ->
      match Webrtc.Rtp.decode data with
      | Error e -> failwith e
      | Ok pkt ->
        assert_eq "payload_type" header.payload_type pkt.header.payload_type;
        assert_eq "sequence" header.sequence pkt.header.sequence;
        assert_eq_i32 "timestamp" header.timestamp pkt.header.timestamp;
        assert_eq_i32 "ssrc" header.ssrc pkt.header.ssrc;
        assert_true "marker" pkt.header.marker;
        assert_true "csrc length" (List.length pkt.header.csrc = 2);
        assert_true "payload matches" (Bytes.equal payload pkt.payload)
  );

  section "Extension + Padding";

  test "extension and padding preserved" (fun () ->
    let ext_data = Bytes.of_string "12345678" in
    let payload = Bytes.of_string "payload" in
    let base = Webrtc.Rtp.default_header () in
    let header = { base with
      extension = Some { profile = 0xABCD; data = ext_data };
      padding_len = 4;
    } in
    match Webrtc.Rtp.encode header ~payload with
    | Error e -> failwith e
    | Ok data ->
      match Webrtc.Rtp.decode data with
      | Error e -> failwith e
      | Ok pkt ->
        assert_eq "padding_len" 4 pkt.header.padding_len;
        (match pkt.header.extension with
         | None -> failwith "missing extension"
         | Some ext ->
           assert_eq "ext profile" 0xABCD ext.profile;
           assert_true "ext data" (Bytes.equal ext.data ext_data));
        assert_true "payload matches" (Bytes.equal payload pkt.payload)
  );

  section "Validation";

  test "reject invalid version" (fun () ->
    let payload = Bytes.of_string "x" in
    let header = Webrtc.Rtp.default_header () in
    match Webrtc.Rtp.encode header ~payload with
    | Error e -> failwith e
    | Ok data ->
      let b0 = Bytes.get_uint8 data 0 in
      Bytes.set_uint8 data 0 (b0 land 0x3F); (* version -> 0 *)
      match Webrtc.Rtp.decode data with
      | Ok _ -> failwith "expected decode error"
      | Error _ -> ()
  );

  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
