(** RTCP Test Suite

    Minimal encode/decode tests for RTCP SR/RR and compound packets.
*)

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

let assert_eq_i32 what expected actual =
  if expected <> actual then
    failwith (Printf.sprintf "%s: expected %ld, got %ld" what expected actual)

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)

let sample_report_block () : Webrtc.Rtcp.report_block =
  {
    ssrc = 0x11111111l;
    fraction_lost = 1;
    cumulative_lost = -2l;
    highest_seq = 0x22222222l;
    jitter = 0x33333333l;
    last_sr = 0x44444444l;
    dlsr = 0x55555555l;
  }

let () =
  Printf.printf "===============================================================\n";
  Printf.printf "RTCP Test Suite (RFC 3550)\n";
  Printf.printf "===============================================================\n";

  section "Roundtrip";

  test "SR encode/decode" (fun () ->
    let sr : Webrtc.Rtcp.sender_report =
      {
        ssrc = 0x01020304l;
        sender_info = {
          ntp_sec = 1l;
          ntp_frac = 2l;
          rtp_timestamp = 3l;
          packet_count = 4l;
          octet_count = 5l;
        };
        report_blocks = [ sample_report_block () ];
      }
    in
    let data = Webrtc.Rtcp.encode (Webrtc.Rtcp.Sender_report sr) in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Sender_report decoded) ->
      assert_eq_i32 "ssrc" sr.ssrc decoded.ssrc;
      assert_eq_i32 "rtp_timestamp" sr.sender_info.rtp_timestamp decoded.sender_info.rtp_timestamp;
      assert_true "report_blocks len" (List.length decoded.report_blocks = 1)
    | Ok _ -> failwith "expected SR"
  );

  test "RR encode/decode" (fun () ->
    let rr : Webrtc.Rtcp.receiver_report =
      {
        ssrc = 0x0A0B0C0Dl;
        report_blocks = [ sample_report_block (); sample_report_block () ];
      }
    in
    let data = Webrtc.Rtcp.encode (Webrtc.Rtcp.Receiver_report rr) in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Receiver_report decoded) ->
      assert_eq_i32 "ssrc" rr.ssrc decoded.ssrc;
      assert_true "report_blocks len" (List.length decoded.report_blocks = 2)
    | Ok _ -> failwith "expected RR"
  );

  test "Unknown packet roundtrip" (fun () ->
    let payload = Bytes.of_string "appdata0" in
    let data = Webrtc.Rtcp.encode (Webrtc.Rtcp.Unknown_packet (Webrtc.Rtcp.APP, payload)) in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Unknown_packet (pt, body)) ->
      assert_true "packet type" (pt = Webrtc.Rtcp.APP);
      assert_true "payload" (Bytes.equal payload body)
    | Ok _ -> failwith "expected Unknown"
  );

  section "Compound";

  test "decode compound packets" (fun () ->
    let sr = Webrtc.Rtcp.Sender_report {
      ssrc = 0x11111111l;
      sender_info = {
        ntp_sec = 10l; ntp_frac = 11l; rtp_timestamp = 12l;
        packet_count = 13l; octet_count = 14l;
      };
      report_blocks = [];
    } in
    let rr = Webrtc.Rtcp.Receiver_report {
      ssrc = 0x22222222l;
      report_blocks = [];
    } in
    let data = Bytes.concat Bytes.empty [ Webrtc.Rtcp.encode sr; Webrtc.Rtcp.encode rr ] in
    match Webrtc.Rtcp.decode_compound data with
    | Error e -> failwith e
    | Ok packets ->
      assert_eq "packet count" 2 (List.length packets);
      (match packets with
       | Webrtc.Rtcp.Sender_report _ :: Webrtc.Rtcp.Receiver_report _ :: _ -> ()
       | _ -> failwith "unexpected packet order")
  );

  section "Validation";

  test "reject invalid version" (fun () ->
    let sr = Webrtc.Rtcp.Sender_report {
      ssrc = 1l;
      sender_info = {
        ntp_sec = 1l; ntp_frac = 1l; rtp_timestamp = 1l;
        packet_count = 1l; octet_count = 1l;
      };
      report_blocks = [];
    } in
    let data = Webrtc.Rtcp.encode sr in
    let b0 = Bytes.get_uint8 data 0 in
    Bytes.set_uint8 data 0 (b0 land 0x3F); (* version -> 0 *)
    match Webrtc.Rtcp.decode data with
    | Ok _ -> failwith "expected decode error"
    | Error _ -> ()
  );

  test "reject invalid padding" (fun () ->
    let rr = Webrtc.Rtcp.Receiver_report {
      ssrc = 1l;
      report_blocks = [];
    } in
    let data = Webrtc.Rtcp.encode rr in
    let b0 = Bytes.get_uint8 data 0 in
    Bytes.set_uint8 data 0 (b0 lor 0x20); (* padding bit *)
    Bytes.set_uint8 data (Bytes.length data - 1) 0;
    match Webrtc.Rtcp.decode data with
    | Ok _ -> failwith "expected padding error"
    | Error _ -> ()
  );

  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
