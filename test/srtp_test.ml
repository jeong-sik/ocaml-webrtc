(** SRTP Test Suite

    Basic protect/unprotect roundtrip for RTP/RTCP.
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

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)

let sample_keying () =
  let key = Bytes.init 16 (fun i -> Char.chr (i land 0xFF)) in
  let salt = Bytes.init 14 (fun i -> Char.chr ((i + 1) land 0xFF)) in
  { Webrtc.Srtp.master_key = key; master_salt = salt }

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║               SRTP Test Suite (RFC 3711)                      ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";

  section "RTP Roundtrip";

  test "protect/unprotect RTP" (fun () ->
    let keying = sample_keying () in
    let ssrc = 0x12345678l in
    let ctx = Webrtc.Srtp.create
      ~profile:Webrtc.Srtp.AES_128_CM_HMAC_SHA1_80
      ~keying ~ssrc
    in
    let header = Webrtc.Rtp.default_header
      ~payload_type:111 ~sequence:42 ~timestamp:960l ~ssrc () in
    let payload = Bytes.of_string "hello-srtp" in
    let rtp =
      match Webrtc.Rtp.encode header ~payload with
      | Ok data -> data
      | Error e -> failwith e
    in
    let protected =
      match Webrtc.Srtp.protect_rtp ctx ~rtp with
      | Ok p -> p
      | Error e -> failwith e
    in
    let unprotected =
      match Webrtc.Srtp.unprotect_rtp ctx ~rtp:protected with
      | Ok p -> p
      | Error e -> failwith e
    in
    match Webrtc.Rtp.decode unprotected with
    | Error e -> failwith e
    | Ok pkt ->
      assert_true "payload matches" (Bytes.equal payload pkt.payload)
  );

  section "RTP Auth Failure";

  test "tampered auth tag fails" (fun () ->
    let keying = sample_keying () in
    let ssrc = 0x12345678l in
    let ctx = Webrtc.Srtp.create
      ~profile:Webrtc.Srtp.AES_128_CM_HMAC_SHA1_80
      ~keying ~ssrc
    in
    let header = Webrtc.Rtp.default_header
      ~payload_type:111 ~sequence:1 ~timestamp:960l ~ssrc () in
    let payload = Bytes.of_string "tamper" in
    let rtp =
      match Webrtc.Rtp.encode header ~payload with
      | Ok data -> data
      | Error e -> failwith e
    in
    let protected =
      match Webrtc.Srtp.protect_rtp ctx ~rtp with
      | Ok p -> p
      | Error e -> failwith e
    in
    Bytes.set_uint8 protected 8 (Bytes.get_uint8 protected 8 lxor 0x01);
    match Webrtc.Srtp.unprotect_rtp ctx ~rtp:protected with
    | Ok _ -> failwith "expected auth failure"
    | Error _ -> ()
  );

  section "RTCP Roundtrip";

  test "protect/unprotect RTCP" (fun () ->
    let keying = sample_keying () in
    let ssrc = 0x11111111l in
    let ctx = Webrtc.Srtp.create
      ~profile:Webrtc.Srtp.AES_128_CM_HMAC_SHA1_80
      ~keying ~ssrc
    in
    let rr = Webrtc.Rtcp.Receiver_report { ssrc; report_blocks = [] } in
    let rtcp = Webrtc.Rtcp.encode rr in
    let protected =
      match Webrtc.Srtp.protect_rtcp ctx ~rtcp with
      | Ok p -> p
      | Error e -> failwith e
    in
    let unprotected =
      match Webrtc.Srtp.unprotect_rtcp ctx ~rtcp:protected with
      | Ok p -> p
      | Error e -> failwith e
    in
    match Webrtc.Rtcp.decode unprotected with
    | Error e -> failwith e
    | Ok _ -> ()
  );

  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
