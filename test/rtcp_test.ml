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
  with
  | e ->
    incr failed;
    Printf.printf "  %s... FAIL: %s\n%!" name (Printexc.to_string e)
;;

let section title = Printf.printf "\n=== %s ===\n%!" title

let assert_eq what expected actual =
  if expected <> actual
  then failwith (Printf.sprintf "%s: expected %d, got %d" what expected actual)
;;

let assert_eq_i32 what expected actual =
  if expected <> actual
  then failwith (Printf.sprintf "%s: expected %ld, got %ld" what expected actual)
;;

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)
;;

let sample_report_block () : Webrtc.Rtcp.report_block =
  { ssrc = 0x11111111l
  ; fraction_lost = 1
  ; cumulative_lost = -2l
  ; highest_seq = 0x22222222l
  ; jitter = 0x33333333l
  ; last_sr = 0x44444444l
  ; dlsr = 0x55555555l
  }
;;

let () =
  Printf.printf "===============================================================\n";
  Printf.printf "RTCP Test Suite (RFC 3550)\n";
  Printf.printf "===============================================================\n";
  section "Roundtrip";
  test "SR encode/decode" (fun () ->
    let sr : Webrtc.Rtcp.sender_report =
      { ssrc = 0x01020304l
      ; sender_info =
          { ntp_sec = 1l
          ; ntp_frac = 2l
          ; rtp_timestamp = 3l
          ; packet_count = 4l
          ; octet_count = 5l
          }
      ; report_blocks = [ sample_report_block () ]
      }
    in
    let data = Webrtc.Rtcp.encode (Webrtc.Rtcp.Sender_report sr) in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Sender_report decoded) ->
      assert_eq_i32 "ssrc" sr.ssrc decoded.ssrc;
      assert_eq_i32
        "rtp_timestamp"
        sr.sender_info.rtp_timestamp
        decoded.sender_info.rtp_timestamp;
      assert_true "report_blocks len" (List.length decoded.report_blocks = 1)
    | Ok _ -> failwith "expected SR");
  test "RR encode/decode" (fun () ->
    let rr : Webrtc.Rtcp.receiver_report =
      { ssrc = 0x0A0B0C0Dl
      ; report_blocks = [ sample_report_block (); sample_report_block () ]
      }
    in
    let data = Webrtc.Rtcp.encode (Webrtc.Rtcp.Receiver_report rr) in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Receiver_report decoded) ->
      assert_eq_i32 "ssrc" rr.ssrc decoded.ssrc;
      assert_true "report_blocks len" (List.length decoded.report_blocks = 2)
    | Ok _ -> failwith "expected RR");
  test "APP encode/decode" (fun () ->
    let app : Webrtc.Rtcp.app_packet =
      { subtype = 5
      ; ssrc = 0xDEADBEEFl
      ; name = "TEST"
      ; data = Bytes.of_string "appdata0"
      }
    in
    let data = Webrtc.Rtcp.encode (Webrtc.Rtcp.App app) in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.App decoded) ->
      assert_eq "subtype" 5 decoded.subtype;
      assert_eq_i32 "ssrc" 0xDEADBEEFl decoded.ssrc;
      assert_true "name" (decoded.name = "TEST");
      assert_true "data" (Bytes.equal app.data decoded.data)
    | Ok _ -> failwith "expected APP");
  test "Unknown packet roundtrip" (fun () ->
    (* Use XR (207) which is a known type but not yet implemented *)
    let payload = Bytes.of_string "xrdata00" in
    (* 8 bytes, 32-bit aligned *)
    let data =
      Webrtc.Rtcp.encode (Webrtc.Rtcp.Unknown_packet (Webrtc.Rtcp.XR, payload))
    in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Unknown_packet (pt, body)) ->
      assert_true "packet type" (pt = Webrtc.Rtcp.XR);
      assert_true "payload" (Bytes.equal payload body)
    | Ok _ -> failwith "expected Unknown");
  section "SDES (RFC 3550 Section 6.5)";
  test "SDES encode/decode" (fun () ->
    let sdes : Webrtc.Rtcp.sdes_chunk list =
      [ { ssrc = 0xDEADBEEFl
        ; items =
            [ { item_type = Webrtc.Rtcp.CNAME; value = "user@example.com" }
            ; { item_type = Webrtc.Rtcp.NAME; value = "Test User" }
            ]
        }
      ]
    in
    let data = Webrtc.Rtcp.encode (Webrtc.Rtcp.Source_description sdes) in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Source_description decoded) ->
      assert_eq "chunk count" 1 (List.length decoded);
      let chunk = List.hd decoded in
      assert_eq_i32 "ssrc" 0xDEADBEEFl chunk.ssrc;
      assert_eq "item count" 2 (List.length chunk.items);
      let cname = List.hd chunk.items in
      assert_true "CNAME type" (cname.item_type = Webrtc.Rtcp.CNAME);
      assert_true "CNAME value" (cname.value = "user@example.com")
    | Ok _ -> failwith "expected SDES");
  test "SDES make_sdes_cname helper" (fun () ->
    let pkt = Webrtc.Rtcp.make_sdes_cname ~ssrc:0x12345678l ~cname:"test@local" in
    let data = Webrtc.Rtcp.encode pkt in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Source_description chunks) ->
      assert_eq "chunk count" 1 (List.length chunks);
      let chunk = List.hd chunks in
      assert_eq_i32 "ssrc" 0x12345678l chunk.ssrc;
      assert_eq "item count" 1 (List.length chunk.items);
      let item = List.hd chunk.items in
      assert_true "is CNAME" (item.item_type = Webrtc.Rtcp.CNAME);
      assert_true "cname value" (item.value = "test@local")
    | Ok _ -> failwith "expected SDES");
  section "BYE (RFC 3550 Section 6.6)";
  test "BYE encode/decode without reason" (fun () ->
    let bye = Webrtc.Rtcp.make_bye [ 0x11111111l; 0x22222222l ] in
    let data = Webrtc.Rtcp.encode bye in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Bye decoded) ->
      assert_eq "ssrc count" 2 (List.length decoded.ssrcs);
      assert_true "first ssrc" (List.hd decoded.ssrcs = 0x11111111l);
      assert_true "no reason" (decoded.reason = None)
    | Ok _ -> failwith "expected BYE");
  test "BYE encode/decode with reason" (fun () ->
    let bye = Webrtc.Rtcp.make_bye ~reason:"Session ended" [ 0xCAFEBABEl ] in
    let data = Webrtc.Rtcp.encode bye in
    match Webrtc.Rtcp.decode data with
    | Error e -> failwith e
    | Ok (Webrtc.Rtcp.Bye decoded) ->
      assert_eq "ssrc count" 1 (List.length decoded.ssrcs);
      assert_eq_i32 "ssrc" 0xCAFEBABEl (List.hd decoded.ssrcs);
      (match decoded.reason with
       | None -> failwith "expected reason"
       | Some r -> assert_true "reason text" (r = "Session ended"))
    | Ok _ -> failwith "expected BYE");
  section "RTCP Timing (RFC 3550 Section 6.3)";
  test "calculate_rtcp_interval minimum" (fun () ->
    let interval =
      Webrtc.Rtcp.calculate_rtcp_interval
        ~members:2
        ~senders:1
        ~rtcp_bw:1000.0
        ~we_sent:false
        ~avg_rtcp_size:100.0
        ~initial:false
    in
    assert_true "min 5 seconds" (interval >= 5.0));
  test "calculate_rtcp_interval initial reduced" (fun () ->
    let interval =
      Webrtc.Rtcp.calculate_rtcp_interval
        ~members:2
        ~senders:1
        ~rtcp_bw:10000.0
        ~we_sent:false
        ~avg_rtcp_size:100.0
        ~initial:true
    in
    assert_true "min 2.5 seconds for initial" (interval >= 2.5));
  section "Compound";
  test "decode compound packets" (fun () ->
    let sr =
      Webrtc.Rtcp.Sender_report
        { ssrc = 0x11111111l
        ; sender_info =
            { ntp_sec = 10l
            ; ntp_frac = 11l
            ; rtp_timestamp = 12l
            ; packet_count = 13l
            ; octet_count = 14l
            }
        ; report_blocks = []
        }
    in
    let rr = Webrtc.Rtcp.Receiver_report { ssrc = 0x22222222l; report_blocks = [] } in
    let data =
      Bytes.concat Bytes.empty [ Webrtc.Rtcp.encode sr; Webrtc.Rtcp.encode rr ]
    in
    match Webrtc.Rtcp.decode_compound data with
    | Error e -> failwith e
    | Ok packets ->
      assert_eq "packet count" 2 (List.length packets);
      (match packets with
       | Webrtc.Rtcp.Sender_report _ :: Webrtc.Rtcp.Receiver_report _ :: _ -> ()
       | _ -> failwith "unexpected packet order"));
  section "Validation";
  test "reject invalid version" (fun () ->
    let sr =
      Webrtc.Rtcp.Sender_report
        { ssrc = 1l
        ; sender_info =
            { ntp_sec = 1l
            ; ntp_frac = 1l
            ; rtp_timestamp = 1l
            ; packet_count = 1l
            ; octet_count = 1l
            }
        ; report_blocks = []
        }
    in
    let data = Webrtc.Rtcp.encode sr in
    let b0 = Bytes.get_uint8 data 0 in
    Bytes.set_uint8 data 0 (b0 land 0x3F);
    (* version -> 0 *)
    match Webrtc.Rtcp.decode data with
    | Ok _ -> failwith "expected decode error"
    | Error _ -> ());
  test "reject invalid padding" (fun () ->
    let rr = Webrtc.Rtcp.Receiver_report { ssrc = 1l; report_blocks = [] } in
    let data = Webrtc.Rtcp.encode rr in
    let b0 = Bytes.get_uint8 data 0 in
    Bytes.set_uint8 data 0 (b0 lor 0x20);
    (* padding bit *)
    Bytes.set_uint8 data (Bytes.length data - 1) 0;
    match Webrtc.Rtcp.decode data with
    | Ok _ -> failwith "expected padding error"
    | Error _ -> ());
  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
;;
