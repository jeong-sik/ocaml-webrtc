(** DCEP Test Suite (RFC 8832) *)

open Webrtc

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

let assert_eq_str what expected actual =
  if expected <> actual
  then failwith (Printf.sprintf "%s: expected %s, got %s" what expected actual)
;;

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)
;;

let () =
  Printf.printf "===============================================================\n";
  Printf.printf "DCEP Test Suite (RFC 8832)\n";
  Printf.printf "===============================================================\n";
  section "Encode/Decode";
  test "encode/decode OPEN roundtrip" (fun () ->
    let open_msg : Dcep.data_channel_open =
      { channel_type = Dcep.PartialReliableTimed 1500
      ; priority = 42
      ; label = "chat"
      ; protocol = "json"
      }
    in
    let encoded = Dcep.encode_open open_msg in
    match Dcep.decode_open encoded with
    | Error e -> failwith e
    | Ok decoded ->
      assert_eq "priority" open_msg.priority decoded.priority;
      assert_eq_str "label" open_msg.label decoded.label;
      assert_eq_str "protocol" open_msg.protocol decoded.protocol;
      (match decoded.channel_type with
       | Dcep.PartialReliableTimed 1500 -> ()
       | _ -> failwith "channel_type mismatch"));
  test "decode OPEN rejects wrong type" (fun () ->
    let ack = Dcep.encode_ack () in
    match Dcep.decode_open ack with
    | Ok _ -> failwith "expected decode error"
    | Error _ -> ());
  test "ACK detection" (fun () ->
    let ack = Dcep.encode_ack () in
    let open_msg : Dcep.data_channel_open =
      { channel_type = Dcep.Reliable; priority = 1; label = "x"; protocol = "" }
    in
    let encoded = Dcep.encode_open open_msg in
    assert_true "ack true" (Dcep.is_ack ack);
    assert_true "ack false" (not (Dcep.is_ack encoded)));
  section "Stream IDs";
  test "allocate stream id parity" (fun () ->
    let client = Dcep.create ~is_client:true in
    let id0 = Dcep.allocate_stream_id client in
    let id1 = Dcep.allocate_stream_id client in
    assert_eq "client id0" 0 id0;
    assert_eq "client id1" 2 id1;
    let server = Dcep.create ~is_client:false in
    let id2 = Dcep.allocate_stream_id server in
    let id3 = Dcep.allocate_stream_id server in
    assert_eq "server id0" 1 id2;
    assert_eq "server id1" 3 id3);
  section "Channel lifecycle";
  test "open_channel -> ack -> open" (fun () ->
    let t = Dcep.create ~is_client:true in
    let stream_id, _msg = Dcep.open_channel t ~label:"chat" () in
    (match Dcep.get_channel t ~stream_id with
     | None -> failwith "missing channel"
     | Some ch -> assert_true "state opening" (ch.state = Dcep.Opening));
    (match Dcep.handle_ack t ~stream_id with
     | Ok () -> ()
     | Error e -> failwith e);
    (match Dcep.get_channel t ~stream_id with
     | None -> failwith "missing channel"
     | Some ch -> assert_true "state open" (ch.state = Dcep.Open));
    assert_eq "list_channels" 1 (List.length (Dcep.list_channels t)));
  test "handle_open creates open channel + ack" (fun () ->
    let t = Dcep.create ~is_client:false in
    let open_msg : Dcep.data_channel_open =
      { channel_type = Dcep.ReliableUnordered
      ; priority = 7
      ; label = "file"
      ; protocol = "bin"
      }
    in
    let stream_id, ack = Dcep.handle_open t ~stream_id:1 open_msg in
    assert_true "ack is ack" (Dcep.is_ack ack);
    match Dcep.get_channel t ~stream_id with
    | None -> failwith "missing channel"
    | Some ch ->
      assert_eq_str "label" "file" ch.label;
      assert_eq_str "protocol" "bin" ch.protocol;
      assert_true "state open" (ch.state = Dcep.Open));
  test "ppid selection" (fun () ->
    let t = Dcep.create ~is_client:true in
    let stream_id, _msg = Dcep.open_channel t ~label:"ppid" () in
    match Dcep.get_channel t ~stream_id with
    | None -> failwith "missing channel"
    | Some ch ->
      assert_true "string ppid" (Dcep.ppid_for_data ~is_string:true ch = 51l);
      assert_true "binary ppid" (Dcep.ppid_for_data ~is_string:false ch = 53l));
  test "stats track active channels" (fun () ->
    let t = Dcep.create ~is_client:true in
    let stream_id, _msg = Dcep.open_channel t ~label:"stats" () in
    let stats0 = Dcep.get_stats t in
    assert_eq "opened" 1 stats0.channels_opened;
    assert_eq "active" 0 stats0.active_channels;
    (match Dcep.handle_ack t ~stream_id with
     | Ok () -> ()
     | Error e -> failwith e);
    let stats1 = Dcep.get_stats t in
    assert_eq "opened" 1 stats1.channels_opened;
    assert_eq "active" 1 stats1.active_channels);
  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
;;
