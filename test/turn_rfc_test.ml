(** TURN RFC 5766 client tests (sans-network)

    Focus:
    - Allocate/refresh lifecycle
    - Long-term credential auth (401 -> authenticated allocate)
    - CreatePermission + ChannelBind + channel data
    - Send indication when channel is absent
*)

open Effect.Deep
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

let bytes_concat parts = Bytes.concat Bytes.empty parts
let magic_cookie = 0x2112A442l
let attr_lifetime = 0x000D
let attr_xor_relayed_address = 0x0016
let attr_realm = 0x0014
let attr_nonce = 0x0015
let attr_error_code = 0x0009

let build_message_header msg_type length tid =
  let buf = Bytes.create 20 in
  Bytes.set_uint16_be buf 0 msg_type;
  Bytes.set_uint16_be buf 2 length;
  Bytes.set_int32_be buf 4 magic_cookie;
  Bytes.blit tid 0 buf 8 12;
  buf

let build_attribute attr_type value =
  let len = Bytes.length value in
  let padded_len = (len + 3) land (lnot 3) in
  let buf = Bytes.create (4 + padded_len) in
  Bytes.set_uint16_be buf 0 attr_type;
  Bytes.set_uint16_be buf 2 len;
  Bytes.blit value 0 buf 4 len;
  buf

let build_xor_address ~ip ~port =
  let buf = Bytes.create 8 in
  Bytes.set_uint8 buf 0 0;
  Bytes.set_uint8 buf 1 1;
  Bytes.set_uint16_be buf 2 (port lxor 0x2112);
  let parts = String.split_on_char '.' ip in
  (match parts with
  | [a; b; c; d] ->
    let raw =
      (int_of_string a lsl 24) lor (int_of_string b lsl 16) lor
      (int_of_string c lsl 8) lor (int_of_string d)
    in
    let xored = Int32.logxor magic_cookie (Int32.of_int raw) in
    Bytes.set_int32_be buf 4 xored
  | _ -> ());
  buf

let build_xor_relayed_attr ~ip ~port =
  let addr = build_xor_address ~ip ~port in
  build_attribute attr_xor_relayed_address addr

let build_lifetime_attr lifetime =
  let buf = Bytes.create 4 in
  Bytes.set_int32_be buf 0 (Int32.of_int lifetime);
  build_attribute attr_lifetime buf

let build_success_response ~msg_type ~attrs =
  let tid = Bytes.make 12 '\xAA' in
  let header = build_message_header msg_type (Bytes.length attrs) tid in
  bytes_concat [header; attrs]

let build_error_response ~msg_type ~realm ~nonce ~err_class ~err_number =
  let tid = Bytes.make 12 '\xBB' in
  let realm_attr = build_attribute attr_realm (Bytes.of_string realm) in
  let nonce_attr = build_attribute attr_nonce (Bytes.of_string nonce) in
  let err_buf = Bytes.create 4 in
  Bytes.set_uint16_be err_buf 0 0;
  Bytes.set_uint8 err_buf 2 err_class;
  Bytes.set_uint8 err_buf 3 err_number;
  let err_attr = build_attribute attr_error_code err_buf in
  let attrs = bytes_concat [realm_attr; nonce_attr; err_attr] in
  let header = build_message_header msg_type (Bytes.length attrs) tid in
  bytes_concat [header; attrs]

let run_with_stub ~responses:(responses : (bytes * string * int) list) ~now:(now : float) f =
  let responses = ref responses in
  let sends = ref [] in
  let result =
    try_with f ()
      { effc = (fun (type a) (eff : a Effect.t) ->
          match eff with
          | Turn.Send (data, host, port) ->
            Some (fun (k : (a, _) continuation) ->
              sends := (data, host, port) :: !sends;
              continue k (Bytes.length data))
          | Turn.Recv _size ->
            Some (fun (k : (a, _) continuation) ->
              match !responses with
              | resp :: rest ->
                responses := rest;
                continue k resp
              | [] ->
                continue k (Bytes.empty, "0.0.0.0", 0))
          | Turn.Now ->
            Some (fun (k : (a, _) continuation) -> continue k now)
          | Turn.Sleep _ ->
            Some (fun (k : (a, _) continuation) -> continue k ())
          | _ -> None) }
  in
  (result, List.rev !sends)

let ok_response msg_type attrs =
  (build_success_response ~msg_type ~attrs, "127.0.0.1", 3478)

let err_response msg_type realm nonce err_class err_number =
  (build_error_response ~msg_type ~realm ~nonce ~err_class ~err_number, "127.0.0.1", 3478)

let base_config () =
  { Turn.default_config with
    server_host = "turn.example.com";
    server_port = 3478;
    username = "user";
    password = "pass";
    realm = "example.org";
  }

let test_allocate_success () =
  Printf.printf "\n=== Allocate/Refresh ===\n";

  test "allocate success sets active state" (fun () ->
    let t = Turn.create (base_config ()) in
    let attrs = bytes_concat [
      build_xor_relayed_attr ~ip:"192.0.2.1" ~port:5000;
      build_lifetime_attr 600;
    ] in
    let responses = [ok_response 0x0103 attrs] in
    let (result, _sends) = run_with_stub ~responses ~now:1000.0 (fun () ->
      Turn.allocate t
    ) in
    match result with
    | Result.Ok (ip, port) ->
      assert_true "relayed address" (ip = "192.0.2.1" && port = 5000);
      assert_true "is active" (Turn.is_active t)
    | Result.Error e -> failwith e
  );

  test "refresh lifetime=0 deallocates" (fun () ->
    let t = Turn.create (base_config ()) in
    let alloc_attrs = bytes_concat [
      build_xor_relayed_attr ~ip:"192.0.2.2" ~port:5001;
      build_lifetime_attr 600;
    ] in
    let refresh_attrs = build_lifetime_attr 0 in
    let responses = [
      ok_response 0x0103 alloc_attrs;
      ok_response 0x0104 refresh_attrs;
    ] in
    let (result, _sends) = run_with_stub ~responses ~now:1000.0 (fun () ->
      let _ = Turn.allocate t in
      Turn.refresh t ~lifetime:0 ()
    ) in
    match result with
    | Result.Ok 0 -> assert_true "inactive" (not (Turn.is_active t))
    | _ -> failwith "Expected Ok 0"
  )

let test_allocate_auth_flow () =
  Printf.printf "\n=== Authenticated Allocate ===\n";

  test "401 -> authenticated allocate" (fun () ->
    let t = Turn.create (base_config ()) in
    let error_resp = err_response 0x0113 "example.org" "nonce-1" 4 1 in
    let ok_attrs = bytes_concat [
      build_xor_relayed_attr ~ip:"192.0.2.3" ~port:5002;
      build_lifetime_attr 600;
    ] in
    let ok_resp = ok_response 0x0103 ok_attrs in
    let responses = [error_resp; ok_resp] in
    let (result, sends) = run_with_stub ~responses ~now:1000.0 (fun () ->
      Turn.allocate t
    ) in
    match result with
    | Result.Ok _ ->
      assert_true "two sends" (List.length sends = 2);
      assert_true "active" (Turn.is_active t)
    | Result.Error e -> failwith e
  )

let test_permissions_and_channel_data () =
  Printf.printf "\n=== Permissions/Channels ===\n";

  test "CreatePermission + ChannelBind + channel data" (fun () ->
    let t = Turn.create (base_config ()) in
    let alloc_attrs = bytes_concat [
      build_xor_relayed_attr ~ip:"192.0.2.4" ~port:5003;
      build_lifetime_attr 600;
    ] in
    let responses = [
      ok_response 0x0103 alloc_attrs;
      ok_response 0x0108 Bytes.empty;
      ok_response 0x0109 Bytes.empty;
    ] in
    let data = Bytes.of_string "ping" in
    let (result, sends) = run_with_stub ~responses ~now:1000.0 (fun () ->
      let _ = Turn.allocate t in
      let _ = Turn.create_permission t "198.51.100.1" in
      let _ = Turn.channel_bind t 0x4000 ("198.51.100.1", 9000) in
      Turn.send_data t ("198.51.100.1", 9000) data
    ) in
    (match result with
    | Result.Ok () -> ()
    | Result.Error e -> failwith e);
    let last_send = List.hd (List.rev sends) in
    let (payload, _host, _port) = last_send in
    let chan = Bytes.get_uint16_be payload 0 in
    let len = Bytes.get_uint16_be payload 2 in
    assert_true "channel number" (chan = 0x4000);
    assert_true "payload length" (len = Bytes.length data)
  );

  test "send indication when no channel" (fun () ->
    let t = Turn.create (base_config ()) in
    let responses = [] in
    let (result, sends) = run_with_stub ~responses ~now:1000.0 (fun () ->
      Turn.send_data t ("203.0.113.10", 9001) (Bytes.of_string "pong")
    ) in
    (match result with
    | Result.Ok () -> ()
    | Result.Error e -> failwith e);
    let (payload, _host, _port) = List.hd sends in
    let msg_type = Bytes.get_uint16_be payload 0 in
    assert_true "send indication" (msg_type = 0x0016)
  );

  test "channel number range check" (fun () ->
    let t = Turn.create (base_config ()) in
    match Turn.channel_bind t 0x3000 ("198.51.100.1", 9000) with
    | Result.Error _ -> ()
    | Result.Ok () -> failwith "Expected error for invalid channel number"
  )

let () =
  test_allocate_success ();
  test_allocate_auth_flow ();
  test_permissions_and_channel_data ();
  Printf.printf "\nTURN tests: %d passed, %d failed\n" !passed !failed;
  if !failed > 0 then exit 1
