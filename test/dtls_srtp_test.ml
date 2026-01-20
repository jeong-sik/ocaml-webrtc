(** DTLS-SRTP Test Suite (RFC 5764) *)

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

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)

let () =
  Printf.printf "===============================================================\n";
  Printf.printf "DTLS-SRTP Test Suite (RFC 5764)\n";
  Printf.printf "===============================================================\n";

  section "Keying Material Split";

  test "split ordering matches RFC 5764" (fun () ->
    let params = Srtp.params_of_profile Srtp.SRTP_AES128_CM_HMAC_SHA1_80 in
    let total_len = 2 * (params.cipher_key_len + params.cipher_salt_len) in
    let material = Bytes.init total_len (fun i -> Char.chr (i land 0xFF)) in
    match Dtls_srtp.split_keying_material
      ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
      material
    with
    | Error e -> failwith e
    | Ok km ->
      assert_eq "client_key len" params.cipher_key_len (Bytes.length km.client_key);
      assert_eq "server_key len" params.cipher_key_len (Bytes.length km.server_key);
      assert_eq "client_salt len" params.cipher_salt_len (Bytes.length km.client_salt);
      assert_eq "server_salt len" params.cipher_salt_len (Bytes.length km.server_salt);
      assert_true "client_key starts at 0"
        (Bytes.get_uint8 km.client_key 0 = 0);
      assert_true "server_key starts at key_len"
        (Bytes.get_uint8 km.server_key 0 = params.cipher_key_len);
      assert_true "client_salt starts after keys"
        (Bytes.get_uint8 km.client_salt 0 = params.cipher_key_len * 2);
      assert_true "server_salt starts after client_salt"
        (Bytes.get_uint8 km.server_salt 0 =
          (params.cipher_key_len * 2) + params.cipher_salt_len)
  );

  section "Masters";

  test "masters_of_key_material wiring" (fun () ->
    let km = {
      Dtls_srtp.client_key = Bytes.init 16 (fun i -> Char.chr i);
      server_key = Bytes.init 16 (fun i -> Char.chr (0x10 + i));
      client_salt = Bytes.init 14 (fun i -> Char.chr (0x20 + i));
      server_salt = Bytes.init 14 (fun i -> Char.chr (0x30 + i));
    } in
    let (client, server) = Dtls_srtp.masters_of_key_material km in
    assert_true "client key" (Bytes.equal client.key km.client_key);
    assert_true "server key" (Bytes.equal server.key km.server_key)
  );

  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
