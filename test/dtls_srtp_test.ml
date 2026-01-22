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

  section "use_srtp Extension (RFC 5764 Section 4.1.2)";

  test "encode/decode use_srtp round-trip" (fun () ->
    let profiles = [Srtp.SRTP_AES128_CM_HMAC_SHA1_80; Srtp.SRTP_AES128_CM_HMAC_SHA1_32] in
    let ext = Dtls_srtp.client_use_srtp profiles in
    (* Skip extension type (2) and length (2), decode data *)
    let data = Bytes.sub ext 4 (Bytes.length ext - 4) in
    match Dtls_srtp.decode_use_srtp_extension data with
    | Error e -> failwith e
    | Ok decoded ->
      assert_eq "profile count" 2 (List.length decoded.profiles);
      assert_true "first profile"
        (List.hd decoded.profiles = Srtp.SRTP_AES128_CM_HMAC_SHA1_80);
      assert_true "MKI empty" (Bytes.length decoded.mki = 0)
  );

  test "profile_to_code mapping" (fun () ->
    assert_eq "SHA1_80 code" 0x0001
      (Dtls_srtp.profile_to_code Srtp.SRTP_AES128_CM_HMAC_SHA1_80);
    assert_eq "SHA1_32 code" 0x0002
      (Dtls_srtp.profile_to_code Srtp.SRTP_AES128_CM_HMAC_SHA1_32);
    assert_eq "NULL_80 code" 0x0005
      (Dtls_srtp.profile_to_code Srtp.SRTP_NULL_HMAC_SHA1_80);
    assert_eq "NULL_32 code" 0x0006
      (Dtls_srtp.profile_to_code Srtp.SRTP_NULL_HMAC_SHA1_32)
  );

  test "code_to_profile mapping" (fun () ->
    assert_true "SHA1_80"
      (Dtls_srtp.code_to_profile 0x0001 = Some Srtp.SRTP_AES128_CM_HMAC_SHA1_80);
    assert_true "SHA1_32"
      (Dtls_srtp.code_to_profile 0x0002 = Some Srtp.SRTP_AES128_CM_HMAC_SHA1_32);
    assert_true "unknown code" (Dtls_srtp.code_to_profile 0x9999 = None)
  );

  test "negotiate_profile" (fun () ->
    (* Client prefers SHA1_32 first, but server only supports SHA1_80 *)
    let client = [Srtp.SRTP_AES128_CM_HMAC_SHA1_32; Srtp.SRTP_AES128_CM_HMAC_SHA1_80] in
    let server = [Srtp.SRTP_AES128_CM_HMAC_SHA1_80; Srtp.SRTP_NULL_HMAC_SHA1_80] in
    match Dtls_srtp.negotiate_profile ~client_profiles:client ~server_supported:server with
    | None -> failwith "Expected negotiation success"
    | Some p -> assert_true "negotiated SHA1_80 (first client profile in server)"
        (p = Srtp.SRTP_AES128_CM_HMAC_SHA1_80)
  );

  test "negotiate_profile no match" (fun () ->
    let client = [Srtp.SRTP_AES128_CM_HMAC_SHA1_32] in
    let server = [Srtp.SRTP_NULL_HMAC_SHA1_80] in
    match Dtls_srtp.negotiate_profile ~client_profiles:client ~server_supported:server with
    | None -> ()  (* Expected: no common profile *)
    | Some _ -> failwith "Expected negotiation failure"
  );

  test "server_use_srtp single profile" (fun () ->
    let ext = Dtls_srtp.server_use_srtp Srtp.SRTP_AES128_CM_HMAC_SHA1_80 in
    let data = Bytes.sub ext 4 (Bytes.length ext - 4) in
    match Dtls_srtp.decode_use_srtp_extension data with
    | Error e -> failwith e
    | Ok decoded ->
      assert_eq "single profile" 1 (List.length decoded.profiles)
  );

  test "extension_type is 14" (fun () ->
    assert_eq "use_srtp type" 14 Dtls_srtp.extension_type_use_srtp
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
