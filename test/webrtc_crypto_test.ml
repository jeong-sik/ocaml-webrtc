(** WebRTC Crypto Test Suite

    Tests TLS 1.2 PRF, key derivation, and AES-GCM encrypt/decrypt.

    @author Second Brain
*)

let passed = ref 0
let failed = ref 0

let test name f =
  try
    f ();
    incr passed;
    Printf.printf "  %s... ✅ PASS\n%!" name
  with
  | e ->
    incr failed;
    Printf.printf "  %s... ❌ FAIL: %s\n%!" name (Printexc.to_string e)
;;

let section title = Printf.printf "\n═══ %s ═══\n%!" title

let assert_eq what expected actual =
  if expected <> actual
  then
    failwith
      (Printf.sprintf
         "%s: expected %s, got %s"
         what
         (string_of_int expected)
         (string_of_int actual))
;;

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)
;;

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     WebRTC Crypto Test Suite (RFC 5246, RFC 5288)             ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";
  (* ═══ Constants ═══ *)
  section "Constants";
  test "master_secret_size = 48" (fun () ->
    assert_eq "master_secret_size" 48 Webrtc.Webrtc_crypto.master_secret_size);
  test "aes_128_gcm_key_size = 16" (fun () ->
    assert_eq "aes_128_gcm_key_size" 16 Webrtc.Webrtc_crypto.aes_128_gcm_key_size);
  test "aes_256_gcm_key_size = 32" (fun () ->
    assert_eq "aes_256_gcm_key_size" 32 Webrtc.Webrtc_crypto.aes_256_gcm_key_size);
  test "aes_gcm_implicit_iv_size = 4" (fun () ->
    assert_eq "aes_gcm_implicit_iv_size" 4 Webrtc.Webrtc_crypto.aes_gcm_implicit_iv_size);
  test "aes_gcm_explicit_nonce_size = 8" (fun () ->
    assert_eq
      "aes_gcm_explicit_nonce_size"
      8
      Webrtc.Webrtc_crypto.aes_gcm_explicit_nonce_size);
  test "aes_gcm_tag_size = 16" (fun () ->
    assert_eq "aes_gcm_tag_size" 16 Webrtc.Webrtc_crypto.aes_gcm_tag_size);
  (* ═══ PRF ═══ *)
  section "PRF (RFC 5246 §5)";
  test "prf_sha256 produces correct length" (fun () ->
    let secret = Cstruct.of_string "secret" in
    let seed = Cstruct.of_string "seed" in
    let output = Webrtc.Webrtc_crypto.prf_sha256 ~secret ~label:"test" ~seed ~length:32 in
    assert_eq "output length" 32 (Cstruct.length output));
  test "prf_sha256 deterministic" (fun () ->
    let secret = Cstruct.of_string "mysecret" in
    let seed = Cstruct.of_string "myseed" in
    let out1 = Webrtc.Webrtc_crypto.prf_sha256 ~secret ~label:"test" ~seed ~length:48 in
    let out2 = Webrtc.Webrtc_crypto.prf_sha256 ~secret ~label:"test" ~seed ~length:48 in
    assert_true "outputs equal" (Cstruct.equal out1 out2));
  test "prf_sha256 different labels produce different output" (fun () ->
    let secret = Cstruct.of_string "secret" in
    let seed = Cstruct.of_string "seed" in
    let out1 = Webrtc.Webrtc_crypto.prf_sha256 ~secret ~label:"label1" ~seed ~length:32 in
    let out2 = Webrtc.Webrtc_crypto.prf_sha256 ~secret ~label:"label2" ~seed ~length:32 in
    assert_true "outputs differ" (not (Cstruct.equal out1 out2)));
  (* ═══ Master Secret Derivation ═══ *)
  section "Master Secret Derivation (RFC 5246 §8.1)";
  test "derive_master_secret produces 48 bytes" (fun () ->
    let pre_master = Cstruct.create 32 in
    let client_random = Cstruct.create 32 in
    let server_random = Cstruct.create 32 in
    let master =
      Webrtc.Webrtc_crypto.derive_master_secret
        ~pre_master_secret:pre_master
        ~client_random
        ~server_random
    in
    assert_eq "master secret length" 48 (Cstruct.length master));
  test "derive_master_secret deterministic" (fun () ->
    let pre_master = Cstruct.of_string (String.make 32 'p') in
    let client_random = Cstruct.of_string (String.make 32 'c') in
    let server_random = Cstruct.of_string (String.make 32 's') in
    let m1 =
      Webrtc.Webrtc_crypto.derive_master_secret
        ~pre_master_secret:pre_master
        ~client_random
        ~server_random
    in
    let m2 =
      Webrtc.Webrtc_crypto.derive_master_secret
        ~pre_master_secret:pre_master
        ~client_random
        ~server_random
    in
    assert_true "same inputs produce same master" (Cstruct.equal m1 m2));
  (* ═══ Key Material Derivation ═══ *)
  section "Key Material Derivation (RFC 5246 §6.3)";
  test "derive_key_material produces correct sizes (AES-128-GCM)" (fun () ->
    let master = Cstruct.create 48 in
    let server_random = Cstruct.create 32 in
    let client_random = Cstruct.create 32 in
    let km =
      Webrtc.Webrtc_crypto.derive_key_material
        ~master_secret:master
        ~server_random
        ~client_random
        ~key_size:16
        ~iv_size:4
    in
    assert_eq "client_write_key" 16 (Cstruct.length km.client_write_key);
    assert_eq "server_write_key" 16 (Cstruct.length km.server_write_key);
    assert_eq "client_write_iv" 4 (Cstruct.length km.client_write_iv);
    assert_eq "server_write_iv" 4 (Cstruct.length km.server_write_iv));
  test "derive_key_material produces correct sizes (AES-256-GCM)" (fun () ->
    let master = Cstruct.create 48 in
    let server_random = Cstruct.create 32 in
    let client_random = Cstruct.create 32 in
    let km =
      Webrtc.Webrtc_crypto.derive_key_material
        ~master_secret:master
        ~server_random
        ~client_random
        ~key_size:32
        ~iv_size:4
    in
    assert_eq "client_write_key" 32 (Cstruct.length km.client_write_key);
    assert_eq "server_write_key" 32 (Cstruct.length km.server_write_key));
  test "client and server keys are different" (fun () ->
    let master = Cstruct.of_string (String.make 48 'm') in
    let server_random = Cstruct.of_string (String.make 32 's') in
    let client_random = Cstruct.of_string (String.make 32 'c') in
    let km =
      Webrtc.Webrtc_crypto.derive_key_material
        ~master_secret:master
        ~server_random
        ~client_random
        ~key_size:16
        ~iv_size:4
    in
    assert_true
      "keys differ"
      (not (Cstruct.equal km.client_write_key km.server_write_key)));
  (* ═══ Nonce Building ═══ *)
  section "Nonce Building (RFC 5288 §3)";
  test "build_nonce produces 12 bytes" (fun () ->
    let implicit_iv = Cstruct.create 4 in
    let explicit_nonce = Cstruct.create 8 in
    let nonce = Webrtc.Webrtc_crypto.build_nonce ~implicit_iv ~explicit_nonce in
    assert_eq "nonce length" 12 (Cstruct.length nonce));
  test "build_nonce concatenates correctly" (fun () ->
    let implicit_iv = Cstruct.of_string "AAAA" in
    let explicit_nonce = Cstruct.of_string "BBBBBBBB" in
    let nonce = Webrtc.Webrtc_crypto.build_nonce ~implicit_iv ~explicit_nonce in
    let expected = Cstruct.of_string "AAAABBBBBBBB" in
    assert_true "correct concatenation" (Cstruct.equal nonce expected));
  (* ═══ AES-GCM Encrypt/Decrypt ═══ *)
  section "AES-GCM Encrypt/Decrypt (RFC 5288)";
  test "encrypt then decrypt returns original" (fun () ->
    let key = Cstruct.of_string (String.make 16 'k') in
    let implicit_iv = Cstruct.of_string "AAAA" in
    let explicit_nonce = Cstruct.of_string "12345678" in
    let aad = Cstruct.of_string "header" in
    let plaintext = Cstruct.of_string "Hello, WebRTC!" in
    let ciphertext =
      Webrtc.Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad
        ~plaintext
    in
    (* Ciphertext should be longer (includes 16-byte tag) *)
    assert_true "ciphertext longer" (Cstruct.length ciphertext > Cstruct.length plaintext);
    match
      Webrtc.Webrtc_crypto.aes_gcm_decrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad
        ~ciphertext_and_tag:ciphertext
    with
    | Ok decrypted ->
      assert_true "roundtrip successful" (Cstruct.equal plaintext decrypted)
    | Error e -> failwith e);
  test "decrypt fails with wrong key" (fun () ->
    let key = Cstruct.of_string (String.make 16 'k') in
    let wrong_key = Cstruct.of_string (String.make 16 'x') in
    let implicit_iv = Cstruct.of_string "AAAA" in
    let explicit_nonce = Cstruct.of_string "12345678" in
    let aad = Cstruct.of_string "header" in
    let plaintext = Cstruct.of_string "secret data" in
    let ciphertext =
      Webrtc.Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad
        ~plaintext
    in
    match
      Webrtc.Webrtc_crypto.aes_gcm_decrypt
        ~key:wrong_key
        ~implicit_iv
        ~explicit_nonce
        ~aad
        ~ciphertext_and_tag:ciphertext
    with
    | Ok _ -> failwith "Should have failed with wrong key"
    | Error _ -> () (* Expected *));
  test "decrypt fails with tampered ciphertext" (fun () ->
    let key = Cstruct.of_string (String.make 16 'k') in
    let implicit_iv = Cstruct.of_string "AAAA" in
    let explicit_nonce = Cstruct.of_string "12345678" in
    let aad = Cstruct.of_string "header" in
    let plaintext = Cstruct.of_string "secret data" in
    let ciphertext =
      Webrtc.Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad
        ~plaintext
    in
    (* Tamper with ciphertext - create a copy and modify it *)
    let tampered = Cstruct.create (Cstruct.length ciphertext) in
    Cstruct.blit ciphertext 0 tampered 0 (Cstruct.length ciphertext);
    Cstruct.set_uint8 tampered 0 (Cstruct.get_uint8 tampered 0 lxor 0xFF);
    match
      Webrtc.Webrtc_crypto.aes_gcm_decrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad
        ~ciphertext_and_tag:tampered
    with
    | Ok _ -> failwith "Should have detected tampering"
    | Error _ -> () (* Expected *));
  test "decrypt fails with wrong AAD" (fun () ->
    let key = Cstruct.of_string (String.make 16 'k') in
    let implicit_iv = Cstruct.of_string "AAAA" in
    let explicit_nonce = Cstruct.of_string "12345678" in
    let aad = Cstruct.of_string "header" in
    let wrong_aad = Cstruct.of_string "wrong!" in
    let plaintext = Cstruct.of_string "secret" in
    let ciphertext =
      Webrtc.Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad
        ~plaintext
    in
    match
      Webrtc.Webrtc_crypto.aes_gcm_decrypt
        ~key
        ~implicit_iv
        ~explicit_nonce
        ~aad:wrong_aad
        ~ciphertext_and_tag:ciphertext
    with
    | Ok _ -> failwith "Should have detected AAD mismatch"
    | Error _ -> () (* Expected *));
  (* ═══ Random Generation ═══ *)
  section "Random Generation";
  test "random_bytes produces correct length" (fun () ->
    let r = Webrtc.Webrtc_crypto.random_bytes 32 in
    assert_eq "length" 32 (Cstruct.length r));
  test "random_bytes produces different values" (fun () ->
    let r1 = Webrtc.Webrtc_crypto.random_bytes 16 in
    let r2 = Webrtc.Webrtc_crypto.random_bytes 16 in
    assert_true "different randoms" (not (Cstruct.equal r1 r2)));
  test "generate_random produces 32 bytes" (fun () ->
    let r = Webrtc.Webrtc_crypto.generate_random () in
    assert_eq "length" 32 (Cstruct.length r));
  (* ═══ Results ═══ *)
  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";
  if !failed > 0 then exit 1
;;
