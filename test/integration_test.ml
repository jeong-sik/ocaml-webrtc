(* WebRTC Pure OCaml - Integration Test Suite *)
open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... " name;
  try
    f ();
    incr passed;
    Printf.printf "✅ PASS\n"
  with
  | e ->
    incr failed;
    Printf.printf "❌ FAIL (%s)\n" (Printexc.to_string e)
;;

let assert_true msg b = if not b then failwith msg

let assert_equal msg a b =
  if a <> b
  then failwith (Printf.sprintf "%s: %s <> %s" msg (string_of_int a) (string_of_int b))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 1. ECDHE Tests *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_ecdhe () =
  Printf.printf "\n═══ 1. ECDHE P-256 (RFC 8422) ═══\n";
  test "Key generation" (fun () ->
    match Ecdhe.generate_p256 () with
    | Ok kp ->
      let pub = Ecdhe.public_key kp in
      assert_true "Public key should be 65 bytes" (Cstruct.length pub = 65)
    | Error e -> failwith e);
  test "Key exchange" (fun () ->
    match Ecdhe.generate_p256 (), Ecdhe.generate_p256 () with
    | Ok alice, Ok bob ->
      let alice_pub = Ecdhe.public_key alice in
      let bob_pub = Ecdhe.public_key bob in
      (match
         ( Ecdhe.compute_shared_secret ~keypair:alice ~peer_public_key:bob_pub
         , Ecdhe.compute_shared_secret ~keypair:bob ~peer_public_key:alice_pub )
       with
       | Ok s1, Ok s2 ->
         assert_true "Shared secrets must match" (Cstruct.equal s1 s2);
         assert_true "Shared secret should be 32 bytes" (Cstruct.length s1 = 32)
       | _ -> failwith "Shared secret computation failed")
    | _ -> failwith "Key generation failed");
  test "Multiple exchanges produce different secrets" (fun () ->
    match Ecdhe.generate_p256 (), Ecdhe.generate_p256 (), Ecdhe.generate_p256 () with
    | Ok a, Ok b, Ok c ->
      let ab =
        Ecdhe.compute_shared_secret ~keypair:a ~peer_public_key:(Ecdhe.public_key b)
      in
      let ac =
        Ecdhe.compute_shared_secret ~keypair:a ~peer_public_key:(Ecdhe.public_key c)
      in
      (match ab, ac with
       | Ok s1, Ok s2 ->
         assert_true
           "Different peers should produce different secrets"
           (not (Cstruct.equal s1 s2))
       | _ -> failwith "Computation failed")
    | _ -> failwith "Key generation failed")
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 2. AES-GCM Tests *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_aes_gcm () =
  Printf.printf "\n═══ 2. AES-GCM (RFC 5288) ═══\n";
  test "Encrypt/decrypt roundtrip" (fun () ->
    let key = Cstruct.create 16 in
    for i = 0 to 15 do
      Cstruct.set_uint8 key i (i + 1)
    done;
    let iv = Cstruct.create 4 in
    let nonce = Cstruct.create 8 in
    let aad = Cstruct.of_string "test aad" in
    let plaintext = Cstruct.of_string "Hello WebRTC!" in
    let ciphertext =
      Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv:iv
        ~explicit_nonce:nonce
        ~aad
        ~plaintext
    in
    assert_true
      "Ciphertext should be plaintext + 16 bytes tag"
      (Cstruct.length ciphertext = Cstruct.length plaintext + 16);
    match
      Webrtc_crypto.aes_gcm_decrypt
        ~key
        ~implicit_iv:iv
        ~explicit_nonce:nonce
        ~aad
        ~ciphertext_and_tag:ciphertext
    with
    | Ok decrypted ->
      assert_true "Decryption should match" (Cstruct.equal plaintext decrypted)
    | Error e -> failwith e);
  test "Tampered ciphertext fails" (fun () ->
    let key = Cstruct.create 16 in
    let iv = Cstruct.create 4 in
    let nonce = Cstruct.create 8 in
    let aad = Cstruct.of_string "aad" in
    let plaintext = Cstruct.of_string "secret" in
    let ciphertext =
      Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv:iv
        ~explicit_nonce:nonce
        ~aad
        ~plaintext
    in
    (* Tamper with ciphertext *)
    Cstruct.set_uint8 ciphertext 0 (Cstruct.get_uint8 ciphertext 0 lxor 0xFF);
    match
      Webrtc_crypto.aes_gcm_decrypt
        ~key
        ~implicit_iv:iv
        ~explicit_nonce:nonce
        ~aad
        ~ciphertext_and_tag:ciphertext
    with
    | Ok _ -> failwith "Should have failed authentication"
    | Error _ -> () (* Expected *));
  test "Different AAD fails" (fun () ->
    let key = Cstruct.create 16 in
    let iv = Cstruct.create 4 in
    let nonce = Cstruct.create 8 in
    let aad1 = Cstruct.of_string "aad1" in
    let aad2 = Cstruct.of_string "aad2" in
    let plaintext = Cstruct.of_string "data" in
    let ciphertext =
      Webrtc_crypto.aes_gcm_encrypt
        ~key
        ~implicit_iv:iv
        ~explicit_nonce:nonce
        ~aad:aad1
        ~plaintext
    in
    match
      Webrtc_crypto.aes_gcm_decrypt
        ~key
        ~implicit_iv:iv
        ~explicit_nonce:nonce
        ~aad:aad2
        ~ciphertext_and_tag:ciphertext
    with
    | Ok _ -> failwith "Should have failed with different AAD"
    | Error _ -> ())
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 3. TLS PRF Tests *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_tls_prf () =
  Printf.printf "\n═══ 3. TLS 1.2 PRF (RFC 5246) ═══\n";
  test "PRF produces deterministic output" (fun () ->
    let secret = Cstruct.of_string "master_secret_here_32_bytes!!!!!" in
    let label = "key expansion" in
    let seed =
      Cstruct.of_string "client_random_32_bytes__________server_random_32_bytes__________"
    in
    let out1 = Webrtc_crypto.prf_sha256 ~secret ~label ~seed ~length:48 in
    let out2 = Webrtc_crypto.prf_sha256 ~secret ~label ~seed ~length:48 in
    assert_true "PRF should be deterministic" (Cstruct.equal out1 out2));
  test "Different labels produce different output" (fun () ->
    let secret = Cstruct.of_string "secret_32_bytes_long_enough!!!!!" in
    let seed = Cstruct.of_string "seed_data" in
    let out1 = Webrtc_crypto.prf_sha256 ~secret ~label:"label1" ~seed ~length:32 in
    let out2 = Webrtc_crypto.prf_sha256 ~secret ~label:"label2" ~seed ~length:32 in
    assert_true
      "Different labels should produce different output"
      (not (Cstruct.equal out1 out2)));
  test "Key material expansion" (fun () ->
    let pre_master = Cstruct.of_string "pre_master_secret_32_bytes_long!" in
    let client_random = Cstruct.create 32 in
    let server_random = Cstruct.create 32 in
    (* First derive master secret *)
    let master_secret =
      Webrtc_crypto.derive_master_secret
        ~pre_master_secret:pre_master
        ~client_random
        ~server_random
    in
    (* Then derive key material from master secret *)
    let keys =
      Webrtc_crypto.derive_key_material
        ~master_secret
        ~client_random
        ~server_random
        ~key_size:16
        ~iv_size:4
    in
    assert_true
      "Client write key should be 16 bytes"
      (Cstruct.length keys.client_write_key = 16);
    assert_true
      "Server write key should be 16 bytes"
      (Cstruct.length keys.server_write_key = 16);
    assert_true
      "Client write IV should be 4 bytes"
      (Cstruct.length keys.client_write_iv = 4);
    assert_true
      "Server write IV should be 4 bytes"
      (Cstruct.length keys.server_write_iv = 4))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 4. SCTP Tests *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_sctp () =
  Printf.printf "\n═══ 4. SCTP (RFC 4960 + Optimizations) ═══\n";
  test "Default config has optimized values" (fun () ->
    let cfg = Sctp.default_config in
    assert_equal "MTU should be 1280" cfg.mtu 1280;
    assert_equal "a_rwnd should be 256KB" cfg.a_rwnd 262144;
    assert_equal "RTO initial should be 1000ms" cfg.rto_initial_ms 1000);
  test "Association creation with IW10" (fun () ->
    let assoc = Sctp.create Sctp.default_config in
    let state = Sctp.get_state assoc in
    assert_true "Initial state should be Closed" (state = Sctp.Closed));
  test "DATA chunk encode/decode roundtrip" (fun () ->
    let chunk : Sctp.data_chunk =
      { tsn = 12345l
      ; stream_id = 1
      ; stream_seq = 0
      ; ppid = 51l
      ; (* WebRTC String PPID *)
        user_data = Bytes.of_string "Hello SCTP!"
      ; flags =
          { begin_fragment = true
          ; end_fragment = true
          ; unordered = false
          ; immediate = false
          }
      }
    in
    let encoded = Sctp.encode_data_chunk chunk in
    match Sctp.decode_data_chunk encoded with
    | Ok decoded ->
      assert_true "TSN should match" (decoded.tsn = chunk.tsn);
      assert_true "Stream ID should match" (decoded.stream_id = chunk.stream_id);
      assert_true "Data should match" (decoded.user_data = chunk.user_data)
    | Error e -> failwith e);
  test "Data fragmentation" (fun () ->
    let large_data = Bytes.make 5000 'X' in
    (* Larger than MTU *)
    let fragments =
      Sctp.fragment_data
        ~data:large_data
        ~stream_id:1
        ~stream_seq:0
        ~ppid:51l
        ~start_tsn:1000l
        ~mtu:1280
    in
    assert_true "Should produce multiple fragments" (List.length fragments > 1);
    (* Check first/last flags *)
    let first = List.hd fragments in
    let last = List.hd (List.rev fragments) in
    assert_true "First fragment should have B flag" first.flags.begin_fragment;
    assert_true "First fragment should not have E flag" (not first.flags.end_fragment);
    assert_true "Last fragment should have E flag" last.flags.end_fragment;
    assert_true "Last fragment should not have B flag" (not last.flags.begin_fragment);
    assert_true "Last fragment should have I flag (immediate)" last.flags.immediate);
  test "Batch encoding" (fun () ->
    let chunks =
      List.init 5 (fun i ->
        Sctp.
          { tsn = Int32.of_int (1000 + i)
          ; stream_id = 1
          ; stream_seq = i
          ; ppid = 51l
          ; user_data = Bytes.of_string (Printf.sprintf "msg%d" i)
          ; flags =
              { begin_fragment = true
              ; end_fragment = true
              ; unordered = false
              ; immediate = false
              }
          })
    in
    let packets = Sctp.encode_data_chunks_batch chunks ~mtu:1280 in
    (* All 5 small chunks should fit in 1 packet *)
    assert_true
      "Small chunks should be batched into fewer packets"
      (List.length packets <= 2))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 5. ICE Tests *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_ice () =
  Printf.printf "\n═══ 5. ICE + Trickle ICE (RFC 8445/8838) ═══\n";
  test "Agent creation" (fun () ->
    let agent = Ice.create Ice.default_config in
    let state = Ice.get_state agent in
    assert_true "Initial state should be New" (state = Ice.New));
  test "Credential generation" (fun () ->
    let agent = Ice.create Ice.default_config in
    let ufrag, pwd = Ice.get_local_credentials agent in
    assert_true "ufrag should be 4+ chars" (String.length ufrag >= 4);
    assert_true "pwd should be 22+ chars" (String.length pwd >= 22));
  test "Trickle ICE callback registration" (fun () ->
    let agent = Ice.create Ice.default_config in
    let callback_called = ref false in
    Ice.on_candidate agent (fun _candidate -> callback_called := true);
    (* Manually test callback *)
    let test_candidate : Ice.candidate =
      { foundation = "test"
      ; component = 1
      ; transport = Ice.UDP
      ; priority = 12345
      ; address = "192.168.1.1"
      ; port = 5000
      ; cand_type = Ice.Host
      ; base_address = None
      ; base_port = None
      ; related_address = None
      ; related_port = None
      ; extensions = []
      }
    in
    Ice.add_local_candidate agent test_candidate;
    assert_true "Callback should be called on add_local_candidate" !callback_called);
  test "Remote candidate adds and forms pairs" (fun () ->
    let agent = Ice.create Ice.default_config in
    (* Add a local candidate first *)
    let local : Ice.candidate =
      { foundation = "local"
      ; component = 1
      ; transport = Ice.UDP
      ; priority = 2130706431
      ; (* Host priority *)
        address = "192.168.1.100"
      ; port = 5000
      ; cand_type = Ice.Host
      ; base_address = None
      ; base_port = None
      ; related_address = None
      ; related_port = None
      ; extensions = []
      }
    in
    Ice.add_local_candidate agent local;
    (* Add remote candidate *)
    let remote : Ice.candidate =
      { foundation = "remote"
      ; component = 1
      ; transport = Ice.UDP
      ; priority = 2130706431
      ; address = "192.168.1.200"
      ; port = 6000
      ; cand_type = Ice.Host
      ; base_address = None
      ; base_port = None
      ; related_address = None
      ; related_port = None
      ; extensions = []
      }
    in
    Ice.add_remote_candidate agent remote;
    let pairs = Ice.get_pairs agent in
    assert_true "Should have formed at least one pair" (List.length pairs >= 1));
  test "ICE restart clears state" (fun () ->
    let agent = Ice.create Ice.default_config in
    let old_ufrag, _ = Ice.get_local_credentials agent in
    Ice.restart agent;
    let new_ufrag, _ = Ice.get_local_credentials agent in
    assert_true "Restart should generate new credentials" (old_ufrag <> new_ufrag))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* 6. STUN Tests *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_stun () =
  Printf.printf "\n═══ 6. STUN (RFC 5389) ═══\n";
  test "Binding request creation and encoding" (fun () ->
    let msg = Stun.create_binding_request () in
    let encoded = Stun.encode msg in
    assert_true "Encoded request should not be empty" (Bytes.length encoded > 0);
    (* Check magic cookie at offset 4 *)
    let magic = Bytes.get_int32_be encoded 4 in
    assert_true "Magic cookie should be 0x2112A442" (magic = 0x2112A442l));
  test "HMAC-SHA1 integrity calculation" (fun () ->
    let msg = Stun.create_binding_request () in
    let key = "testpassword" in
    let integrity = Stun.calculate_integrity msg ~key in
    (* HMAC-SHA1 produces 20 bytes *)
    assert_true "Integrity should be 20 bytes" (Bytes.length integrity = 20))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     WebRTC Pure OCaml - Integration Test Suite                ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";
  test_ecdhe ();
  test_aes_gcm ();
  test_tls_prf ();
  test_sctp ();
  test_ice ();
  test_stun ();
  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";
  if !failed > 0 then exit 1
;;
