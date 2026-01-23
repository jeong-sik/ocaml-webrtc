(* Quick smoke test for ECDHE and AES-GCM *)
open Webrtc

let () =
  Printf.printf "=== WebRTC Crypto Smoke Test ===\n";
  (* Test ECDHE P-256 *)
  Printf.printf "\n1. ECDHE P-256 Key Exchange:\n";
  (match Ecdhe.generate_p256 (), Ecdhe.generate_p256 () with
   | Ok alice, Ok bob ->
     let alice_pub = Ecdhe.public_key alice in
     let bob_pub = Ecdhe.public_key bob in
     Printf.printf "   Alice pub: %d bytes\n" (Cstruct.length alice_pub);
     Printf.printf "   Bob pub: %d bytes\n" (Cstruct.length bob_pub);
     (match
        ( Ecdhe.compute_shared_secret ~keypair:alice ~peer_public_key:bob_pub
        , Ecdhe.compute_shared_secret ~keypair:bob ~peer_public_key:alice_pub )
      with
      | Ok shared_alice, Ok shared_bob ->
        let match_result = Cstruct.equal shared_alice shared_bob in
        Printf.printf "   Shared secrets match: %b\n" match_result;
        Printf.printf "   Shared secret: %d bytes\n" (Cstruct.length shared_alice);
        if match_result
        then Printf.printf "   ✅ ECDHE P-256: PASS\n"
        else Printf.printf "   ❌ ECDHE P-256: FAIL (mismatch)\n"
      | _ -> Printf.printf "   ❌ ECDHE P-256: FAIL (computation error)\n")
   | _ -> Printf.printf "   ❌ ECDHE P-256: FAIL (keygen error)\n");
  (* Test AES-GCM encryption *)
  Printf.printf "\n2. AES-GCM Encryption:\n";
  let key = Cstruct.create 16 in
  for i = 0 to 15 do
    Cstruct.set_uint8 key i (i + 1)
  done;
  let implicit_iv = Cstruct.create 4 in
  let explicit_nonce = Cstruct.create 8 in
  let aad = Cstruct.of_string "additional data" in
  let plaintext = Cstruct.of_string "Hello WebRTC!" in
  let ciphertext =
    Webrtc_crypto.aes_gcm_encrypt ~key ~implicit_iv ~explicit_nonce ~aad ~plaintext
  in
  Printf.printf "   Plaintext: %d bytes\n" (Cstruct.length plaintext);
  Printf.printf
    "   Ciphertext: %d bytes (includes 16-byte tag)\n"
    (Cstruct.length ciphertext);
  (match
     Webrtc_crypto.aes_gcm_decrypt
       ~key
       ~implicit_iv
       ~explicit_nonce
       ~aad
       ~ciphertext_and_tag:ciphertext
   with
   | Ok decrypted ->
     let match_result = Cstruct.equal plaintext decrypted in
     Printf.printf "   Roundtrip match: %b\n" match_result;
     if match_result
     then Printf.printf "   ✅ AES-GCM: PASS\n"
     else Printf.printf "   ❌ AES-GCM: FAIL (mismatch)\n"
   | Error e -> Printf.printf "   ❌ AES-GCM: FAIL (%s)\n" e);
  Printf.printf "\n=== Tests Complete ===\n"
;;
