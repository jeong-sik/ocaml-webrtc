(** SRTP Test Suite (RFC 3711) *)

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

let bytes_of_hex s =
  let is_hex = function
    | '0' .. '9' | 'a' .. 'f' | 'A' .. 'F' -> true
    | _ -> false
  in
  let clean =
    String.to_seq s |> Seq.filter is_hex |> List.of_seq |> List.to_seq |> String.of_seq
  in
  if String.length clean mod 2 <> 0 then invalid_arg "hex string must be even length";
  let len = String.length clean / 2 in
  let buf = Bytes.create len in
  for i = 0 to len - 1 do
    let byte = int_of_string ("0x" ^ String.sub clean (i * 2) 2) in
    Bytes.set_uint8 buf i byte
  done;
  buf
;;

let hex_of_bytes b =
  let hex = "0123456789ABCDEF" in
  let out = Bytes.create (Bytes.length b * 2) in
  for i = 0 to Bytes.length b - 1 do
    let v = Bytes.get_uint8 b i in
    Bytes.set out (i * 2) hex.[v lsr 4];
    Bytes.set out ((i * 2) + 1) hex.[v land 0x0F]
  done;
  Bytes.to_string out
;;

let assert_hex what expected actual =
  let actual_hex = hex_of_bytes actual in
  if String.uppercase_ascii expected <> actual_hex
  then failwith (Printf.sprintf "%s: expected %s, got %s" what expected actual_hex)
;;

let assert_eq what expected actual =
  if expected <> actual
  then failwith (Printf.sprintf "%s: expected %d, got %d" what expected actual)
;;

let assert_true what cond =
  if not cond then failwith (Printf.sprintf "%s: expected true" what)
;;

let () =
  Printf.printf "===============================================================\n";
  Printf.printf "SRTP Test Suite (RFC 3711)\n";
  Printf.printf "===============================================================\n";
  section "Key Derivation Vectors (RFC 3711 B.3)";
  test "derive cipher key, salt, auth key" (fun () ->
    let master_key = bytes_of_hex "E1F97A0D3E018BE0D64FA32C06DE4139" in
    let master_salt = bytes_of_hex "0EC675AD498AFEEBB6960B3AABE6" in
    let master = { Srtp.key = master_key; salt = master_salt } in
    let k_e =
      Srtp.derive_key ~master ~label:0x00 ~key_derivation_rate:0L ~index:0L ~out_len:16
    in
    let k_s =
      Srtp.derive_key ~master ~label:0x02 ~key_derivation_rate:0L ~index:0L ~out_len:14
    in
    let k_a =
      Srtp.derive_key ~master ~label:0x01 ~key_derivation_rate:0L ~index:0L ~out_len:20
    in
    match k_e, k_s, k_a with
    | Ok enc, Ok salt, Ok auth ->
      assert_hex "cipher key" "C61E7A93744F39EE10734AFE3FF7A087" enc;
      assert_hex "cipher salt" "30CBBC08863D8C85D49DB34A9AE1" salt;
      assert_hex
        "auth key (first 20 bytes)"
        "CEBE321F6FF7716B6FD4AB49AF256A156D38BAA4"
        auth
    | Error e, _, _ | _, Error e, _ | _, _, Error e -> failwith e);
  section "AES-CM Keystream (RFC 3711 B.2)";
  test "first keystream block" (fun () ->
    let session_key = bytes_of_hex "2B7E151628AED2A6ABF7158809CF4F3C" in
    let session_salt = bytes_of_hex "F0F1F2F3F4F5F6F7F8F9FAFBFCFD" in
    let iv =
      match Srtp.srtp_iv ~salt:session_salt ~ssrc:0l ~index:0L with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_hex "IV" "F0F1F2F3F4F5F6F7F8F9FAFBFCFD0000" iv;
    let keystream =
      match Srtp.aes_cm_crypt ~key:session_key ~iv ~payload:(Bytes.make 16 '\x00') with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_hex "keystream block" "E03EAD0935C95E80E166B16DD92B4EB4" keystream);
  section "Auth + Encrypt Roundtrip";
  test "encrypt/decrypt roundtrip" (fun () ->
    let master_key = bytes_of_hex "E1F97A0D3E018BE0D64FA32C06DE4139" in
    let master_salt = bytes_of_hex "0EC675AD498AFEEBB6960B3AABE6" in
    let master = { Srtp.key = master_key; salt = master_salt } in
    let keys =
      match
        Srtp.derive_session_keys
          ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
          ~master
          ~key_derivation_rate:0L
          ~index:0L
      with
      | Ok k -> k
      | Error e -> failwith e
    in
    let iv =
      match Srtp.srtp_iv ~salt:keys.srtp_salt_key ~ssrc:0x12345678l ~index:0L with
      | Ok v -> v
      | Error e -> failwith e
    in
    let plaintext = Bytes.of_string "hello-srtp" in
    let ciphertext =
      match Srtp.aes_cm_crypt ~key:keys.srtp_encryption_key ~iv ~payload:plaintext with
      | Ok v -> v
      | Error e -> failwith e
    in
    let decrypted =
      match Srtp.aes_cm_crypt ~key:keys.srtp_encryption_key ~iv ~payload:ciphertext with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_true "roundtrip" (Bytes.equal plaintext decrypted));
  test "auth tag length" (fun () ->
    let master_key = bytes_of_hex "E1F97A0D3E018BE0D64FA32C06DE4139" in
    let master_salt = bytes_of_hex "0EC675AD498AFEEBB6960B3AABE6" in
    let master = { Srtp.key = master_key; salt = master_salt } in
    let keys =
      match
        Srtp.derive_session_keys
          ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_32
          ~master
          ~key_derivation_rate:0L
          ~index:0L
      with
      | Ok k -> k
      | Error e -> failwith e
    in
    let packet = Bytes.of_string "rtp-packet" in
    let tag =
      Srtp.srtp_auth_tag
        ~auth_key:keys.srtp_auth_key
        ~packet
        ~roc:0l
        ~tag_len:
          (Srtp.params_of_profile Srtp.SRTP_AES128_CM_HMAC_SHA1_32).srtp_auth_tag_len
    in
    assert_eq "tag length" 4 (Bytes.length tag));
  section "Protect/Unprotect";
  test "SRTP RTP protect/unprotect" (fun () ->
    let master_key = bytes_of_hex "E1F97A0D3E018BE0D64FA32C06DE4139" in
    let master_salt = bytes_of_hex "0EC675AD498AFEEBB6960B3AABE6" in
    let master = { Srtp.key = master_key; salt = master_salt } in
    let keys =
      match
        Srtp.derive_session_keys
          ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
          ~master
          ~key_derivation_rate:0L
          ~index:0L
      with
      | Ok k -> k
      | Error e -> failwith e
    in
    let header =
      Rtp.default_header
        ~payload_type:111
        ~sequence:0x100
        ~timestamp:1234l
        ~ssrc:0x11223344l
        ()
    in
    let payload = Bytes.of_string "hello-rtp" in
    let packet =
      match Rtp.encode header ~payload with
      | Ok p -> p
      | Error e -> failwith e
    in
    let protected =
      match
        Srtp.protect_rtp ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80 ~keys ~roc:0l ~packet
      with
      | Ok p -> p
      | Error e -> failwith e
    in
    let decrypted =
      match
        Srtp.unprotect_rtp
          ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
          ~keys
          ~roc:0l
          ~packet:protected
      with
      | Ok p -> p
      | Error e -> failwith e
    in
    assert_true "rtp roundtrip" (Bytes.equal packet decrypted));
  test "SRTCP protect/unprotect" (fun () ->
    let master_key = bytes_of_hex "E1F97A0D3E018BE0D64FA32C06DE4139" in
    let master_salt = bytes_of_hex "0EC675AD498AFEEBB6960B3AABE6" in
    let master = { Srtp.key = master_key; salt = master_salt } in
    let keys =
      match
        Srtp.derive_session_keys
          ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
          ~master
          ~key_derivation_rate:0L
          ~index:0L
      with
      | Ok k -> k
      | Error e -> failwith e
    in
    let sr =
      Rtcp.Sender_report
        { ssrc = 0x01020304l
        ; sender_info =
            { ntp_sec = 1l
            ; ntp_frac = 2l
            ; rtp_timestamp = 3l
            ; packet_count = 4l
            ; octet_count = 5l
            }
        ; report_blocks = []
        }
    in
    let rtcp = Rtcp.encode sr in
    let srtcp =
      match
        Srtp.protect_rtcp
          ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
          ~keys
          ~index:1l
          ~encrypt:true
          ~packet:rtcp
      with
      | Ok p -> p
      | Error e -> failwith e
    in
    let rtcp_out, index_out =
      match
        Srtp.unprotect_rtcp ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80 ~keys ~packet:srtcp
      with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_eq "index" 1 (Int32.to_int index_out);
    assert_true "rtcp roundtrip" (Bytes.equal rtcp rtcp_out));
  section "AES-GCM AEAD (RFC 7714)";
  test "GCM IV construction (SRTP)" (fun () ->
    let salt = bytes_of_hex "000102030405060708090A0B" in
    (* 12 bytes *)
    let ssrc = 0x12345678l in
    let index = 0x123456789ABCL in
    let iv =
      match Srtp.srtp_gcm_iv ~salt ~ssrc ~index with
      | Ok v -> v
      | Error e -> failwith e
    in
    (* IV = salt XOR (0x00 || 0x00 || SSRC || 0x00 || 0x00 || index[6]) *)
    (* Build expected: 0x00 0x00 0x12 0x34 0x56 0x78 0x12 0x34 0x56 0x78 0x9A 0xBC *)
    (* XOR with salt: 0x00 0x01 0x02 0x03 0x04 0x05 0x06 0x07 0x08 0x09 0x0A 0x0B *)
    (* Result should be computed by XOR *)
    assert_eq "GCM IV length" 12 (Bytes.length iv));
  test "GCM IV construction (SRTCP)" (fun () ->
    let salt = bytes_of_hex "000102030405060708090A0B" in
    (* 12 bytes *)
    let ssrc = 0x11223344l in
    let index = 0x00001234l in
    let iv =
      match Srtp.srtcp_gcm_iv ~salt ~ssrc ~index with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_eq "SRTCP GCM IV length" 12 (Bytes.length iv));
  test "AES-128-GCM encrypt/decrypt" (fun () ->
    let key = bytes_of_hex "000102030405060708090A0B0C0D0E0F" in
    (* 16 bytes *)
    let iv = bytes_of_hex "000102030405060708090A0B" in
    (* 12 bytes *)
    let aad = bytes_of_hex "FEEDFACE" in
    let plaintext = Bytes.of_string "hello-gcm" in
    let ciphertext =
      match Srtp.aes_gcm_encrypt ~key ~iv ~aad ~plaintext with
      | Ok v -> v
      | Error e -> failwith e
    in
    (* Ciphertext should be plaintext_len + 16 bytes (tag) *)
    assert_eq "ciphertext length" (Bytes.length plaintext + 16) (Bytes.length ciphertext);
    let decrypted =
      match Srtp.aes_gcm_decrypt ~key ~iv ~aad ~ciphertext_and_tag:ciphertext with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_true "GCM roundtrip" (Bytes.equal plaintext decrypted));
  test "AES-256-GCM encrypt/decrypt" (fun () ->
    let key =
      bytes_of_hex "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    in
    (* 32 bytes *)
    let iv = bytes_of_hex "000102030405060708090A0B" in
    (* 12 bytes *)
    let aad = bytes_of_hex "FEEDFACE" in
    let plaintext = Bytes.of_string "hello-gcm-256" in
    let ciphertext =
      match Srtp.aes_gcm_encrypt ~key ~iv ~aad ~plaintext with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_eq "ciphertext length" (Bytes.length plaintext + 16) (Bytes.length ciphertext);
    let decrypted =
      match Srtp.aes_gcm_decrypt ~key ~iv ~aad ~ciphertext_and_tag:ciphertext with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_true "GCM-256 roundtrip" (Bytes.equal plaintext decrypted));
  test "GCM auth failure on tampered ciphertext" (fun () ->
    let key = bytes_of_hex "000102030405060708090A0B0C0D0E0F" in
    let iv = bytes_of_hex "000102030405060708090A0B" in
    let aad = bytes_of_hex "FEEDFACE" in
    let plaintext = Bytes.of_string "secret" in
    let ciphertext =
      match Srtp.aes_gcm_encrypt ~key ~iv ~aad ~plaintext with
      | Ok v -> v
      | Error e -> failwith e
    in
    (* Tamper with ciphertext *)
    let tampered = Bytes.copy ciphertext in
    Bytes.set_uint8 tampered 0 (Bytes.get_uint8 tampered 0 lxor 0xFF);
    let result = Srtp.aes_gcm_decrypt ~key ~iv ~aad ~ciphertext_and_tag:tampered in
    match result with
    | Ok _ -> failwith "Expected auth failure"
    | Error _ -> () (* Expected *));
  test "SRTP-GCM protect/unprotect (AES-128)" (fun () ->
    (* For GCM, master salt is 12 bytes *)
    let master_key = bytes_of_hex "E1F97A0D3E018BE0D64FA32C06DE4139" in
    let master_salt = bytes_of_hex "0EC675AD498AFEEBB6960B3A" in
    (* 12 bytes for GCM *)
    (* Use master key directly as session key (simplified test) *)
    let keys =
      { Srtp.srtp_encryption_key = master_key
      ; srtp_auth_key = Bytes.empty
      ; (* Not used for GCM *)
        srtp_salt_key = master_salt
      ; srtcp_encryption_key = master_key
      ; srtcp_auth_key = Bytes.empty
      ; srtcp_salt_key = master_salt
      }
    in
    let header =
      Rtp.default_header
        ~payload_type:111
        ~sequence:0x100
        ~timestamp:1234l
        ~ssrc:0x11223344l
        ()
    in
    let payload = Bytes.of_string "hello-srtp-gcm" in
    let packet =
      match Rtp.encode header ~payload with
      | Ok p -> p
      | Error e -> failwith e
    in
    let protected =
      match
        Srtp.protect_rtp ~profile:Srtp.SRTP_AEAD_AES_128_GCM ~keys ~roc:0l ~packet
      with
      | Ok p -> p
      | Error e -> failwith e
    in
    (* Protected should be header + ciphertext + 16-byte tag *)
    assert_eq "protected length" (Bytes.length packet + 16) (Bytes.length protected);
    let decrypted =
      match
        Srtp.unprotect_rtp
          ~profile:Srtp.SRTP_AEAD_AES_128_GCM
          ~keys
          ~roc:0l
          ~packet:protected
      with
      | Ok p -> p
      | Error e -> failwith e
    in
    assert_true "SRTP-GCM roundtrip" (Bytes.equal packet decrypted));
  test "SRTCP-GCM protect/unprotect (AES-128)" (fun () ->
    let master_key = bytes_of_hex "E1F97A0D3E018BE0D64FA32C06DE4139" in
    let master_salt = bytes_of_hex "0EC675AD498AFEEBB6960B3A" in
    (* 12 bytes *)
    let keys =
      { Srtp.srtp_encryption_key = master_key
      ; srtp_auth_key = Bytes.empty
      ; srtp_salt_key = master_salt
      ; srtcp_encryption_key = master_key
      ; srtcp_auth_key = Bytes.empty
      ; srtcp_salt_key = master_salt
      }
    in
    let sr =
      Rtcp.Sender_report
        { ssrc = 0x01020304l
        ; sender_info =
            { ntp_sec = 1l
            ; ntp_frac = 2l
            ; rtp_timestamp = 3l
            ; packet_count = 4l
            ; octet_count = 5l
            }
        ; report_blocks = []
        }
    in
    let rtcp = Rtcp.encode sr in
    let srtcp =
      match
        Srtp.protect_rtcp
          ~profile:Srtp.SRTP_AEAD_AES_128_GCM
          ~keys
          ~index:1l
          ~encrypt:true
          ~packet:rtcp
      with
      | Ok p -> p
      | Error e -> failwith e
    in
    let rtcp_out, index_out =
      match
        Srtp.unprotect_rtcp ~profile:Srtp.SRTP_AEAD_AES_128_GCM ~keys ~packet:srtcp
      with
      | Ok v -> v
      | Error e -> failwith e
    in
    assert_eq "SRTCP index" 1 (Int32.to_int index_out);
    assert_true "SRTCP-GCM roundtrip" (Bytes.equal rtcp rtcp_out));
  test "is_aead_profile" (fun () ->
    assert_true "AES-128-GCM is AEAD" (Srtp.is_aead_profile Srtp.SRTP_AEAD_AES_128_GCM);
    assert_true "AES-256-GCM is AEAD" (Srtp.is_aead_profile Srtp.SRTP_AEAD_AES_256_GCM);
    assert_true
      "AES-CM is not AEAD"
      (not (Srtp.is_aead_profile Srtp.SRTP_AES128_CM_HMAC_SHA1_80)));
  test "GCM profile params" (fun () ->
    let params128 = Srtp.params_of_profile Srtp.SRTP_AEAD_AES_128_GCM in
    assert_eq "GCM-128 key len" 16 params128.cipher_key_len;
    assert_eq "GCM-128 salt len" 12 params128.cipher_salt_len;
    assert_eq "GCM-128 auth key len" 0 params128.auth_key_len;
    assert_eq "GCM-128 tag len" 16 params128.srtp_auth_tag_len;
    let params256 = Srtp.params_of_profile Srtp.SRTP_AEAD_AES_256_GCM in
    assert_eq "GCM-256 key len" 32 params256.cipher_key_len;
    assert_eq "GCM-256 salt len" 12 params256.cipher_salt_len;
    assert_eq "GCM-256 tag len" 16 params256.srtp_auth_tag_len);
  Printf.printf "\nPassed: %d, Failed: %d\n%!" !passed !failed;
  if !failed > 0 then exit 1
;;
