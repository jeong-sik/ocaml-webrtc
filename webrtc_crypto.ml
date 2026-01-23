(** WebRTC Crypto - TLS 1.2 PRF and Key Derivation

    Pure OCaml implementation of cryptographic primitives needed for DTLS handshake.
    Based on RFC 5246 (TLS 1.2) and RFC 5288 (AES-GCM).

    @author Second Brain
    @since ocaml-webrtc 0.2.0
*)

(** {1 Constants} *)

let master_secret_size = 48

(** {1 PRF - Pseudo-Random Function (RFC 5246 Section 5)} *)

(** TLS 1.2 PRF using SHA-256

    PRF(secret, label, seed) = P_SHA256(secret, label + seed)

    P_hash(secret, seed) = HMAC_hash(secret, A(1) + seed) +
                           HMAC_hash(secret, A(2) + seed) +
                           HMAC_hash(secret, A(3) + seed) + ...

    where A(0) = seed
          A(i) = HMAC_hash(secret, A(i-1))
*)
let prf_sha256 ~secret ~label ~seed ~length =
  let module H = Digestif.SHA256 in
  let hmac key data =
    H.hmac_string ~key:(Cstruct.to_string key) (Cstruct.to_string data)
    |> H.to_raw_string
    |> Cstruct.of_string
  in
  let label_seed = Cstruct.concat [ Cstruct.of_string label; seed ] in
  (* P_hash(secret, seed) = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ... *)
  let rec p_hash acc a remaining =
    if remaining <= 0
    then Cstruct.sub (Cstruct.concat (List.rev acc)) 0 length
    else (
      let a_next = hmac secret a in
      let output = hmac secret (Cstruct.concat [ a_next; label_seed ]) in
      p_hash (output :: acc) a_next (remaining - Cstruct.length output))
  in
  let a1 = hmac secret label_seed in
  p_hash [] a1 length
;;

(** {1 Key Derivation (RFC 5246 Section 8.1)} *)

(** Derive master secret from pre-master secret

    master_secret = PRF(pre_master_secret, "master secret",
                        ClientHello.random + ServerHello.random)[0..47]
*)
let derive_master_secret ~pre_master_secret ~client_random ~server_random =
  let seed = Cstruct.concat [ client_random; server_random ] in
  prf_sha256
    ~secret:pre_master_secret
    ~label:"master secret"
    ~seed
    ~length:master_secret_size
;;

(** {1 Key Expansion (RFC 5246 Section 6.3)} *)

(** Key material derived from master secret *)
type key_material =
  { client_write_key : Cstruct.t
  ; server_write_key : Cstruct.t
  ; client_write_iv : Cstruct.t
  ; server_write_iv : Cstruct.t
  }

(** Derive encryption keys from master secret

    key_block = PRF(SecurityParameters.master_secret,
                    "key expansion",
                    SecurityParameters.server_random +
                    SecurityParameters.client_random)
*)
let derive_key_material ~master_secret ~server_random ~client_random ~key_size ~iv_size =
  let seed = Cstruct.concat [ server_random; client_random ] in
  let key_block_length = (2 * key_size) + (2 * iv_size) in
  let key_block =
    prf_sha256 ~secret:master_secret ~label:"key expansion" ~seed ~length:key_block_length
  in
  let offset = ref 0 in
  let take n =
    let result = Cstruct.sub key_block !offset n in
    offset := !offset + n;
    result
  in
  { client_write_key = take key_size
  ; server_write_key = take key_size
  ; client_write_iv = take iv_size
  ; server_write_iv = take iv_size
  }
;;

(** {1 AES-GCM Encryption (RFC 5288)} *)

(** AES-GCM parameters for DTLS 1.2 *)
let aes_128_gcm_key_size = 16

let aes_256_gcm_key_size = 32
let aes_gcm_implicit_iv_size = 4 (* Fixed IV from key derivation *)
let aes_gcm_explicit_nonce_size = 8 (* Explicit nonce per record *)
let aes_gcm_tag_size = 16

(** Build nonce for AES-GCM (RFC 5288 Section 3)
    nonce = implicit_iv (4 bytes) || explicit_nonce (8 bytes) *)
let build_nonce ~implicit_iv ~explicit_nonce =
  Cstruct.concat [ implicit_iv; explicit_nonce ]
;;

(** Encrypt data using AES-GCM
    @param key Write key (16 or 32 bytes)
    @param implicit_iv 4-byte fixed IV from key derivation
    @param explicit_nonce 8-byte per-record nonce (usually sequence number)
    @param aad Additional authenticated data (record header)
    @param plaintext Data to encrypt
    @return ciphertext || tag *)
let aes_gcm_encrypt ~key ~implicit_iv ~explicit_nonce ~aad ~plaintext =
  let nonce = build_nonce ~implicit_iv ~explicit_nonce in
  let key_cs = Cstruct.to_string key in
  let nonce_cs = Cstruct.to_string nonce in
  let aad_cs = Cstruct.to_string aad in
  let plaintext_cs = Cstruct.to_string plaintext in
  (* Use mirage-crypto AES-GCM *)
  let cipher_key = Mirage_crypto.AES.GCM.of_secret key_cs in
  let result =
    Mirage_crypto.AES.GCM.authenticate_encrypt
      ~key:cipher_key
      ~nonce:nonce_cs
      ~adata:aad_cs
      plaintext_cs
  in
  Cstruct.of_string result
;;

(** Decrypt data using AES-GCM
    @param key Read key (16 or 32 bytes)
    @param implicit_iv 4-byte fixed IV from key derivation
    @param explicit_nonce 8-byte per-record nonce (extracted from ciphertext)
    @param aad Additional authenticated data (record header)
    @param ciphertext_and_tag Ciphertext with appended tag
    @return plaintext or error if authentication fails *)
let aes_gcm_decrypt ~key ~implicit_iv ~explicit_nonce ~aad ~ciphertext_and_tag =
  let nonce = build_nonce ~implicit_iv ~explicit_nonce in
  let key_cs = Cstruct.to_string key in
  let nonce_cs = Cstruct.to_string nonce in
  let aad_cs = Cstruct.to_string aad in
  let ciphertext_cs = Cstruct.to_string ciphertext_and_tag in
  let cipher_key = Mirage_crypto.AES.GCM.of_secret key_cs in
  match
    Mirage_crypto.AES.GCM.authenticate_decrypt
      ~key:cipher_key
      ~nonce:nonce_cs
      ~adata:aad_cs
      ciphertext_cs
  with
  | Some plaintext -> Ok (Cstruct.of_string plaintext)
  | None -> Error "AES-GCM authentication failed"
;;

(** {1 Utilities} *)

(** Generate random bytes using mirage-crypto-rng *)
let random_bytes n =
  Mirage_crypto_rng_unix.use_default ();
  Cstruct.of_string (Mirage_crypto_rng.generate n)
;;

(** Generate client/server random (32 bytes with timestamp prefix) *)
let generate_random () =
  let buf = Cstruct.create 32 in
  let timestamp = Int32.of_float (Unix.gettimeofday ()) in
  Cstruct.BE.set_uint32 buf 0 timestamp;
  let random_part = random_bytes 28 in
  Cstruct.blit random_part 0 buf 4 28;
  buf
;;
