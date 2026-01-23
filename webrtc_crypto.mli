(** WebRTC Crypto - TLS 1.2 PRF and Key Derivation

    Pure OCaml implementation of cryptographic primitives for DTLS handshake.
    Implements RFC 5246 (TLS 1.2 PRF) and RFC 5288 (AES-GCM cipher suites).

    {1 Key Derivation Flow}

    {v
    Pre-master secret (ECDHE shared secret)
           |
           v
    ┌─────────────────────────────────────────────┐
    │ PRF(pre_master, "master secret",            │
    │     client_random + server_random)          │
    └─────────────────────────────────────────────┘
           |
           v
    Master secret (48 bytes)
           |
           v
    ┌─────────────────────────────────────────────┐
    │ PRF(master, "key expansion",                │
    │     server_random + client_random)          │
    └─────────────────────────────────────────────┘
           |
           v
    Key block → client_write_key | server_write_key | client_iv | server_iv
    v}

    @author Second Brain
    @since ocaml-webrtc 0.2.0
*)

(** {1 Constants} *)

(** Master secret size = 48 bytes (RFC 5246 §8.1) *)
val master_secret_size : int

(** AES-128-GCM key size = 16 bytes *)
val aes_128_gcm_key_size : int

(** AES-256-GCM key size = 32 bytes *)
val aes_256_gcm_key_size : int

(** Fixed IV size = 4 bytes (from key derivation) *)
val aes_gcm_implicit_iv_size : int

(** Per-record nonce size = 8 bytes (usually seq number) *)
val aes_gcm_explicit_nonce_size : int

(** Authentication tag size = 16 bytes *)
val aes_gcm_tag_size : int

(** {1 PRF - Pseudo-Random Function} *)

(** [prf_sha256 ~secret ~label ~seed ~length] implements TLS 1.2 PRF.

    PRF(secret, label, seed) = P_SHA256(secret, label + seed)

    Uses HMAC-SHA256 in an iterative construction per RFC 5246 §5.

    @param secret The secret key
    @param label ASCII label string
    @param seed Additional seed data
    @param length Desired output length in bytes *)
val prf_sha256
  :  secret:Cstruct.t
  -> label:string
  -> seed:Cstruct.t
  -> length:int
  -> Cstruct.t

(** {1 Key Derivation} *)

(** [derive_master_secret ~pre_master_secret ~client_random ~server_random]
    derives the 48-byte master secret.

    master_secret = PRF(pre_master_secret, "master secret",
                        ClientHello.random + ServerHello.random)[0..47] *)
val derive_master_secret
  :  pre_master_secret:Cstruct.t
  -> client_random:Cstruct.t
  -> server_random:Cstruct.t
  -> Cstruct.t

(** Key material derived from master secret *)
type key_material =
  { client_write_key : Cstruct.t
  ; server_write_key : Cstruct.t
  ; client_write_iv : Cstruct.t
  ; server_write_iv : Cstruct.t
  }

(** [derive_key_material ~master_secret ~server_random ~client_random ~key_size ~iv_size]
    expands master secret into encryption keys.

    Note: seed order is server_random + client_random (different from master derivation).

    @param key_size 16 for AES-128-GCM, 32 for AES-256-GCM
    @param iv_size 4 for AES-GCM implicit IV *)
val derive_key_material
  :  master_secret:Cstruct.t
  -> server_random:Cstruct.t
  -> client_random:Cstruct.t
  -> key_size:int
  -> iv_size:int
  -> key_material

(** {1 AES-GCM Encryption/Decryption} *)

(** [build_nonce ~implicit_iv ~explicit_nonce] builds 12-byte GCM nonce.

    nonce = implicit_iv (4 bytes) || explicit_nonce (8 bytes)

    The implicit_iv comes from key derivation, explicit_nonce is per-record
    (typically the sequence number). *)
val build_nonce : implicit_iv:Cstruct.t -> explicit_nonce:Cstruct.t -> Cstruct.t

(** [aes_gcm_encrypt ~key ~implicit_iv ~explicit_nonce ~aad ~plaintext]
    encrypts and authenticates data.

    @param key Write key (16 or 32 bytes)
    @param implicit_iv 4-byte fixed IV from key derivation
    @param explicit_nonce 8-byte per-record nonce
    @param aad Additional authenticated data (DTLS record header)
    @param plaintext Data to encrypt
    @return ciphertext || 16-byte auth tag *)
val aes_gcm_encrypt
  :  key:Cstruct.t
  -> implicit_iv:Cstruct.t
  -> explicit_nonce:Cstruct.t
  -> aad:Cstruct.t
  -> plaintext:Cstruct.t
  -> Cstruct.t

(** [aes_gcm_decrypt ~key ~implicit_iv ~explicit_nonce ~aad ~ciphertext_and_tag]
    decrypts and verifies authenticated data.

    @return [Ok plaintext] if authentication succeeds,
            [Error "AES-GCM authentication failed"] otherwise *)
val aes_gcm_decrypt
  :  key:Cstruct.t
  -> implicit_iv:Cstruct.t
  -> explicit_nonce:Cstruct.t
  -> aad:Cstruct.t
  -> ciphertext_and_tag:Cstruct.t
  -> (Cstruct.t, string) result

(** {1 Random Generation} *)

(** [random_bytes n] generates n cryptographically random bytes.

    Uses mirage-crypto-rng with system entropy. *)
val random_bytes : int -> Cstruct.t

(** [generate_random ()] generates a 32-byte TLS random value.

    Format: 4-byte Unix timestamp || 28 random bytes

    Used for ClientHello.random and ServerHello.random. *)
val generate_random : unit -> Cstruct.t
