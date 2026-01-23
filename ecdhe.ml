(** RFC 8422 - Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)

    Pure OCaml implementation for WebRTC DTLS key exchange.
    Uses P-256 (secp256r1) curve as required by WebRTC spec.

    @author Second Brain
    @since ocaml-webrtc 0.2.0
*)

(** {1 Types} *)

(** Named curves supported by TLS (RFC 8422 Section 5.1.1) *)
type named_curve =
  | Secp256r1 (* P-256, NIST curve - WebRTC mandatory *)
  | Secp384r1 (* P-384 *)
  | Secp521r1 (* P-521 *)
  | X25519 (* Curve25519 - modern, fast *)

(** ECDHE key pair *)
type keypair =
  { curve : named_curve
  ; private_key : Cstruct.t (* Scalar *)
  ; public_key : Cstruct.t (* Uncompressed point: 04 || X || Y *)
  }

(** Get the public key from a keypair *)
let public_key kp = kp.public_key

(** {1 Constants} *)

let named_curve_to_int = function
  | Secp256r1 -> 23
  | Secp384r1 -> 24
  | Secp521r1 -> 25
  | X25519 -> 29
;;

let named_curve_of_int = function
  | 23 -> Some Secp256r1
  | 24 -> Some Secp384r1
  | 25 -> Some Secp521r1
  | 29 -> Some X25519
  | _ -> None
;;

let string_of_named_curve = function
  | Secp256r1 -> "secp256r1"
  | Secp384r1 -> "secp384r1"
  | Secp521r1 -> "secp521r1"
  | X25519 -> "x25519"
;;

(** Point size in bytes for each curve (uncompressed: 1 + 2*coord_size) *)
let point_size = function
  | Secp256r1 -> 65 (* 1 + 32 + 32 *)
  | Secp384r1 -> 97 (* 1 + 48 + 48 *)
  | Secp521r1 -> 133 (* 1 + 66 + 66 *)
  | X25519 -> 32 (* Raw X coordinate *)
;;

(** Private key size in bytes *)
let private_key_size = function
  | Secp256r1 -> 32
  | Secp384r1 -> 48
  | Secp521r1 -> 66
  | X25519 -> 32
;;

(** {1 Key Generation} *)

(** Generate ephemeral ECDHE key pair for P-256
    mirage-crypto-ec 1.2.0 API:
    - gen_key () returns (secret, public_key_string)
    - secret_to_octets converts secret to string
    - Public key is already in uncompressed format (04 || X || Y) *)
let generate_p256 () : (keypair, string) result =
  try
    (* Initialize RNG if needed *)
    Mirage_crypto_rng_unix.use_default ();
    (* Generate P-256 key pair using mirage-crypto-ec *)
    (* Returns (secret, public_key_string) where public_key is uncompressed *)
    let priv, pub_str = Mirage_crypto_ec.P256.Dh.gen_key () in
    (* Extract private key as octets and convert to Cstruct *)
    let priv_str = Mirage_crypto_ec.P256.Dh.secret_to_octets priv in
    let priv_cs = Cstruct.of_string priv_str in
    (* Public key is already a string in uncompressed format (04 || X || Y) *)
    let pub_cs = Cstruct.of_string pub_str in
    Ok { curve = Secp256r1; private_key = priv_cs; public_key = pub_cs }
  with
  | exn ->
    Error (Printf.sprintf "P-256 key generation failed: %s" (Printexc.to_string exn))
;;

(** Generate key pair for X25519 (Curve25519)
    Same API as P-256: gen_key returns (secret, public_key_string) *)
let generate_x25519 () : (keypair, string) result =
  try
    Mirage_crypto_rng_unix.use_default ();
    (* gen_key returns (secret, public_key_string) *)
    let priv, pub_str = Mirage_crypto_ec.X25519.gen_key () in
    (* secret_to_octets converts secret to string *)
    let priv_str = Mirage_crypto_ec.X25519.secret_to_octets priv in
    let priv_cs = Cstruct.of_string priv_str in
    let pub_cs = Cstruct.of_string pub_str in
    Ok { curve = X25519; private_key = priv_cs; public_key = pub_cs }
  with
  | exn ->
    Error (Printf.sprintf "X25519 key generation failed: %s" (Printexc.to_string exn))
;;

(** Generate key pair for specified curve *)
let generate ~curve : (keypair, string) result =
  match curve with
  | Secp256r1 -> generate_p256 ()
  | X25519 -> generate_x25519 ()
  | Secp384r1 -> Error "P-384 not yet implemented"
  | Secp521r1 -> Error "P-521 not yet implemented"
;;

(** {1 Key Exchange (Shared Secret Computation)} *)

(** Compute shared secret from our private key and peer's public key (P-256)
    mirage-crypto-ec 1.2.0 API:
    - secret_of_octets: string -> (secret * string, error) result
    - key_exchange: secret -> string -> (string, error) result *)
let compute_shared_secret_p256 ~private_key ~peer_public_key : (Cstruct.t, string) result =
  let priv_str = Cstruct.to_string private_key in
  let peer_pub_str = Cstruct.to_string peer_public_key in
  (* Parse our private key from octets *)
  match Mirage_crypto_ec.P256.Dh.secret_of_octets priv_str with
  | Error _ -> Error "Invalid P-256 private key"
  | Ok (priv, _pub) ->
    (* Compute shared secret (ECDH) directly with peer's public key string *)
    (match Mirage_crypto_ec.P256.Dh.key_exchange priv peer_pub_str with
     | Ok shared -> Ok (Cstruct.of_string shared)
     | Error _ -> Error "P-256 ECDH key exchange failed")
;;

(** Compute shared secret for X25519
    Same API pattern as P-256: need to parse private key with secret_of_octets first *)
let compute_shared_secret_x25519 ~private_key ~peer_public_key
  : (Cstruct.t, string) result
  =
  let priv_str = Cstruct.to_string private_key in
  let peer_pub_str = Cstruct.to_string peer_public_key in
  (* Parse private key from octets *)
  match Mirage_crypto_ec.X25519.secret_of_octets priv_str with
  | Error _ -> Error "Invalid X25519 private key"
  | Ok (priv, _pub) ->
    (match Mirage_crypto_ec.X25519.key_exchange priv peer_pub_str with
     | Ok shared -> Ok (Cstruct.of_string shared)
     | Error _ -> Error "X25519 key exchange failed")
;;

(** Compute shared secret (pre-master secret for TLS) *)
let compute_shared_secret ~keypair ~peer_public_key : (Cstruct.t, string) result =
  match keypair.curve with
  | Secp256r1 ->
    compute_shared_secret_p256 ~private_key:keypair.private_key ~peer_public_key
  | X25519 ->
    compute_shared_secret_x25519 ~private_key:keypair.private_key ~peer_public_key
  | Secp384r1 -> Error "P-384 not yet implemented"
  | Secp521r1 -> Error "P-521 not yet implemented"
;;

(** {1 Wire Format Encoding/Decoding} *)

(** Encode EC point for ServerKeyExchange message (RFC 8422 Section 5.4)
    Format: length (1 byte) || point (uncompressed) *)
let encode_public_key keypair =
  let pub = keypair.public_key in
  let len = Cstruct.length pub in
  let buf = Cstruct.create (1 + len) in
  Cstruct.set_uint8 buf 0 len;
  Cstruct.blit pub 0 buf 1 len;
  buf
;;

(** Decode EC point from ClientKeyExchange message *)
let decode_public_key ~curve data : (Cstruct.t, string) result =
  if Cstruct.length data < 1
  then Error "Public key too short"
  else (
    let len = Cstruct.get_uint8 data 0 in
    let expected = point_size curve in
    if len <> expected
    then
      Error (Printf.sprintf "Invalid public key length: expected %d, got %d" expected len)
    else if Cstruct.length data < 1 + len
    then Error "Public key data truncated"
    else Ok (Cstruct.sub data 1 len))
;;

(** {1 ServerKeyExchange Message Construction} *)

(** Build ECDHE parameters for ServerKeyExchange (RFC 8422 Section 5.4)

    struct {
      ECParameters curve_params;
      ECPoint      public;
    } ServerECDHParams;

    ECParameters {
      ECCurveType curve_type;  // 3 = named_curve
      NamedCurve namedcurve;   // 2 bytes
    }
*)
let build_server_ecdh_params keypair =
  let curve_params = Cstruct.create 3 in
  Cstruct.set_uint8 curve_params 0 3;
  (* named_curve type *)
  Cstruct.BE.set_uint16 curve_params 1 (named_curve_to_int keypair.curve);
  let public_key_encoded = encode_public_key keypair in
  Cstruct.concat [ curve_params; public_key_encoded ]
;;

(** Parse ECDHE parameters from ServerKeyExchange *)
let parse_server_ecdh_params data : (named_curve * Cstruct.t, string) result =
  if Cstruct.length data < 4
  then Error "ServerECDHParams too short"
  else (
    let curve_type = Cstruct.get_uint8 data 0 in
    if curve_type <> 3
    then
      Error
        (Printf.sprintf "Unsupported curve type: %d (expected named_curve=3)" curve_type)
    else (
      let curve_id = Cstruct.BE.get_uint16 data 1 in
      match named_curve_of_int curve_id with
      | None -> Error (Printf.sprintf "Unsupported named curve: %d" curve_id)
      | Some curve ->
        let remaining = Cstruct.sub data 3 (Cstruct.length data - 3) in
        (match decode_public_key ~curve remaining with
         | Ok pub -> Ok (curve, pub)
         | Error e -> Error e)))
;;

(** {1 Finished Message Support} *)

(** Compute verify_data for Finished message (RFC 5246 Section 7.4.9)

    verify_data = PRF(master_secret, finished_label, Hash(handshake_messages))

    finished_label = "client finished" or "server finished"
    Hash = SHA-256 for TLS 1.2
*)
let compute_verify_data ~master_secret ~handshake_hash ~is_client =
  let module H = Digestif.SHA256 in
  let label = if is_client then "client finished" else "server finished" in
  let verify_data_length = 12 in
  (* RFC 5246: always 12 bytes *)
  (* PRF(master_secret, label, handshake_hash)[0..11] *)
  let hmac key data =
    H.hmac_string ~key:(Cstruct.to_string key) (Cstruct.to_string data)
    |> H.to_raw_string
    |> Cstruct.of_string
  in
  let label_seed = Cstruct.concat [ Cstruct.of_string label; handshake_hash ] in
  (* P_SHA256(master_secret, label || handshake_hash) *)
  let a1 = hmac master_secret label_seed in
  let output = hmac master_secret (Cstruct.concat [ a1; label_seed ]) in
  Cstruct.sub output 0 verify_data_length
;;

(** Hash all handshake messages for Finished verification *)
let hash_handshake_messages messages =
  let module H = Digestif.SHA256 in
  let combined = Cstruct.concat messages in
  let hash = H.digest_string (Cstruct.to_string combined) in
  Cstruct.of_string (H.to_raw_string hash)
;;

(** {1 Utilities} *)

(** Check if a curve is supported *)
let is_curve_supported = function
  | Secp256r1 -> true
  | X25519 -> true
  | Secp384r1 -> false
  | Secp521r1 -> false
;;

(** Get default curve for WebRTC (P-256 mandatory) *)
let default_curve = Secp256r1

(** {1 Pretty Printing} *)

let pp_named_curve fmt curve = Format.fprintf fmt "%s" (string_of_named_curve curve)

let pp_keypair fmt kp =
  Format.fprintf
    fmt
    "ECDHE(%s, pub=%d bytes)"
    (string_of_named_curve kp.curve)
    (Cstruct.length kp.public_key)
;;
