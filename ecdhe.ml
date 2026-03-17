(** RFC 8422 - Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)

    Pure OCaml implementation for WebRTC DTLS key exchange.
    Supports P-256, P-384, P-521 (NIST curves) and X25519.

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

(** {1 RNG initialization} *)

(** Initialize RNG at module load time (once per process) *)
let () = Mirage_crypto_rng_unix.use_default ()

(** {1 First-class module for ECDH operations}

    All mirage-crypto-ec DH modules (P256.Dh, P384.Dh, P521.Dh, X25519)
    conform to the [Mirage_crypto_ec.Dh] module type. We use first-class
    modules to factor out the identical generate/compute logic. *)

(** Generate ephemeral key pair using a first-class ECDH module *)
let generate_key
      (type s)
      (module C : Mirage_crypto_ec.Dh with type secret = s)
      ~(curve : named_curve)
      ~(curve_name : string)
      ()
  : (keypair, string) result
  =
  try
    let priv, pub_str = C.gen_key () in
    let priv_cs = Cstruct.of_string (C.secret_to_octets priv) in
    let pub_cs = Cstruct.of_string pub_str in
    Ok { curve; private_key = priv_cs; public_key = pub_cs }
  with
  | exn ->
    Error
      (Printf.sprintf "%s key generation failed: %s" curve_name (Printexc.to_string exn))
;;

(** Compute shared secret using a first-class ECDH module *)
let compute_shared
      (type s)
      (module C : Mirage_crypto_ec.Dh with type secret = s)
      ~(curve_name : string)
      ~private_key
      ~peer_public_key
  : (Cstruct.t, string) result
  =
  let priv_str = Cstruct.to_string private_key in
  let peer_pub_str = Cstruct.to_string peer_public_key in
  match C.secret_of_octets priv_str with
  | Error _ -> Error (Printf.sprintf "Invalid %s private key" curve_name)
  | Ok (priv, _pub) ->
    (match C.key_exchange priv peer_pub_str with
     | Ok shared -> Ok (Cstruct.of_string shared)
     | Error _ -> Error (Printf.sprintf "%s ECDH key exchange failed" curve_name))
;;

(** {1 Key Generation} *)

(** Generate P-256 key pair (WebRTC default) *)
let generate_p256 () =
  generate_key (module Mirage_crypto_ec.P256.Dh) ~curve:Secp256r1 ~curve_name:"P-256" ()
;;

(** Generate P-384 key pair *)
let generate_p384 () =
  generate_key (module Mirage_crypto_ec.P384.Dh) ~curve:Secp384r1 ~curve_name:"P-384" ()
;;

(** Generate P-521 key pair *)
let generate_p521 () =
  generate_key (module Mirage_crypto_ec.P521.Dh) ~curve:Secp521r1 ~curve_name:"P-521" ()
;;

(** Generate X25519 key pair *)
let generate_x25519 () =
  generate_key (module Mirage_crypto_ec.X25519) ~curve:X25519 ~curve_name:"X25519" ()
;;

(** Generate key pair for specified curve *)
let generate ~curve : (keypair, string) result =
  match curve with
  | Secp256r1 -> generate_p256 ()
  | Secp384r1 -> generate_p384 ()
  | Secp521r1 -> generate_p521 ()
  | X25519 -> generate_x25519 ()
;;

(** {1 Key Exchange (Shared Secret Computation)} *)

(** Compute shared secret (pre-master secret for TLS) *)
let compute_shared_secret ~keypair ~peer_public_key : (Cstruct.t, string) result =
  let private_key = keypair.private_key in
  match keypair.curve with
  | Secp256r1 ->
    compute_shared
      (module Mirage_crypto_ec.P256.Dh)
      ~curve_name:"P-256"
      ~private_key
      ~peer_public_key
  | Secp384r1 ->
    compute_shared
      (module Mirage_crypto_ec.P384.Dh)
      ~curve_name:"P-384"
      ~private_key
      ~peer_public_key
  | Secp521r1 ->
    compute_shared
      (module Mirage_crypto_ec.P521.Dh)
      ~curve_name:"P-521"
      ~private_key
      ~peer_public_key
  | X25519 ->
    compute_shared
      (module Mirage_crypto_ec.X25519)
      ~curve_name:"X25519"
      ~private_key
      ~peer_public_key
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
  | Secp384r1 -> true
  | Secp521r1 -> true
  | X25519 -> true
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
