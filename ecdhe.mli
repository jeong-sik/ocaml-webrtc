(** RFC 8422 - Elliptic Curve Diffie-Hellman Ephemeral (ECDHE)

    Pure OCaml implementation for WebRTC DTLS key exchange.
*)

(** {1 Types} *)

(** Named curves supported by TLS *)
type named_curve =
  | Secp256r1 (** P-256, NIST curve - WebRTC mandatory *)
  | Secp384r1 (** P-384 *)
  | Secp521r1 (** P-521 *)
  | X25519 (** Curve25519 - modern, fast *)

(** ECDHE key pair *)
type keypair

(** Get the public key from a keypair (raw, unencoded) *)
val public_key : keypair -> Cstruct.t

(** {1 Key Generation} *)

(** Generate ephemeral key pair for the specified curve *)
val generate : curve:named_curve -> (keypair, string) result

(** Generate P-256 key pair (WebRTC default) *)
val generate_p256 : unit -> (keypair, string) result

(** Generate X25519 key pair (modern alternative) *)
val generate_x25519 : unit -> (keypair, string) result

(** {1 Key Exchange} *)

(** Compute shared secret (pre-master secret) from our keypair and peer's public key *)
val compute_shared_secret
  :  keypair:keypair
  -> peer_public_key:Cstruct.t
  -> (Cstruct.t, string) result

(** {1 Wire Format} *)

(** Encode public key for transmission (length-prefixed) *)
val encode_public_key : keypair -> Cstruct.t

(** Decode public key from received data *)
val decode_public_key : curve:named_curve -> Cstruct.t -> (Cstruct.t, string) result

(** Build ECDHE parameters for ServerKeyExchange message *)
val build_server_ecdh_params : keypair -> Cstruct.t

(** Parse ECDHE parameters from ServerKeyExchange message *)
val parse_server_ecdh_params : Cstruct.t -> (named_curve * Cstruct.t, string) result

(** {1 Finished Message} *)

(** Compute verify_data for Finished message *)
val compute_verify_data
  :  master_secret:Cstruct.t
  -> handshake_hash:Cstruct.t
  -> is_client:bool
  -> Cstruct.t

(** Hash all handshake messages for Finished verification *)
val hash_handshake_messages : Cstruct.t list -> Cstruct.t

(** {1 Utilities} *)

(** Get curve from keypair *)
val default_curve : named_curve

(** Check if curve is supported *)
val is_curve_supported : named_curve -> bool

(** Convert named curve to wire format integer *)
val named_curve_to_int : named_curve -> int

(** Parse named curve from wire format *)
val named_curve_of_int : int -> named_curve option

(** String representation of curve name *)
val string_of_named_curve : named_curve -> string

(** {1 Pretty Printing} *)

val pp_named_curve : Format.formatter -> named_curve -> unit
val pp_keypair : Format.formatter -> keypair -> unit
