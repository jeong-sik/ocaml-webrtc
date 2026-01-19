(** DTLS-SRTP key derivation (RFC 5764). *)

type role =
  | Client
  | Server

(** Derive SRTP master keys and salts from DTLS exporter. *)
val derive_keying_material :
  dtls:Dtls.t ->
  profile:Srtp.profile ->
  (Srtp.keying * Srtp.keying, string) result

(** Select the local keying material based on role. *)
val select_role :
  role ->
  client:Srtp.keying ->
  server:Srtp.keying ->
  Srtp.keying
