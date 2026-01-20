(** DTLS-SRTP key extraction (RFC 5764). *)

(** Key material for SRTP (per direction). *)
type key_material = {
  client_key : bytes;
  server_key : bytes;
  client_salt : bytes;
  server_salt : bytes;
}

(** Split exporter output into SRTP master keys. *)
val split_keying_material :
  profile:Srtp.profile ->
  bytes ->
  (key_material, string) result

(** Export and split SRTP keying material from a DTLS context. *)
val export_keying_material :
  dtls:Dtls.t ->
  profile:Srtp.profile ->
  (key_material, string) result

(** Build SRTP master keys for each direction. *)
val masters_of_key_material :
  key_material ->
  Srtp.master * Srtp.master
