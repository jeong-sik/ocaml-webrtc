(** Simple logging module for WebRTC stack.

    Outputs to stderr with level prefix. *)

val emit : string -> string -> unit
val debug : ('a, unit, string, unit) format4 -> 'a
val info : ('a, unit, string, unit) format4 -> 'a
val warn : ('a, unit, string, unit) format4 -> 'a
val error : ('a, unit, string, unit) format4 -> 'a
