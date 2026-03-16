(** Structured error classification for OAS

    Classifies the unstructured [Error of string] from {!Sctp_core.output}
    into actionable categories so callers can decide retry vs abort.

    {1 Error Classes}

    {v
    Class      | Meaning                  | Caller action
    -----------|--------------------------|---------------------------
    Transient  | Temporary, retry-safe    | Back off and retry
    Protocol   | Malformed/invalid packet | Drop packet, log, continue
    Fatal      | Unrecoverable            | Tear down association
    Config     | Wrong state or setup     | Fix config, re-establish
    v}

    @since 0.3.0
*)

(** Error classification. Determines the recovery strategy. *)
type error_class =
  | Transient  (** Temporary condition — retry after backoff *)
  | Protocol   (** Protocol violation or malformed data *)
  | Fatal      (** Unrecoverable — must tear down *)
  | Config     (** Invalid configuration or wrong state *)
[@@deriving show, eq]

(** Structured error carrying classification and the raw message. *)
type t = {
  cls : error_class;
  message : string;
  module_hint : string;  (** Originating module (best-effort) *)
}
[@@deriving show, eq]

(** [classify msg] inspects a raw error string and returns its class.

    Classification uses prefix matching on known error patterns from
    {!Sctp_core}, {!Sctp_heartbeat}, {!Dcep}, etc.

    Unknown patterns default to [Protocol] (conservative: don't retry
    what you don't understand). *)
val classify : string -> error_class

(** [of_string msg] wraps a raw error string into a structured error.
    Infers [cls] via {!classify} and [module_hint] from the message prefix. *)
val of_string : string -> t

(** [is_retryable t] returns [true] for [Transient] errors only. *)
val is_retryable : t -> bool

(** [is_fatal t] returns [true] for [Fatal] errors. *)
val is_fatal : t -> bool

(** [to_string t] renders as ["[CLASS] module: message"]. *)
val to_string : t -> string
