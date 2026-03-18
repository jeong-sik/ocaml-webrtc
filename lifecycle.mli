(** Connection lifecycle harness

    Manages the WebRTC connection establishment phases and ensures
    deterministic resource cleanup on failure.

    Phases proceed in order:
    {v
    Init → Ice_gathering → Dtls_handshake → Sctp_association → Data_channel → Established
    v}

    On failure at any phase, all resources from completed phases are
    released in reverse order (LIFO cleanup).

    @since 0.3.0
*)

(** Connection establishment phases. *)
type phase =
  | Init (** Initial state, no resources allocated *)
  | Ice_gathering (** ICE candidates being gathered *)
  | Dtls_handshake (** DTLS handshake in progress *)
  | Sctp_association (** SCTP 4-way handshake *)
  | Data_channel (** DataChannel negotiation (DCEP) *)
  | Established (** Ready for data transfer *)
[@@deriving show, eq]

(** Phase failure information. *)
type failure =
  { failed_phase : phase
  ; error : Oas_error.t
  ; cleaned_phases : phase list (** Phases that were cleaned up *)
  }
[@@deriving show, eq]

(** Resource cleanup action for a phase. *)
type cleanup = unit -> unit

(** Lifecycle manager state. *)
type t

(** [create ()] returns a new lifecycle manager in [Init] phase. *)
val create : unit -> t

(** [current_phase t] returns the current phase. *)
val current_phase : t -> phase

(** [advance t ~phase ~cleanup] transitions to [phase], registering
    [cleanup] to be called if this or a later phase fails.

    Returns [Error] if the phase transition is invalid (e.g. skipping phases).
    Valid transitions are strictly sequential: Init → Ice_gathering → ... *)
val advance : t -> phase:phase -> cleanup:cleanup -> (unit, string) result

(** [fail t ~error] transitions to failed state, running cleanup actions
    in reverse order (newest phase first).

    Returns the failure record describing what was cleaned up. *)
val fail : t -> error:string -> failure

(** [is_established t] returns true if phase is [Established]. *)
val is_established : t -> bool

(** [is_failed t] returns true if [fail] has been called. *)
val is_failed : t -> bool

(** [completed_phases t] returns phases that have been advanced through. *)
val completed_phases : t -> phase list

(** [phase_index phase] returns the ordinal (0 = Init, 5 = Established). *)
val phase_index : phase -> int
