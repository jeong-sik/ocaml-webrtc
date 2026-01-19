(** RFC 8445 ICE Connectivity Checks - Sans-IO Implementation

    This module implements ICE connectivity checks using the Sans-IO pattern.
    All I/O operations are represented as ADT values, making the code:
    - Easy to test without mocking
    - Suitable for formal verification
    - Runtime-agnostic (works with Lwt, Eio, or blocking I/O)
*)

(** {1 Types} *)

(** Check state per RFC 8445 Section 6.1.2.6 *)
type check_state =
  | Frozen      (** Initial state, waiting to be scheduled *)
  | Waiting     (** Ready to perform check *)
  | In_progress (** Check request sent, waiting for response *)
  | Succeeded   (** Check completed successfully *)
  | Failed      (** Check failed after all retries *)

val show_check_state : check_state -> string
val equal_check_state : check_state -> check_state -> bool

(** STUN attributes for connectivity checks *)
type stun_attrs = {
  username: string;
  password: string;
  use_candidate: bool;
  priority: int;
  ice_controlling: int64 option;
  ice_controlled: int64 option;
}

(** Transaction state *)
type transaction = {
  id: bytes;
  attempt: int;
  max_attempts: int;
  rto_ms: int;
  sent_at: float;
}

(** Check context *)
type check_context = {
  local_addr: string * int;
  remote_addr: string * int;
  stun_attrs: stun_attrs;
  transaction: transaction;
}

(** Connectivity check state machine *)
type t

(** {1 Sans-IO Input Events} *)

type input =
  | Start_check
  | Stun_response_received of {
      transaction_id: bytes;
      success: bool;
      mapped_addr: (string * int) option;
      error_code: int option;
    }
  | Timer_fired
  | Cancel

(** {1 Sans-IO Output Commands} *)

type output =
  | Send_stun_request of {
      dest: string * int;
      transaction_id: bytes;
      username: string;
      password: string;
      use_candidate: bool;
      priority: int;
      ice_controlling: int64 option;
      ice_controlled: int64 option;
    }
  | Set_timer of { duration_ms: int }
  | Cancel_timer
  | Check_completed of {
      success: bool;
      nominated: bool;
      mapped_addr: (string * int) option;
      error: string option;
    }
  | No_op

(** {1 Creation} *)

val create :
  local_addr:(string * int) ->
  remote_addr:(string * int) ->
  local_ufrag:string ->
  local_pwd:string ->
  remote_ufrag:string ->
  remote_pwd:string ->
  priority:int ->
  is_controlling:bool ->
  tie_breaker:int64 ->
  use_candidate:bool ->
  max_attempts:int ->
  unit -> t

(** {1 State Transitions} *)

(** Step the state machine with an input event.
    Returns the new state and any output command. *)
val step : t -> input -> float -> t * output

(** {1 Queries} *)

val get_state : t -> check_state
val is_terminal : t -> bool
val is_nominated : t -> bool
val get_error : t -> string option
val get_transaction_id : t -> bytes
val get_rto : t -> int

(** {1 Check List Management} *)

type check_list

val create_check_list : unit -> check_list
val add_check : check_list -> t -> check_list * int
val get_check : check_list -> int -> t option
val update_check : check_list -> int -> t -> check_list
val get_next_waiting : check_list -> (int * t) option
val get_succeeded : check_list -> (int * t) list
val has_succeeded : check_list -> bool
val all_finished : check_list -> bool
