(** RFC 8445 - Interactive Connectivity Establishment (ICE)

    ICE agent coordination, state machine, Trickle ICE, consent freshness,
    nomination, and keepalive.

    Candidate types, gathering, and discovery are in {!Ice_candidate}.
    Connectivity checks (Sans-IO) are in {!Ice_check}.

    Candidate types are re-exported so external callers see
    [Ice.candidate] etc. without changes.
*)

(** {1 Candidate Types}

    Re-exported from {!Ice_candidate}. *)

include module type of Ice_candidate

(** {1 Agent Types} *)

(** ICE server configuration *)
type ice_server =
  { urls : string list
  ; username : string option
  ; credential : string option
  ; tls_ca : string option
  }

(** ICE agent role *)
type ice_role =
  | Controlling
  | Controlled

val pp_ice_role : Format.formatter -> ice_role -> unit
val equal_ice_role : ice_role -> ice_role -> bool
val show_ice_role : ice_role -> string

(** ICE configuration *)
type config =
  { role : ice_role
  ; ice_servers : ice_server list
  ; ice_lite : bool
  ; aggressive_nomination : bool
  ; check_interval_ms : int
  ; max_check_attempts : int
  ; ta_timeout_ms : int
  }

(** Connection state per RFC 8445 *)
type connection_state =
  | New
  | Checking
  | Connected
  | Completed
  | Failed
  | Disconnected
  | Closed

val pp_connection_state : Format.formatter -> connection_state -> unit
val equal_connection_state : connection_state -> connection_state -> bool
val show_connection_state : connection_state -> string

(** Gathering state *)
type gathering_state =
  | Gathering_new
  | Gathering
  | Gathering_complete

val pp_gathering_state : Format.formatter -> gathering_state -> unit
val equal_gathering_state : gathering_state -> gathering_state -> bool
val show_gathering_state : gathering_state -> string

(** Candidate pair state *)
type pair_state =
  | Pair_frozen
  | Pair_waiting
  | Pair_in_progress
  | Pair_succeeded
  | Pair_failed

val pp_pair_state : Format.formatter -> pair_state -> unit
val equal_pair_state : pair_state -> pair_state -> bool
val show_pair_state : pair_state -> string

(** Candidate pair *)
type candidate_pair =
  { local : candidate
  ; remote : candidate
  ; pair_priority : int64
  ; pair_state : pair_state
  ; nominated : bool
  }

(** Check result *)
type check_result =
  | Check_success of candidate_pair
  | Check_failure of string

(** Candidate callback for Trickle ICE *)
type candidate_callback = candidate -> unit

(** End-of-candidates callback *)
type end_of_candidates_callback = unit -> unit

(** ICE agent *)
type agent =
  { mutable state : connection_state
  ; mutable gathering_state : gathering_state
  ; mutable local_candidates : candidate list
  ; mutable remote_candidates : candidate list
  ; mutable pairs : candidate_pair list
  ; mutable nominated_pair : candidate_pair option
  ; config : config
  ; mutable local_ufrag : string
  ; mutable local_pwd : string
  ; mutable remote_ufrag : string option
  ; mutable remote_pwd : string option
  ; mutable on_candidate_cb : candidate_callback option
  ; mutable on_gathering_complete_cb : end_of_candidates_callback option
  ; mutable remote_end_of_candidates : bool
  ; mutable consent_last_received : float
  ; mutable consent_failures : int
  ; mutable consent_expired : bool
  }

(** {1 Default Configuration} *)

val default_config : config

(** {1 String Conversions} *)

val string_of_connection_state : connection_state -> string
val string_of_gathering_state : gathering_state -> string
val string_of_pair_state : pair_state -> string

(** {1 Credential Generation} *)

val generate_ufrag : unit -> string
val generate_pwd : unit -> string

(** {1 Agent Creation and Management} *)

val create : config -> agent
val get_state : agent -> connection_state
val get_gathering_state : agent -> gathering_state
val get_local_candidates : agent -> candidate list
val get_remote_candidates : agent -> candidate list

(** {1 Candidate Gathering - RFC 8445 Section 5.1.1} *)

val gather_host_candidates : agent -> candidate list

(** {1 Trickle ICE Support - RFC 8838} *)

val add_local_candidate : agent -> candidate -> unit
val add_remote_candidate : agent -> candidate -> unit
val on_candidate : agent -> candidate_callback -> unit
val on_gathering_complete : agent -> end_of_candidates_callback -> unit
val set_remote_end_of_candidates : agent -> unit
val set_end_of_candidates : agent -> unit

(** {1 Connectivity Checks - RFC 8445 Section 6} *)

val generate_tie_breaker : unit -> int64
val get_pairs : agent -> candidate_pair list
val get_nominated_pair : agent -> candidate_pair option
val get_best_succeeded_pair : agent -> candidate_pair option

(** {1 Candidate Pair Management} *)

val create_pair : local:candidate -> remote:candidate -> role:ice_role -> candidate_pair
val form_new_pairs : agent -> is_local:bool -> candidate -> unit

(** {1 Remote Credentials} *)

val set_remote_credentials : agent -> ufrag:string -> pwd:string -> unit
val get_local_credentials : agent -> string * string
val get_config : agent -> config
val set_gathering_complete : agent -> unit
val set_nominated : agent -> unit

(** {1 State Management} *)

val close : agent -> unit
val restart : agent -> unit

(** {1 Consent Freshness - RFC 7675} *)

val consent_refresh_interval_s : float
val consent_timeout_s : float
val consent_max_failures : int
val consent_received : agent -> unit
val consent_failed : agent -> unit
val is_consent_valid : agent -> bool
val needs_consent_refresh : agent -> bool

val get_consent_status
  :  agent
  -> [> `Assoc of
          (string * [> `Bool of bool | `Float of float | `Int of int | `Null ]) list
     ]

(** {1 JSON Status} *)

val status_json
  :  agent
  -> [> `Assoc of
          (string
          * [> `Assoc of
                 (string * [> `Bool of bool | `Float of float | `Int of int | `Null ])
                   list
            | `Bool of bool
            | `Int of int
            | `String of string
            ])
            list
     ]

(** {1 Pretty Printing} *)

val pp_pair : Format.formatter -> candidate_pair -> unit

(** {1 RFC 5245 - ICE Improvements} *)

type nomination_mode =
  | Regular_nomination
  | Aggressive_nomination

val pp_nomination_mode : Format.formatter -> nomination_mode -> unit
val equal_nomination_mode : nomination_mode -> nomination_mode -> bool
val show_nomination_mode : nomination_mode -> string

type keepalive_state =
  | Keepalive_stopped
  | Keepalive_active of
      { last_sent : float
      ; interval : float
      }

val pp_keepalive_state : Format.formatter -> keepalive_state -> unit
val show_keepalive_state : keepalive_state -> string

val calculate_pair_priority
  :  controlling_priority:int
  -> controlled_priority:int
  -> role:ice_role
  -> int64

val nominate_pair : agent -> candidate_pair -> agent
val start_keepalive : ?interval_sec:float -> unit -> keepalive_state
val is_keepalive_due : keepalive_state -> float -> bool
val update_keepalive_sent : keepalive_state -> keepalive_state
val is_keepalive_timeout : max_failures:int -> current_failures:int -> bool
val recommended_keepalive_interval : transport -> float
