(** RFC 8445 - Interactive Connectivity Establishment (ICE)

    ICE agent coordination, state machine, Trickle ICE, consent freshness,
    nomination, and keepalive.

    Candidate types, gathering, and discovery are in {!Ice_candidate}.
    Connectivity checks (Sans-IO) are in {!Ice_check}.
*)

(* Re-export candidate types so external callers see Ice.candidate etc. unchanged *)
include Ice_candidate

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
[@@deriving show, eq]

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
[@@deriving show, eq]

(** Gathering state *)
type gathering_state =
  | Gathering_new
  | Gathering
  | Gathering_complete
[@@deriving show, eq]

(** Candidate pair state *)
type pair_state =
  | Pair_frozen
  | Pair_waiting
  | Pair_in_progress
  | Pair_succeeded
  | Pair_failed
[@@deriving show, eq]

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
  ; (* Trickle ICE support - RFC 8838 *)
    mutable on_candidate_cb : candidate_callback option
  ; mutable on_gathering_complete_cb : end_of_candidates_callback option
  ; mutable remote_end_of_candidates : bool
  ; (* Consent Freshness - RFC 7675 *)
    mutable consent_last_received : float (** Timestamp of last consent response *)
  ; mutable consent_failures : int (** Consecutive consent check failures *)
  ; mutable consent_expired : bool (** True if consent has expired *)
  }

(** {1 Default Configuration} *)

let default_config =
  { role = Controlling
  ; ice_servers =
      [ { urls = [ Webrtc_constants.google_stun_server ]
        ; username = None
        ; credential = None
        ; tls_ca = None
        }
      ]
  ; ice_lite = false
  ; aggressive_nomination = true
  ; check_interval_ms = 50
  ; max_check_attempts = 7
  ; ta_timeout_ms = 500
  }
;;

(** {1 String Conversions} *)

let string_of_connection_state = function
  | New -> "new"
  | Checking -> "checking"
  | Connected -> "connected"
  | Completed -> "completed"
  | Failed -> "failed"
  | Disconnected -> "disconnected"
  | Closed -> "closed"
;;

let string_of_gathering_state = function
  | Gathering_new -> "new"
  | Gathering -> "gathering"
  | Gathering_complete -> "complete"
;;

let string_of_pair_state = function
  | Pair_frozen -> "frozen"
  | Pair_waiting -> "waiting"
  | Pair_in_progress -> "in-progress"
  | Pair_succeeded -> "succeeded"
  | Pair_failed -> "failed"
;;

(** {1 Pair Priority Calculation} *)

(** Calculate pair priority - RFC 8445 Section 6.1.2.3:
    pair priority = 2^32 * MIN(G,D) + 2 * MAX(G,D) + (G > D ? 1 : 0) *)
let calculate_pair_priority g d is_controlling =
  let g64 = Int64.of_int g in
  let d64 = Int64.of_int d in
  let min_val, max_val = if is_controlling then d64, g64 else g64, d64 in
  let term1 = Int64.shift_left min_val 32 in
  let term2 = Int64.shift_left max_val 1 in
  let term3 = if g > d then 1L else 0L in
  Int64.add (Int64.add term1 term2) term3
;;

(** {1 Agent Creation and Management} *)

(** Unbiased random char selection via rejection sampling.
    Rejects bytes >= (256 - 256 mod charset_len) to avoid modulo bias. *)
let random_char_unbiased chars charset_len =
  let limit = 256 - (256 mod charset_len) in
  let rec go () =
    let b = Char.code (Bytes.get (Webrtc_crypto.random_bytes_raw 1) 0) in
    if b < limit then chars.[b mod charset_len] else go ()
  in
  go ()
;;

(** Generate random credentials *)
let generate_ufrag () =
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in
  let len = String.length chars in
  String.init 4 (fun _ -> random_char_unbiased chars len)
;;

let generate_pwd () =
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/" in
  let len = String.length chars in
  String.init 22 (fun _ -> random_char_unbiased chars len)
;;

(** Create new ICE agent *)
let create config =
  { state = New
  ; gathering_state = Gathering_new
  ; local_candidates = []
  ; remote_candidates = []
  ; pairs = []
  ; nominated_pair = None
  ; config
  ; local_ufrag = generate_ufrag ()
  ; local_pwd = generate_pwd ()
  ; remote_ufrag = None
  ; remote_pwd = None
  ; (* Trickle ICE *)
    on_candidate_cb = None
  ; on_gathering_complete_cb = None
  ; remote_end_of_candidates = false
  ; (* Consent Freshness *)
    consent_last_received = 0.0
  ; consent_failures = 0
  ; consent_expired = false
  }
;;

(** Get agent state *)
let get_state agent = agent.state

(** Get gathering state *)
let get_gathering_state agent = agent.gathering_state

(** Get local candidates *)
let get_local_candidates agent = agent.local_candidates

(** Get remote candidates *)
let get_remote_candidates agent = agent.remote_candidates

(** {1 Candidate Gathering - RFC 8445 Section 5.1.1} *)

(** Internal: Notify about new local candidate via Trickle ICE callback *)
let notify_local_candidate agent candidate =
  match agent.on_candidate_cb with
  | Some cb -> cb candidate
  | None -> ()
;;

(** Gather local host candidates - synchronous version for Eio *)
let gather_host_candidates agent =
  agent.gathering_state <- Gathering;
  (* Step 1: Discover local interfaces for host candidates *)
  let local_ips = get_local_addresses () in
  (* Create host candidates for each local IP *)
  let local_pref = ref 65535 in
  List.iter
    (fun ip ->
       try
         (* Bind a UDP socket to get an available port *)
         let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
         Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_of_string ip, 0));
         let port =
           match Unix.getsockname sock with
           | Unix.ADDR_INET (_, p) -> p
           | _ -> 0
         in
         Unix.close sock;
         let host_candidate =
           { foundation = generate_foundation ~candidate_type:Host ~base_address:ip ()
           ; component = 1
           ; transport = UDP
           ; priority =
               calculate_priority
                 ~candidate_type:Host
                 ~local_pref:!local_pref
                 ~component:1
           ; address = ip
           ; port
           ; cand_type = Host
           ; base_address = None
           ; base_port = None
           ; related_address = None
           ; related_port = None
           ; extensions = []
           }
         in
         agent.local_candidates <- host_candidate :: agent.local_candidates;
         notify_local_candidate agent host_candidate;
         local_pref := !local_pref - 100
       with
       | Unix.Unix_error (_, _, _) -> ())
    local_ips;
  agent.local_candidates
;;

(** {1 Trickle ICE Support - RFC 8838} *)

(** Calculate pair priority (RFC 8445 Section 6.1.2.3) *)
let calculate_pair_priority ~controlling_priority ~controlled_priority ~role =
  let g, d =
    match role with
    | Controlling -> controlling_priority, controlled_priority
    | Controlled -> controlled_priority, controlling_priority
  in
  (* pair_priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0) *)
  let min_v = min g d in
  let max_v = max g d in
  let last_bit = if g > d then 1L else 0L in
  Int64.(add (add (shift_left (of_int min_v) 32) (mul 2L (of_int max_v))) last_bit)
;;

(** Create candidate pair from local and remote candidates *)
let create_pair ~local ~remote ~role =
  let pair_priority =
    calculate_pair_priority
      ~controlling_priority:local.priority
      ~controlled_priority:remote.priority
      ~role
  in
  { local; remote; pair_priority; pair_state = Pair_frozen; nominated = false }
;;

(** Form pairs between a new candidate and existing candidates on the other side *)
let form_new_pairs agent ~is_local new_candidate =
  let existing = if is_local then agent.remote_candidates else agent.local_candidates in
  let new_pairs =
    List.map
      (fun other ->
         let local, remote =
           if is_local then new_candidate, other else other, new_candidate
         in
         create_pair ~local ~remote ~role:agent.config.role)
      existing
  in
  agent.pairs <- new_pairs @ agent.pairs;
  (* Sort pairs by priority (descending) *)
  agent.pairs
  <- List.sort (fun p1 p2 -> Int64.compare p2.pair_priority p1.pair_priority) agent.pairs
;;

(** Add local candidate and notify via callback *)
let add_local_candidate agent candidate =
  agent.local_candidates <- candidate :: agent.local_candidates;
  (* Form pairs with existing remote candidates *)
  form_new_pairs agent ~is_local:true candidate;
  (* Notify via Trickle ICE callback *)
  match agent.on_candidate_cb with
  | Some cb -> cb candidate
  | None -> ()
;;

(** Add remote candidate - Trickle ICE entry point *)
let add_remote_candidate agent candidate =
  agent.remote_candidates <- candidate :: agent.remote_candidates;
  (* Form pairs with existing local candidates *)
  form_new_pairs agent ~is_local:false candidate
;;

(** Set callback for new local candidates (Trickle ICE) *)
let on_candidate agent callback = agent.on_candidate_cb <- Some callback

(** Set callback for gathering complete *)
let on_gathering_complete agent callback = agent.on_gathering_complete_cb <- Some callback

(** Signal end of remote candidates *)
let set_remote_end_of_candidates agent = agent.remote_end_of_candidates <- true

(** Signal end of local candidates *)
let set_end_of_candidates agent =
  agent.gathering_state <- Gathering_complete;
  match agent.on_gathering_complete_cb with
  | Some cb -> cb ()
  | None -> ()
;;

(** {1 Connectivity Checks - RFC 8445 Section 6} *)

(** Generate a tie-breaker value for ICE *)
let generate_tie_breaker () =
  let rand = Webrtc_crypto.random_bytes_raw 8 in
  Bytes.get_int64_be rand 0
;;

(** Get all candidate pairs *)
let get_pairs agent = agent.pairs

(** Get nominated pair *)
let get_nominated_pair agent = agent.nominated_pair

(** Get the best succeeded pair for nomination *)
let get_best_succeeded_pair agent =
  let succeeded = List.filter (fun p -> p.pair_state = Pair_succeeded) agent.pairs in
  (* Sort by priority (highest first) *)
  let sorted =
    List.sort (fun a b -> Int64.compare b.pair_priority a.pair_priority) succeeded
  in
  List.nth_opt sorted 0
;;

(** {1 Remote Credentials} *)

(** Set remote ICE credentials *)
let set_remote_credentials agent ~ufrag ~pwd =
  agent.remote_ufrag <- Some ufrag;
  agent.remote_pwd <- Some pwd
;;

(** Get local credentials *)
let get_local_credentials agent = agent.local_ufrag, agent.local_pwd

(** Get agent configuration *)
let get_config agent = agent.config

(** Set gathering state to complete *)
let set_gathering_complete agent = agent.gathering_state <- Gathering_complete

(** Set nominated pair manually *)
let set_nominated agent =
  match get_best_succeeded_pair agent with
  | Some pair -> agent.nominated_pair <- Some pair
  | None -> ()
;;

(** {1 State Management} *)

(** Close the agent *)
let close agent = agent.state <- Closed

(** Restart ICE *)
let restart agent =
  agent.state <- New;
  agent.gathering_state <- Gathering_new;
  agent.local_candidates <- [];
  agent.remote_candidates <- [];
  agent.pairs <- [];
  agent.nominated_pair <- None;
  agent.local_ufrag <- generate_ufrag ();
  agent.local_pwd <- generate_pwd ();
  agent.remote_ufrag <- None;
  agent.remote_pwd <- None;
  (* Reset Trickle ICE state but keep callbacks *)
  agent.remote_end_of_candidates <- false;
  (* Reset Consent Freshness *)
  agent.consent_last_received <- 0.0;
  agent.consent_failures <- 0;
  agent.consent_expired <- false
;;

(** {1 Consent Freshness - RFC 7675}

    Consent Freshness ensures that the remote peer is still willing to
    communicate. Without periodic consent verification, an attacker could
    hijack the session.

    Per RFC 7675:
    - Consent SHOULD be refreshed every 5 seconds
    - Consent expires after 30 seconds without response
    - Any authenticated STUN response (including binding) refreshes consent
*)

(** RFC 7675 Section 5.1: Consent refresh interval *)
let consent_refresh_interval_s = 5.0

(** RFC 7675 Section 5.1: Consent timeout (30 seconds) *)
let consent_timeout_s = 30.0

(** RFC 7675 Section 5.1: Maximum consecutive failures before expiry *)
let consent_max_failures = 6

(** Record consent response received *)
let consent_received agent =
  let now = Time_compat.now () in
  agent.consent_last_received <- now;
  agent.consent_failures <- 0;
  agent.consent_expired <- false
;;

(** Record consent check failure *)
let consent_failed agent =
  agent.consent_failures <- agent.consent_failures + 1;
  if agent.consent_failures >= consent_max_failures
  then (
    agent.consent_expired <- true;
    agent.state <- Failed)
;;

(** Check if consent is still valid *)
let is_consent_valid agent =
  if agent.consent_expired
  then false
  else if agent.consent_last_received = 0.0
  then true (* Not yet established *)
  else (
    let now = Time_compat.now () in
    let elapsed = now -. agent.consent_last_received in
    elapsed < consent_timeout_s)
;;

(** Check if consent refresh is needed *)
let needs_consent_refresh agent =
  if agent.state <> Connected && agent.state <> Completed
  then false
  else if agent.consent_last_received = 0.0
  then true
  else (
    let now = Time_compat.now () in
    let elapsed = now -. agent.consent_last_received in
    elapsed >= consent_refresh_interval_s)
;;

(** Get consent status for monitoring *)
let get_consent_status agent =
  let now = Time_compat.now () in
  let time_since_last =
    if agent.consent_last_received = 0.0
    then None
    else Some (now -. agent.consent_last_received)
  in
  `Assoc
    [ "valid", `Bool (is_consent_valid agent)
    ; "expired", `Bool agent.consent_expired
    ; "failures", `Int agent.consent_failures
    ; ( "timeSinceLastMs"
      , match time_since_last with
        | None -> `Null
        | Some t -> `Float (t *. 1000.0) )
    ]
;;

(** {1 JSON Status} *)

let status_json agent =
  `Assoc
    [ "state", `String (string_of_connection_state agent.state)
    ; "gatheringState", `String (string_of_gathering_state agent.gathering_state)
    ; "isGathering", `Bool (agent.gathering_state = Gathering)
    ; "localCandidates", `Int (List.length agent.local_candidates)
    ; "remoteCandidates", `Int (List.length agent.remote_candidates)
    ; "pairs", `Int (List.length agent.pairs)
    ; "hasNominatedPair", `Bool (Option.is_some agent.nominated_pair)
    ; "localUfrag", `String agent.local_ufrag
    ; ( "role"
      , `String
          (match agent.config.role with
           | Controlling -> "controlling"
           | Controlled -> "controlled") )
    ; "consent", get_consent_status agent
    ]
;;

(** {1 Pretty Printing} *)

let pp_pair fmt p =
  Format.fprintf
    fmt
    "(%a <-> %a) priority=%Ld state=%s nominated=%b"
    pp_candidate
    p.local
    pp_candidate
    p.remote
    p.pair_priority
    (string_of_pair_state p.pair_state)
    p.nominated
;;

(** {1 RFC 5245 - ICE Improvements} *)

(** Nomination strategy per RFC 5245 Section 8 *)
type nomination_mode =
  | Regular_nomination (** Wait for successful check, then nominate *)
  | Aggressive_nomination (** Nominate every pair immediately *)
[@@deriving show, eq]

(** Keepalive state for maintaining NAT bindings *)
type keepalive_state =
  | Keepalive_stopped
  | Keepalive_active of
      { last_sent : float (** Timestamp of last keepalive sent *)
      ; interval : float (** Keepalive interval in seconds *)
      }
[@@deriving show]

(** Calculate candidate pair priority per RFC 5245 Section 5.7.2. *)
let calculate_pair_priority ~controlling_priority ~controlled_priority ~role =
  let g = Int64.of_int controlling_priority in
  let d = Int64.of_int controlled_priority in
  let _ = role in
  (* Role determines which side we're on, but formula is symmetric *)
  let min_gd = if g < d then g else d in
  let max_gd = if g > d then g else d in
  let two_pow_32 = Int64.shift_left 1L 32 in
  (* term1 = 2^32 * MIN(G, D) *)
  let term1 = Int64.mul two_pow_32 min_gd in
  (* term2 = 2 * MAX(G, D) *)
  let term2 = Int64.mul 2L max_gd in
  (* term3 = (G > D ? 1 : 0) *)
  let term3 = if g > d then 1L else 0L in
  Int64.add (Int64.add term1 term2) term3
;;

(** Nominate a candidate pair. *)
let nominate_pair agent pair =
  let nominated = { pair with nominated = true } in
  let pairs =
    List.map
      (fun p ->
         if
           p.local.foundation = pair.local.foundation
           && p.remote.foundation = pair.remote.foundation
         then nominated
         else p)
      agent.pairs
  in
  { agent with pairs; nominated_pair = Some nominated }
;;

(** Start keepalive mechanism for nominated pair. *)
let start_keepalive ?(interval_sec = 15.0) () =
  Keepalive_active { last_sent = Time_compat.now (); interval = interval_sec }
;;

(** Check if keepalive should be sent now. *)
let is_keepalive_due state now =
  match state with
  | Keepalive_stopped -> false
  | Keepalive_active { last_sent; interval } -> now -. last_sent >= interval
;;

(** Update keepalive state after sending. *)
let update_keepalive_sent state =
  match state with
  | Keepalive_stopped -> Keepalive_stopped
  | Keepalive_active ka -> Keepalive_active { ka with last_sent = Time_compat.now () }
;;

(** Handle keepalive timeout - peer may be unreachable. *)
let is_keepalive_timeout ~max_failures ~current_failures =
  current_failures >= max_failures
;;

(** Get recommended keepalive interval per RFC 5245. *)
let recommended_keepalive_interval = function
  | UDP -> 15.0
  | TCP -> 30.0
;;
