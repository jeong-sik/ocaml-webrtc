(** RFC 8445 - Interactive Connectivity Establishment (ICE)

    Pure OCaml implementation of ICE for WebRTC NAT traversal.

    ICE is responsible for:
    - Gathering local candidates (host, server reflexive, relay)
    - Processing remote candidates
    - Connectivity checks between candidate pairs
    - Selecting the best path for media/data

    Reference: https://datatracker.ietf.org/doc/html/rfc8445
*)

(** {1 Types} *)

(** ICE candidate types per RFC 8445 Section 4.1.1 *)
type candidate_type =
  | Host              (** Local interface address *)
  | Server_reflexive  (** Address as seen by STUN server *)
  | Peer_reflexive    (** Address discovered during connectivity checks *)
  | Relay             (** Relay address from TURN server *)
[@@deriving show, eq]

(** Transport protocol *)
type transport = UDP | TCP
[@@deriving show, eq]

(** ICE server configuration *)
type ice_server = {
  urls: string list;
  username: string option;
  credential: string option;
}

(** ICE agent role *)
type ice_role = Controlling | Controlled
[@@deriving show, eq]

(** ICE candidate - represents a potential connection endpoint *)
type candidate = {
  foundation: string;        (** Uniquely identifies candidate base *)
  component: int;            (** 1 = RTP, 2 = RTCP *)
  transport: transport;
  priority: int;
  address: string;
  port: int;
  cand_type: candidate_type;
  base_address: string option;  (** Base address for srflx/prflx/relay *)
  base_port: int option;
  related_address: string option;  (** Related address for srflx/prflx/relay *)
  related_port: int option;
  extensions: (string * string) list;
}

(** ICE configuration *)
type config = {
  role: ice_role;
  ice_servers: ice_server list;
  ice_lite: bool;
  aggressive_nomination: bool;
  check_interval_ms: int;
  max_check_attempts: int;
  ta_timeout_ms: int;
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
type candidate_pair = {
  local: candidate;
  remote: candidate;
  pair_priority: int64;
  pair_state: pair_state;
  nominated: bool;
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
type agent = {
  mutable state: connection_state;
  mutable gathering_state: gathering_state;
  mutable local_candidates: candidate list;
  mutable remote_candidates: candidate list;
  mutable pairs: candidate_pair list;
  mutable nominated_pair: candidate_pair option;
  config: config;
  mutable local_ufrag: string;
  mutable local_pwd: string;
  mutable remote_ufrag: string option;
  mutable remote_pwd: string option;
  (* Trickle ICE support - RFC 8838 *)
  mutable on_candidate_cb: candidate_callback option;
  mutable on_gathering_complete_cb: end_of_candidates_callback option;
  mutable remote_end_of_candidates: bool;
}

(** {1 Default Configuration} *)

let default_config = {
  role = Controlling;
  ice_servers = [
    { urls = ["stun:stun.l.google.com:19302"]; username = None; credential = None };
  ];
  ice_lite = false;
  aggressive_nomination = true;
  check_interval_ms = 50;
  max_check_attempts = 7;
  ta_timeout_ms = 500;
}

(** {1 String Conversions} *)

let string_of_candidate_type = function
  | Host -> "host"
  | Server_reflexive -> "srflx"
  | Peer_reflexive -> "prflx"
  | Relay -> "relay"

let candidate_type_of_string = function
  | "host" -> Some Host
  | "srflx" -> Some Server_reflexive
  | "prflx" -> Some Peer_reflexive
  | "relay" -> Some Relay
  | _ -> None

let string_of_transport = function
  | UDP -> "UDP"
  | TCP -> "TCP"

let transport_of_string = function
  | "UDP" | "udp" -> Some UDP
  | "TCP" | "tcp" -> Some TCP
  | _ -> None

let string_of_connection_state = function
  | New -> "new"
  | Checking -> "checking"
  | Connected -> "connected"
  | Completed -> "completed"
  | Failed -> "failed"
  | Disconnected -> "disconnected"
  | Closed -> "closed"

let string_of_gathering_state = function
  | Gathering_new -> "new"
  | Gathering -> "gathering"
  | Gathering_complete -> "complete"

let string_of_pair_state = function
  | Pair_frozen -> "frozen"
  | Pair_waiting -> "waiting"
  | Pair_in_progress -> "in-progress"
  | Pair_succeeded -> "succeeded"
  | Pair_failed -> "failed"

(** {1 Priority Calculation - RFC 8445 Section 5.1.2} *)

(** Type preference values per RFC 8445 *)
let type_preference = function
  | Host -> 126
  | Peer_reflexive -> 110
  | Server_reflexive -> 100
  | Relay -> 0

(** Calculate candidate priority:
    priority = (2^24) * (type preference) + (2^8) * (local preference) + (256 - component ID) *)
let calculate_priority ~candidate_type ~local_pref ~component =
  let type_pref = type_preference candidate_type in
  (type_pref lsl 24) + (local_pref lsl 8) + (256 - component)

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

(** {1 Foundation Generation - RFC 8445 Section 5.1.1.3} *)

let generate_foundation ~candidate_type ~base_address ?stun_server () =
  let type_str = string_of_candidate_type candidate_type in
  let server_str = Option.value stun_server ~default:"" in
  let input = type_str ^ base_address ^ server_str in
  (* Simple hash-based foundation *)
  Digest.string input |> Digest.to_hex |> fun s -> String.sub s 0 8

(** {1 Candidate Parsing - RFC 8445 Section 15.1} *)

(** Parse SDP candidate attribute line *)
let parse_candidate line =
  let parts = String.split_on_char ' ' (String.trim line) in
  match parts with
  | foundation :: component_str :: transport_str :: priority_str :: address :: port_str :: "typ" :: type_str :: rest ->
    (match int_of_string_opt component_str,
           transport_of_string transport_str,
           int_of_string_opt priority_str,
           int_of_string_opt port_str,
           candidate_type_of_string type_str with
    | Some component, Some transport, Some priority, Some port, Some cand_type ->
      (* Parse optional raddr/rport and extensions *)
      let rec parse_rest rel_addr rel_port exts = function
        | [] -> (rel_addr, rel_port, List.rev exts)
        | "raddr" :: addr :: rest -> parse_rest (Some addr) rel_port exts rest
        | "rport" :: port_str :: rest ->
          let port = int_of_string_opt port_str in
          parse_rest rel_addr port exts rest
        | key :: value :: rest -> parse_rest rel_addr rel_port ((key, value) :: exts) rest
        | _ :: rest -> parse_rest rel_addr rel_port exts rest
      in
      let (related_address, related_port, extensions) = parse_rest None None [] rest in
      Ok {
        foundation;
        component;
        transport;
        priority;
        address;
        port;
        cand_type;
        base_address = related_address;  (* For srflx/relay, related is base *)
        base_port = related_port;
        related_address;
        related_port;
        extensions;
      }
    | _ -> Error "Invalid candidate format: failed to parse required fields")
  | _ -> Error "Invalid candidate format: not enough parts"

(** Convert candidate to SDP attribute string *)
let candidate_to_string c =
  let base = Printf.sprintf "%s %d %s %d %s %d typ %s"
    c.foundation
    c.component
    (string_of_transport c.transport)
    c.priority
    c.address
    c.port
    (string_of_candidate_type c.cand_type)
  in
  let with_related = match c.related_address, c.related_port with
    | Some addr, Some port -> Printf.sprintf "%s raddr %s rport %d" base addr port
    | Some addr, None -> Printf.sprintf "%s raddr %s" base addr
    | None, Some port -> Printf.sprintf "%s rport %d" base port
    | None, None -> base
  in
  (* Add extensions *)
  List.fold_left (fun acc (k, v) -> Printf.sprintf "%s %s %s" acc k v) with_related c.extensions

(** {1 Agent Creation and Management} *)

(** Generate random credentials *)
let generate_ufrag () =
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in
  let len = String.length chars in
  String.init 4 (fun _ -> chars.[Random.int len])

let generate_pwd () =
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/" in
  let len = String.length chars in
  String.init 22 (fun _ -> chars.[Random.int len])

(** Create new ICE agent *)
let create config =
  Random.self_init ();
  {
    state = New;
    gathering_state = Gathering_new;
    local_candidates = [];
    remote_candidates = [];
    pairs = [];
    nominated_pair = None;
    config;
    local_ufrag = generate_ufrag ();
    local_pwd = generate_pwd ();
    remote_ufrag = None;
    remote_pwd = None;
    (* Trickle ICE *)
    on_candidate_cb = None;
    on_gathering_complete_cb = None;
    remote_end_of_candidates = false;
  }

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

(** Gather local host candidates with Trickle ICE support *)
let gather_candidates agent =
  agent.gathering_state <- Gathering;
  (* Simplified: just add a placeholder host candidate *)
  (* Real implementation would enumerate network interfaces *)
  let host_candidate = {
    foundation = generate_foundation ~candidate_type:Host ~base_address:"0.0.0.0" ();
    component = 1;
    transport = UDP;
    priority = calculate_priority ~candidate_type:Host ~local_pref:65535 ~component:1;
    address = "0.0.0.0";
    port = 0;
    cand_type = Host;
    base_address = None;
    base_port = None;
    related_address = None;
    related_port = None;
    extensions = [];
  } in
  (* Add candidate and notify (Trickle ICE) *)
  agent.local_candidates <- [host_candidate];
  notify_local_candidate agent host_candidate;
  (* Signal end of candidates *)
  agent.gathering_state <- Gathering_complete;
  (match agent.on_gathering_complete_cb with
   | Some cb -> cb ()
   | None -> ());
  Lwt.return_unit

(** {1 Trickle ICE Support - RFC 8838} *)

(** Calculate pair priority (RFC 8445 Section 6.1.2.3) *)
let calculate_pair_priority ~controlling_priority ~controlled_priority ~role =
  let g, d = match role with
    | Controlling -> (controlling_priority, controlled_priority)
    | Controlled -> (controlled_priority, controlling_priority)
  in
  (* pair_priority = 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0) *)
  let min_v = min g d in
  let max_v = max g d in
  let last_bit = if g > d then 1L else 0L in
  Int64.(add (add (shift_left (of_int min_v) 32) (mul 2L (of_int max_v))) last_bit)

(** Create candidate pair from local and remote candidates *)
let create_pair ~local ~remote ~role =
  let pair_priority = calculate_pair_priority
    ~controlling_priority:local.priority
    ~controlled_priority:remote.priority
    ~role
  in
  {
    local;
    remote;
    pair_priority;
    pair_state = Pair_frozen;
    nominated = false;
  }

(** Form pairs between a new candidate and existing candidates on the other side *)
let form_new_pairs agent ~is_local new_candidate =
  let existing = if is_local then agent.remote_candidates else agent.local_candidates in
  let new_pairs = List.map (fun other ->
    let local, remote = if is_local then (new_candidate, other) else (other, new_candidate) in
    create_pair ~local ~remote ~role:agent.config.role
  ) existing in
  agent.pairs <- new_pairs @ agent.pairs;
  (* Sort pairs by priority (descending) *)
  agent.pairs <- List.sort (fun p1 p2 ->
    Int64.compare p2.pair_priority p1.pair_priority
  ) agent.pairs

(** Add local candidate and notify via callback *)
let add_local_candidate agent candidate =
  agent.local_candidates <- candidate :: agent.local_candidates;
  (* Form pairs with existing remote candidates *)
  form_new_pairs agent ~is_local:true candidate;
  (* Notify via Trickle ICE callback *)
  match agent.on_candidate_cb with
  | Some cb -> cb candidate
  | None -> ()

(** Add remote candidate - Trickle ICE entry point *)
let add_remote_candidate agent candidate =
  agent.remote_candidates <- candidate :: agent.remote_candidates;
  (* Form pairs with existing local candidates *)
  form_new_pairs agent ~is_local:false candidate

(** Set callback for new local candidates (Trickle ICE) *)
let on_candidate agent callback =
  agent.on_candidate_cb <- Some callback

(** Set callback for gathering complete *)
let on_gathering_complete agent callback =
  agent.on_gathering_complete_cb <- Some callback

(** Signal end of remote candidates *)
let set_remote_end_of_candidates agent =
  agent.remote_end_of_candidates <- true

(** Signal end of local candidates *)
let set_end_of_candidates agent =
  agent.gathering_state <- Gathering_complete;
  match agent.on_gathering_complete_cb with
  | Some cb -> cb ()
  | None -> ()

(** {1 Connectivity Checks - RFC 8445 Section 6} *)

(** Perform connectivity check on a pair *)
let check_pair _agent pair =
  (* Simplified: just mark as succeeded *)
  let succeeded_pair = { pair with pair_state = Pair_succeeded } in
  Lwt.return (Check_success succeeded_pair)

(** Get all candidate pairs *)
let get_pairs agent = agent.pairs

(** Get nominated pair *)
let get_nominated_pair agent = agent.nominated_pair

(** {1 Remote Credentials} *)

(** Set remote ICE credentials *)
let set_remote_credentials agent ~ufrag ~pwd =
  agent.remote_ufrag <- Some ufrag;
  agent.remote_pwd <- Some pwd

(** Get local credentials *)
let get_local_credentials agent =
  (agent.local_ufrag, agent.local_pwd)

(** {1 State Management} *)

(** Close the agent *)
let close agent =
  agent.state <- Closed

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
  agent.remote_end_of_candidates <- false

(** {1 JSON Status} *)

let status_json agent =
  `Assoc [
    ("state", `String (string_of_connection_state agent.state));
    ("gatheringState", `String (string_of_gathering_state agent.gathering_state));
    ("isGathering", `Bool (agent.gathering_state = Gathering));
    ("localCandidates", `Int (List.length agent.local_candidates));
    ("remoteCandidates", `Int (List.length agent.remote_candidates));
    ("pairs", `Int (List.length agent.pairs));
    ("hasNominatedPair", `Bool (Option.is_some agent.nominated_pair));
    ("localUfrag", `String agent.local_ufrag);
    ("role", `String (match agent.config.role with Controlling -> "controlling" | Controlled -> "controlled"));
  ]

(** {1 Pretty Printing} *)

let pp_candidate fmt c =
  Format.fprintf fmt "%s %d %s %d %s:%d typ %s"
    c.foundation c.component
    (string_of_transport c.transport)
    c.priority c.address c.port
    (string_of_candidate_type c.cand_type)

let pp_pair fmt p =
  Format.fprintf fmt "(%a <-> %a) priority=%Ld state=%s nominated=%b"
    pp_candidate p.local
    pp_candidate p.remote
    p.pair_priority
    (string_of_pair_state p.pair_state)
    p.nominated
