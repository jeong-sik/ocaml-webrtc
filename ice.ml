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
  | Host (** Local interface address *)
  | Server_reflexive (** Address as seen by STUN server *)
  | Peer_reflexive (** Address discovered during connectivity checks *)
  | Relay (** Relay address from TURN server *)
[@@deriving show, eq]

(** Transport protocol *)
type transport =
  | UDP
  | TCP
[@@deriving show, eq]

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

(** ICE candidate - represents a potential connection endpoint *)
type candidate =
  { foundation : string (** Uniquely identifies candidate base *)
  ; component : int (** 1 = RTP, 2 = RTCP *)
  ; transport : transport
  ; priority : int
  ; address : string
  ; port : int
  ; cand_type : candidate_type
  ; base_address : string option (** Base address for srflx/prflx/relay *)
  ; base_port : int option
  ; related_address : string option (** Related address for srflx/prflx/relay *)
  ; related_port : int option
  ; extensions : (string * string) list
  }

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
      [ { urls = [ "stun:stun.l.google.com:19302" ]
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

let string_of_candidate_type = function
  | Host -> "host"
  | Server_reflexive -> "srflx"
  | Peer_reflexive -> "prflx"
  | Relay -> "relay"
;;

let candidate_type_of_string = function
  | "host" -> Some Host
  | "srflx" -> Some Server_reflexive
  | "prflx" -> Some Peer_reflexive
  | "relay" -> Some Relay
  | _ -> None
;;

let string_of_transport = function
  | UDP -> "UDP"
  | TCP -> "TCP"
;;

let transport_of_string = function
  | "UDP" | "udp" -> Some UDP
  | "TCP" | "tcp" -> Some TCP
  | _ -> None
;;

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

(** {1 Priority Calculation - RFC 8445 Section 5.1.2} *)

(** Type preference values per RFC 8445 *)
let type_preference = function
  | Host -> 126
  | Peer_reflexive -> 110
  | Server_reflexive -> 100
  | Relay -> 0
;;

(** Calculate candidate priority:
    priority = (2^24) * (type preference) + (2^8) * (local preference) + (256 - component ID) *)
let calculate_priority ~candidate_type ~local_pref ~component =
  let type_pref = type_preference candidate_type in
  (type_pref lsl 24) + (local_pref lsl 8) + (256 - component)
;;

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

(** {1 Foundation Generation - RFC 8445 Section 5.1.1.3} *)

let generate_foundation ~candidate_type ~base_address ?stun_server () =
  let type_str = string_of_candidate_type candidate_type in
  let server_str = Option.value stun_server ~default:"" in
  let input = type_str ^ base_address ^ server_str in
  (* Simple hash-based foundation *)
  Digest.string input |> Digest.to_hex |> fun s -> String.sub s 0 8
;;

(** Create a server-reflexive candidate from STUN response.
    This is a helper for Eio-based ICE implementations. *)
let create_srflx_candidate ~component ~address ~port ~base_address ~base_port =
  { foundation = generate_foundation ~candidate_type:Server_reflexive ~base_address ()
  ; component
  ; transport = UDP
  ; priority =
      calculate_priority ~candidate_type:Server_reflexive ~local_pref:65535 ~component
  ; address
  ; port
  ; cand_type = Server_reflexive
  ; base_address = Some base_address
  ; base_port = Some base_port
  ; related_address = Some base_address
  ; related_port = Some base_port
  ; extensions = []
  }
;;

(** Create a peer-reflexive candidate from an incoming connectivity check. *)
let create_prflx_candidate ~component ~address ~port ?base_address ?base_port () =
  let base_address = Option.value ~default:address base_address in
  let base_port = Option.value ~default:port base_port in
  { foundation = generate_foundation ~candidate_type:Peer_reflexive ~base_address ()
  ; component
  ; transport = UDP
  ; priority =
      calculate_priority ~candidate_type:Peer_reflexive ~local_pref:65535 ~component
  ; address
  ; port
  ; cand_type = Peer_reflexive
  ; base_address = Some base_address
  ; base_port = Some base_port
  ; related_address = Some base_address
  ; related_port = Some base_port
  ; extensions = []
  }
;;

(** {1 Candidate Parsing - RFC 8445 Section 15.1} *)

(** Parse SDP candidate attribute line *)
let parse_candidate line =
  let parts = String.split_on_char ' ' (String.trim line) in
  match parts with
  | foundation
    :: component_str
    :: transport_str
    :: priority_str
    :: address
    :: port_str
    :: "typ"
    :: type_str
    :: rest ->
    (match
       ( int_of_string_opt component_str
       , transport_of_string transport_str
       , int_of_string_opt priority_str
       , int_of_string_opt port_str
       , candidate_type_of_string type_str )
     with
     | Some component, Some transport, Some priority, Some port, Some cand_type ->
       (* Parse optional raddr/rport and extensions *)
       let rec parse_rest rel_addr rel_port exts = function
         | [] -> rel_addr, rel_port, List.rev exts
         | "raddr" :: addr :: rest -> parse_rest (Some addr) rel_port exts rest
         | "rport" :: port_str :: rest ->
           let port = int_of_string_opt port_str in
           parse_rest rel_addr port exts rest
         | key :: value :: rest ->
           parse_rest rel_addr rel_port ((key, value) :: exts) rest
         | _ :: rest -> parse_rest rel_addr rel_port exts rest
       in
       let related_address, related_port, extensions = parse_rest None None [] rest in
       Ok
         { foundation
         ; component
         ; transport
         ; priority
         ; address
         ; port
         ; cand_type
         ; base_address = related_address
         ; (* For srflx/relay, related is base *)
           base_port = related_port
         ; related_address
         ; related_port
         ; extensions
         }
     | _ -> Error "Invalid candidate format: failed to parse required fields")
  | _ -> Error "Invalid candidate format: not enough parts"
;;

(** Convert candidate to SDP attribute string *)
let candidate_to_string c =
  let base =
    Printf.sprintf
      "%s %d %s %d %s %d typ %s"
      c.foundation
      c.component
      (string_of_transport c.transport)
      c.priority
      c.address
      c.port
      (string_of_candidate_type c.cand_type)
  in
  let with_related =
    match c.related_address, c.related_port with
    | Some addr, Some port -> Printf.sprintf "%s raddr %s rport %d" base addr port
    | Some addr, None -> Printf.sprintf "%s raddr %s" base addr
    | None, Some port -> Printf.sprintf "%s rport %d" base port
    | None, None -> base
  in
  (* Add extensions *)
  List.fold_left
    (fun acc (k, v) -> Printf.sprintf "%s %s %s" acc k v)
    with_related
    c.extensions
;;

(** {1 Agent Creation and Management} *)

(** Generate random credentials *)
let generate_ufrag () =
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" in
  let len = String.length chars in
  String.init 4 (fun _ -> chars.[Random.int len])
;;

let generate_pwd () =
  let chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/" in
  let len = String.length chars in
  String.init 22 (fun _ -> chars.[Random.int len])
;;

(** Create new ICE agent *)
let create config =
  Random.self_init ();
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

(** {2 Network Interface Discovery} *)

(** Check if IP address is loopback (127.x.x.x) *)
let is_loopback ip = String.length ip >= 4 && String.sub ip 0 4 = "127."

(** Check if IP address is link-local (169.254.x.x) *)
let is_link_local ip = String.length ip >= 8 && String.sub ip 0 8 = "169.254."

(** Check if IP address is private (RFC 1918) *)
let is_private_ip ip =
  let parts = String.split_on_char '.' ip in
  match List.map int_of_string_opt parts with
  | [ Some a; Some b; _; _ ] ->
    (* 10.0.0.0/8 *)
    a = 10
    (* 172.16.0.0/12 *)
    || (a = 172 && b >= 16 && b <= 31)
    ||
    (* 192.168.0.0/16 *)
    (a = 192 && b = 168)
  | _ -> false
;;

(** Discover local IP address by connecting to external endpoint.
    This uses the routing table to find the actual outbound interface. *)
let discover_local_ip () =
  try
    (* Use Google's DNS as reference point - no actual data is sent *)
    let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
    let addr = Unix.ADDR_INET (Unix.inet_addr_of_string "8.8.8.8", 80) in
    Unix.connect sock addr;
    let local_addr = Unix.getsockname sock in
    Unix.close sock;
    match local_addr with
    | Unix.ADDR_INET (ip, _) -> Some (Unix.string_of_inet_addr ip)
    | _ -> None
  with
  | _ -> None
;;

(** Discover local IP for a specific STUN server *)
let discover_local_ip_for_server server_host =
  try
    let addrs = Unix.getaddrinfo server_host "3478" [ Unix.AI_FAMILY Unix.PF_INET ] in
    match addrs with
    | [] -> None
    | addr :: _ ->
      let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
      Unix.connect sock addr.Unix.ai_addr;
      let local_addr = Unix.getsockname sock in
      Unix.close sock;
      (match local_addr with
       | Unix.ADDR_INET (ip, _) -> Some (Unix.string_of_inet_addr ip)
       | _ -> None)
  with
  | _ -> None
;;

(** Parse IPv4 address from ifconfig/ip output line *)
let extract_ipv4_from_line line =
  (* Match patterns like "inet 192.168.1.5" or "inet addr:192.168.1.5" *)
  let ipv4_pattern =
    Str.regexp {|inet[ \t]+\(addr:\)?\([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)|}
  in
  if Str.string_match ipv4_pattern line 0
  then (
    try Some (Str.matched_group 2 line) with
    | _ -> None)
  else None
;;

(** Get local addresses from ifconfig output (macOS/Linux) *)
let get_addresses_from_ifconfig () =
  let addresses = ref [] in
  (try
     let read_process_lines prog argv =
       try
         let ic = Unix.open_process_args_in prog argv in
         let rec loop acc =
           match input_line ic with
           | line -> loop (line :: acc)
           | exception End_of_file ->
             ignore (Unix.close_process_in ic);
             List.rev acc
         in
         Some (loop [])
       with
       | _ -> None
     in
     let lines =
       match read_process_lines "ifconfig" [| "ifconfig" |] with
       | Some ls -> ls
       | None ->
         (match read_process_lines "ip" [| "ip"; "addr" |] with
          | Some ls -> ls
          | None -> [])
     in
     List.iter
       (fun line ->
          match extract_ipv4_from_line line with
          | Some ip when (not (is_loopback ip)) && not (is_link_local ip) ->
            if not (List.mem ip !addresses) then addresses := ip :: !addresses
          | _ -> ())
       lines
   with
   | _ -> ());
  !addresses
;;

(** Get addresses from /proc/net/fib_trie (Linux only, Pure OCaml) *)
let get_addresses_from_proc () =
  let addresses = ref [] in
  (try
     let ic = open_in "/proc/net/fib_trie" in
     let local_pattern = Str.regexp {|.*|-- \([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\)$|} in
     let in_local_block = ref false in
     (try
        while true do
          let line = input_line ic in
          (* Look for LOCAL entries which indicate assigned addresses *)
          if String.length line > 0
          then
            if Str.string_match (Str.regexp {|.*/32 host LOCAL|}) line 0
            then in_local_block := true
            else if !in_local_block && Str.string_match local_pattern line 0
            then (
              let ip = Str.matched_group 1 line in
              if
                (not (is_loopback ip))
                && (not (is_link_local ip))
                && not (List.mem ip !addresses)
              then addresses := ip :: !addresses;
              in_local_block := false)
            else if String.length line > 0 && line.[0] <> ' '
            then in_local_block := false
        done
      with
      | End_of_file -> ());
     close_in ic
   with
   | _ -> ());
  !addresses
;;

(** Discover addresses by connecting to multiple external endpoints.
    This helps find addresses on different network interfaces. *)
let discover_addresses_via_routing () =
  let addresses = ref [] in
  (* List of well-known public DNS servers in different networks *)
  let external_targets =
    [ "8.8.8.8"
    ; (* Google DNS *)
      "1.1.1.1"
    ; (* Cloudflare DNS *)
      "208.67.222.222"
    ; (* OpenDNS *)
      "9.9.9.9" (* Quad9 DNS *)
    ]
  in
  List.iter
    (fun target ->
       try
         let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
         let addr = Unix.ADDR_INET (Unix.inet_addr_of_string target, 80) in
         Unix.connect sock addr;
         let local_addr = Unix.getsockname sock in
         Unix.close sock;
         match local_addr with
         | Unix.ADDR_INET (ip, _) ->
           let ip_str = Unix.string_of_inet_addr ip in
           if
             (not (is_loopback ip_str))
             && (not (is_link_local ip_str))
             && not (List.mem ip_str !addresses)
           then addresses := ip_str :: !addresses
         | _ -> ()
       with
       | _ -> ())
    external_targets;
  !addresses
;;

(** Get list of usable local IP addresses.
    Uses multiple methods for comprehensive interface discovery:
    1. Routing-based discovery (most reliable for default interface)
    2. ifconfig/ip addr parsing (finds all configured interfaces)
    3. /proc/net/fib_trie parsing (Linux-specific, Pure OCaml)
    4. Hostname resolution (fallback)

    RFC 8445 Section 5.1.1: "The agent gathers candidates from its
    host candidates (IP addresses attached to its network interfaces)."
*)
let get_local_addresses () =
  let addresses = ref [] in
  let add_if_new ip =
    if (not (is_loopback ip)) && (not (is_link_local ip)) && not (List.mem ip !addresses)
    then addresses := ip :: !addresses
  in
  (* Method 1: Routing-based discovery (reliable for primary interface) *)
  List.iter add_if_new (discover_addresses_via_routing ());
  (* Method 2: ifconfig/ip addr parsing (all interfaces) *)
  List.iter add_if_new (get_addresses_from_ifconfig ());
  (* Method 3: /proc/net/fib_trie (Linux, no external process) *)
  List.iter add_if_new (get_addresses_from_proc ());
  (* Method 4: Hostname resolution (fallback) *)
  (try
     let hostname = Unix.gethostname () in
     let host_entry = Unix.gethostbyname hostname in
     Array.iter
       (fun addr -> add_if_new (Unix.string_of_inet_addr addr))
       host_entry.Unix.h_addr_list
   with
   | _ -> ());
  !addresses
;;

(** {2 Candidate Gathering} *)

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

(** Gather local host candidates with Trickle ICE support *)
(** Parse STUN server URL to extract host and port *)
let parse_stun_url url =
  (* Format: stun:host:port or stun:host *)
  let url =
    if String.sub url 0 5 = "stun:" then String.sub url 5 (String.length url - 5) else url
  in
  match String.split_on_char ':' url with
  | [ host; port_str ] ->
    (match int_of_string_opt port_str with
     | Some port -> Some (host, port)
     | None -> Some (host, 3478))
    (* Default STUN port *)
  | [ host ] -> Some (host, 3478)
  | _ -> None
;;

(** {2 TURN Relay Candidate Gathering - RFC 5766} *)

(** Parse TURN server URL to extract host, port, and credentials.
    Format: turn:host:port or turn:host or turns:host:port
    Credentials may be in ice_server configuration. *)
let parse_turn_url url =
  (* Remove protocol prefix *)
  let url, is_tls =
    if String.length url >= 6 && String.sub url 0 6 = "turns:"
    then String.sub url 6 (String.length url - 6), true
    else if String.length url >= 5 && String.sub url 0 5 = "turn:"
    then String.sub url 5 (String.length url - 5), false
    else url, false
  in
  (* Parse host and port *)
  match String.split_on_char ':' url with
  | [ host; port_str ] ->
    (match int_of_string_opt port_str with
     | Some port -> Some (host, port, is_tls)
     | None -> Some (host, (if is_tls then 5349 else 3478), is_tls))
  | [ host ] -> Some (host, (if is_tls then 5349 else 3478), is_tls)
  | _ -> None
;;

(** Create a relay candidate from TURN allocation response.
    RFC 8445 Section 5.1.1.2: Relay candidates have the lowest priority
    (type preference = 0) but provide connectivity through NAT/firewall. *)
let create_relay_candidate ~component ~address ~port ~base_address ~base_port ~turn_server
  =
  { foundation =
      generate_foundation ~candidate_type:Relay ~base_address ~stun_server:turn_server ()
  ; component
  ; transport = UDP
  ; priority = calculate_priority ~candidate_type:Relay ~local_pref:65535 ~component
  ; address
  ; port
  ; cand_type = Relay
  ; base_address = Some base_address
  ; base_port = Some base_port
  ; related_address = Some base_address
  ; related_port = Some base_port
  ; extensions = []
  }
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
let generate_tie_breaker () = Random.int64 Int64.max_int

(** Get all candidate pairs *)
let get_pairs agent = agent.pairs

(** Get nominated pair *)
let get_nominated_pair agent = agent.nominated_pair

(** Get the best succeeded pair for nomination *)

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
  let now = Unix.gettimeofday () in
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
    let now = Unix.gettimeofday () in
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
    let now = Unix.gettimeofday () in
    let elapsed = now -. agent.consent_last_received in
    elapsed >= consent_refresh_interval_s)
;;

(** Get consent status for monitoring *)
let get_consent_status agent =
  let now = Unix.gettimeofday () in
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

let pp_candidate fmt c =
  Format.fprintf
    fmt
    "%s %d %s %d %s:%d typ %s"
    c.foundation
    c.component
    (string_of_transport c.transport)
    c.priority
    c.address
    c.port
    (string_of_candidate_type c.cand_type)
;;

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

(** Calculate candidate pair priority per RFC 5245 Section 5.7.2.

    Formula: 2^32 * MIN(G, D) + 2 * MAX(G, D) + (G > D ? 1 : 0)

    Where G = priority of controlling agent's candidate
          D = priority of controlled agent's candidate

    @param controlling_priority Priority of the controlling agent's candidate
    @param controlled_priority Priority of the controlled agent's candidate
    @param role Current agent's role (Controlling or Controlled)
    @return 64-bit pair priority
*)
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

(** Nominate a candidate pair.

    In Regular nomination, this happens after connectivity check succeeds.
    In Aggressive nomination, this happens immediately when sending check.

    @param agent The ICE agent
    @param pair The pair to nominate
    @return Updated agent with nominated pair
*)
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

(** Start keepalive mechanism for nominated pair.

    Sends STUN Binding Indications at regular intervals to keep
    NAT bindings alive per RFC 5245 Section 10.

    @param interval_sec Keepalive interval in seconds (default: 15.0)
    @return Keepalive state
*)
let start_keepalive ?(interval_sec = 15.0) () =
  Keepalive_active { last_sent = Unix.gettimeofday (); interval = interval_sec }
;;

(** Check if keepalive should be sent now.

    @param state Current keepalive state
    @param now Current timestamp
    @return true if keepalive is due
*)
let is_keepalive_due state now =
  match state with
  | Keepalive_stopped -> false
  | Keepalive_active { last_sent; interval } -> now -. last_sent >= interval
;;

(** Update keepalive state after sending.

    @param state Current keepalive state
    @return Updated state with new timestamp
*)
let update_keepalive_sent state =
  match state with
  | Keepalive_stopped -> Keepalive_stopped
  | Keepalive_active ka -> Keepalive_active { ka with last_sent = Unix.gettimeofday () }
;;

(** Handle keepalive timeout - peer may be unreachable.

    If too many keepalives fail, the connection should be considered dead.

    @param max_failures Maximum consecutive failures before timeout
    @param current_failures Current failure count
    @return true if connection should be considered dead
*)
let is_keepalive_timeout ~max_failures ~current_failures =
  current_failures >= max_failures
;;

(** Get recommended keepalive interval per RFC 5245.

    The default is 15 seconds for UDP. For TCP, keepalives are less critical
    since the connection state is maintained by the transport.

    @param transport UDP or TCP
    @return Recommended interval in seconds
*)
let recommended_keepalive_interval = function
  | UDP -> 15.0
  | TCP -> 30.0
;;
