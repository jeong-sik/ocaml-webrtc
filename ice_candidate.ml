(** RFC 8445 ICE Candidate - Gathering, discovery, parsing

    Candidate types, priority calculation, network interface discovery,
    STUN/TURN URL parsing, and candidate serialization.

    Used by {!Ice} for agent coordination.
*)

(** {1 Candidate Types} *)

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

(** {1 Foundation Generation - RFC 8445 Section 5.1.1.3} *)

let generate_foundation ~candidate_type ~base_address ?stun_server () =
  let type_str = string_of_candidate_type candidate_type in
  let server_str = Option.value stun_server ~default:"" in
  let input = type_str ^ base_address ^ server_str in
  (* Simple hash-based foundation *)
  Digest.string input |> Digest.to_hex |> fun s -> String.sub s 0 8
;;

(** {1 Candidate Creation} *)

(** Create a server-reflexive candidate from STUN response. *)
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

(** {1 Network Interface Discovery} *)

(** Check if IP address is loopback (127.x.x.x) - RFC 5735 *)
let is_loopback ip = String.starts_with ~prefix:Webrtc_constants.loopback_prefix ip

(** Check if IP address is link-local (169.254.x.x) - RFC 3927 *)
let is_link_local ip = String.starts_with ~prefix:Webrtc_constants.link_local_prefix ip

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
    let addr =
      Unix.ADDR_INET (Unix.inet_addr_of_string Webrtc_constants.google_dns, 80)
    in
    Unix.connect sock addr;
    let local_addr = Unix.getsockname sock in
    Unix.close sock;
    match local_addr with
    | Unix.ADDR_INET (ip, _) -> Some (Unix.string_of_inet_addr ip)
    | _ -> None
  with
  | Unix.Unix_error (err, func, arg) ->
    Log.warn
      "discover_local_ip: Unix error: %s (func=%s, arg=%s)"
      (Unix.error_message err)
      func
      arg;
    None
;;

(** Discover local IP for a specific STUN server *)
let discover_local_ip_for_server server_host =
  try
    let addrs =
      Unix.getaddrinfo
        server_host
        (string_of_int Webrtc_constants.stun_default_port)
        [ Unix.AI_FAMILY Unix.PF_INET ]
    in
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
  | Unix.Unix_error (err, func, arg) ->
    Log.warn
      "discover_local_ip_for_server(%s): Unix error: %s (func=%s, arg=%s)"
      server_host
      (Unix.error_message err)
      func
      arg;
    None
  | Not_found ->
    Log.warn "discover_local_ip_for_server(%s): host not found" server_host;
    None
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
    | Not_found | Invalid_argument _ -> None)
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
       | Unix.Unix_error _ | Sys_error _ -> None
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
   | Unix.Unix_error _ | Sys_error _ -> ());
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
   | Sys_error _ -> ());
  !addresses
;;

(** Discover addresses by connecting to multiple external endpoints. *)
let discover_addresses_via_routing () =
  let addresses = ref [] in
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
       | Unix.Unix_error _ -> ())
    external_targets;
  !addresses
;;

(** Get list of usable local IP addresses.
    Uses multiple methods for comprehensive interface discovery. *)
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
   | Unix.Unix_error _ | Not_found -> ());
  !addresses
;;

(** {1 URL Parsing} *)

(** Parse STUN server URL to extract host and port *)
let parse_stun_url url =
  (* Format: stun:host:port or stun:host *)
  let url =
    if String.starts_with ~prefix:Webrtc_constants.stun_url_prefix url
    then
      String.sub
        url
        (String.length Webrtc_constants.stun_url_prefix)
        (String.length url - String.length Webrtc_constants.stun_url_prefix)
    else url
  in
  match String.split_on_char ':' url with
  | [ host; port_str ] ->
    (match int_of_string_opt port_str with
     | Some port -> Some (host, port)
     | None -> Some (host, Webrtc_constants.stun_default_port))
  | [ host ] -> Some (host, Webrtc_constants.stun_default_port)
  | _ -> None
;;

(** Parse TURN server URL to extract host, port, and TLS flag.
    Format: turn:host:port or turn:host or turns:host:port *)
let parse_turn_url url =
  (* Remove protocol prefix *)
  let url, is_tls =
    if String.starts_with ~prefix:Webrtc_constants.turns_url_prefix url
    then
      ( String.sub
          url
          (String.length Webrtc_constants.turns_url_prefix)
          (String.length url - String.length Webrtc_constants.turns_url_prefix)
      , true )
    else if String.starts_with ~prefix:Webrtc_constants.turn_url_prefix url
    then
      ( String.sub
          url
          (String.length Webrtc_constants.turn_url_prefix)
          (String.length url - String.length Webrtc_constants.turn_url_prefix)
      , false )
    else url, false
  in
  let default_port =
    if is_tls
    then Webrtc_constants.turns_default_port
    else Webrtc_constants.stun_default_port
  in
  (* Parse host and port *)
  match String.split_on_char ':' url with
  | [ host; port_str ] ->
    (match int_of_string_opt port_str with
     | Some port -> Some (host, port, is_tls)
     | None -> Some (host, default_port, is_tls))
  | [ host ] -> Some (host, default_port, is_tls)
  | _ -> None
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
