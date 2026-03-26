(** RFC 8445 ICE Candidate - Gathering, discovery, parsing

    Candidate types, priority calculation, network interface discovery,
    STUN/TURN URL parsing, and candidate serialization.
*)

(** {1 Candidate Types} *)

type candidate_type =
  | Host
  | Server_reflexive
  | Peer_reflexive
  | Relay

val pp_candidate_type : Format.formatter -> candidate_type -> unit
val equal_candidate_type : candidate_type -> candidate_type -> bool
val show_candidate_type : candidate_type -> string

type transport =
  | UDP
  | TCP

val pp_transport : Format.formatter -> transport -> unit
val equal_transport : transport -> transport -> bool
val show_transport : transport -> string

type candidate =
  { foundation : string
  ; component : int
  ; transport : transport
  ; priority : int
  ; address : string
  ; port : int
  ; cand_type : candidate_type
  ; base_address : string option
  ; base_port : int option
  ; related_address : string option
  ; related_port : int option
  ; extensions : (string * string) list
  }

(** {1 String Conversions} *)

val string_of_candidate_type : candidate_type -> string
val candidate_type_of_string : string -> candidate_type option
val string_of_transport : transport -> string
val transport_of_string : string -> transport option

(** {1 Priority Calculation - RFC 8445 Section 5.1.2} *)

val type_preference : candidate_type -> int

val calculate_priority
  :  candidate_type:candidate_type
  -> local_pref:int
  -> component:int
  -> int

(** {1 Foundation Generation - RFC 8445 Section 5.1.1.3} *)

val generate_foundation
  :  candidate_type:candidate_type
  -> base_address:string
  -> ?stun_server:string
  -> unit
  -> string

(** {1 Candidate Creation} *)

val create_srflx_candidate
  :  component:int
  -> address:string
  -> port:int
  -> base_address:string
  -> base_port:int
  -> candidate

val create_prflx_candidate
  :  component:int
  -> address:string
  -> port:int
  -> ?base_address:string
  -> ?base_port:int
  -> unit
  -> candidate

val create_relay_candidate
  :  component:int
  -> address:string
  -> port:int
  -> base_address:string
  -> base_port:int
  -> turn_server:string
  -> candidate

(** {1 Candidate Parsing - RFC 8445 Section 15.1} *)

val parse_candidate : string -> (candidate, string) result
val candidate_to_string : candidate -> string

(** {1 Network Interface Discovery} *)

val is_loopback : string -> bool
val is_link_local : string -> bool
val is_private_ip : string -> bool
val discover_local_ip : unit -> string option
val discover_local_ip_for_server : string -> string option
val extract_ipv4_from_line : string -> string option
val get_addresses_from_ifconfig : unit -> string list
val get_addresses_from_proc : unit -> string list
val discover_addresses_via_routing : unit -> string list
val get_local_addresses : unit -> string list

(** {1 URL Parsing} *)

val parse_stun_url : string -> (string * int) option
val parse_turn_url : string -> (string * int * bool) option

(** {1 Pretty Printing} *)

val pp_candidate : Format.formatter -> candidate -> unit
