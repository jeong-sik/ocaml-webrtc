(** RFC 4960 - Stream Control Transmission Protocol (SCTP)

    Pure OCaml implementation of SCTP for WebRTC data channels.

    SCTP provides:
    - Reliable, in-order delivery (configurable per stream)
    - Multiple streams within a single association
    - Message-oriented (not byte-stream)
    - Congestion control

    For WebRTC, SCTP runs over DTLS (RFC 8261).

    Reference: https://datatracker.ietf.org/doc/html/rfc4960
*)

(** {1 Types} *)

(** SCTP Chunk Types - RFC 4960 Section 3.2 *)
type chunk_type =
  | DATA
  | INIT
  | INIT_ACK
  | SACK
  | HEARTBEAT
  | HEARTBEAT_ACK
  | ABORT
  | SHUTDOWN
  | SHUTDOWN_ACK
  | ERROR
  | COOKIE_ECHO
  | COOKIE_ACK
  | SHUTDOWN_COMPLETE
  | FORWARD_TSN
  | RE_CONFIG
  | Unknown of int

val pp_chunk_type : Format.formatter -> chunk_type -> unit
val equal_chunk_type : chunk_type -> chunk_type -> bool
val show_chunk_type : chunk_type -> string

(** Association states - RFC 4960 Section 4 *)
type state =
  | Closed
  | Cookie_wait
  | Cookie_echoed
  | Established
  | Shutdown_pending
  | Shutdown_sent
  | Shutdown_received
  | Shutdown_ack_sent

val pp_state : Format.formatter -> state -> unit
val equal_state : state -> state -> bool
val show_state : state -> string

(** WebRTC Data Channel PPID message types - RFC 8831 *)
type message_type =
  | WebRTC_DCEP
  | WebRTC_String
  | WebRTC_Binary
  | WebRTC_String_Empty
  | WebRTC_Binary_Empty

val pp_message_type : Format.formatter -> message_type -> unit
val equal_message_type : message_type -> message_type -> bool
val show_message_type : message_type -> string

(** Data chunk flags *)
type data_flags =
  { end_fragment : bool
  ; begin_fragment : bool
  ; unordered : bool
  ; immediate : bool
  }

(** DATA chunk structure *)
type data_chunk =
  { flags : data_flags
  ; tsn : int32
  ; stream_id : int
  ; stream_seq : int
  ; ppid : int32
  ; user_data : bytes
  }

(** SCTP packet header - RFC 4960 Section 3 *)
type packet_header =
  { source_port : int
  ; dest_port : int
  ; verification_tag : int32
  ; checksum : int32
  }

(** Raw chunk for encoding/decoding *)
type raw_chunk =
  { chunk_type : int
  ; chunk_flags : int
  ; chunk_length : int
  ; chunk_value : bytes
  }

(** SCTP Packet *)
type packet =
  { header : packet_header
  ; chunks : raw_chunk list
  }

(** Stream within an association *)
type stream =
  { id : int
  ; ordered : bool
  ; mutable next_ssn : int
  ; mutable next_tsn : int32
  }

(** SCTP configuration *)
type config =
  { local_port : int
  ; remote_port : int
  ; mtu : int
  ; max_retransmits : int
  ; rto_initial_ms : int
  ; rto_min_ms : int
  ; rto_max_ms : int
  ; a_rwnd : int
  ; num_outbound_streams : int
  ; num_inbound_streams : int
  ; skip_checksum_validation : bool
  }

(** SCTP Association *)
type association =
  { mutable state : state
  ; streams : (int, stream) Hashtbl.t
  ; config : config
  ; mutable my_vtag : int32
  ; mutable peer_vtag : int32
  ; mutable next_tsn : int32
  ; mutable last_rcvd_tsn : int32
  ; mutable cwnd : int
  ; mutable ssthresh : int
  }

(** {1 Default Configuration} *)

val default_config : config

(** {1 String Conversions} *)

val string_of_chunk_type : chunk_type -> string
val chunk_type_of_int : int -> chunk_type
val int_of_chunk_type : chunk_type -> int
val string_of_state : state -> string
val string_of_message_type : message_type -> string

(** {1 PPID Conversions - RFC 8831} *)

val ppid_of_message_type : message_type -> int32
val message_type_of_ppid : int32 -> message_type option

(** {1 Association Management} *)

val create : config -> association
val get_state : association -> state
val is_established : association -> bool

val association_info
  :  association
  -> [> `Assoc of (string * [> `Int of int | `String of string ]) list ]

(** {1 Stream Management} *)

val open_stream : association -> int -> ?ordered:bool -> unit -> stream
val get_stream : association -> int -> stream option
val close_stream : association -> int -> unit
val get_streams : association -> stream list

(** {1 Encoding/Decoding} *)

val encode_data_chunk_into : buf:bytes -> off:int -> data_chunk -> int
val encode_data_chunk : data_chunk -> bytes
val encode_data_chunks_batch : data_chunk list -> mtu:int -> bytes list

val fragment_data
  :  data:bytes
  -> stream_id:int
  -> stream_seq:int
  -> ppid:int32
  -> start_tsn:int32
  -> mtu:int
  -> data_chunk list

val decode_data_chunk_view : bytes -> off:int -> len:int -> (data_chunk, string) result
val decode_data_chunk : bytes -> (data_chunk, string) result
val calculate_checksum : bytes -> int32
val encode_packet : packet -> bytes
val decode_packet : bytes -> (packet, string) result
val is_sctp_data : bytes -> bool

(** {1 State Machine} *)

val set_state : association -> state -> unit
val establish : association -> unit
val begin_shutdown : association -> unit

(** {1 Pretty Printing} *)

val pp_data_chunk : Format.formatter -> data_chunk -> unit
val pp_stream : Format.formatter -> stream -> unit
val pp_association : Format.formatter -> association -> unit
