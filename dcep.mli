(** RFC 8832 - WebRTC Data Channel Establishment Protocol (DCEP)

    DCEP runs over SCTP with PPID 50 (WebRTC_DCEP) and negotiates
    DataChannel properties between WebRTC peers.

    {1 Protocol Flow}

    {v
    Initiator                    Responder
       |                             |
       |--- DATA_CHANNEL_OPEN ------>|  (label, protocol, reliability options)
       |<--- DATA_CHANNEL_ACK -------|
       |                             |
       |<======= Data Flow =========>|  (PPID 51/53 for string/binary)
    v}

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

(** {1 Message Type Constants} *)

(** DATA_CHANNEL_ACK = 0x02 *)
val msg_type_data_channel_ack : int

(** DATA_CHANNEL_OPEN = 0x03 *)
val msg_type_data_channel_open : int

(** {1 Channel Types} *)

(** Channel reliability mode (RFC 8832 §5.1) *)
type channel_type =
  | Reliable (** 0x00 - Reliable ordered (default) *)
  | ReliableUnordered (** 0x80 - Reliable unordered *)
  | PartialReliableRexmit of int (** 0x01 - Limited retransmits (PR-SCTP) *)
  | PartialReliableRexmitUnordered of int (** 0x81 *)
  | PartialReliableTimed of int (** 0x02 - Limited lifetime ms (PR-SCTP) *)
  | PartialReliableTimedUnordered of int (** 0x82 *)

(** Convert channel type to wire format byte code. *)
val channel_type_to_code : channel_type -> int

(** Extract reliability parameter (max retransmits or max lifetime). *)
val channel_type_param : channel_type -> int

(** {1 DATA_CHANNEL_OPEN Message} *)

(** DATA_CHANNEL_OPEN message structure (RFC 8832 §5.1) *)
type data_channel_open =
  { channel_type : channel_type
  ; priority : int (** 0-65535, higher = more important *)
  ; label : string (** Channel label (e.g., "chat") *)
  ; protocol : string (** Subprotocol (e.g., "" or "json") *)
  }

(** {1 Channel State} *)

(** DataChannel state machine *)
type channel_state =
  | Opening (** OPEN sent, waiting for ACK *)
  | Open (** Channel is established and ready *)
  | Closing (** Close requested *)
  | Closed (** Channel is closed *)

(** DataChannel instance *)
type channel =
  { id : int (** Stream ID (SCTP stream) *)
  ; mutable state : channel_state
  ; channel_type : channel_type
  ; label : string
  ; protocol : string
  ; priority : int
  ; negotiated : bool (** true if pre-negotiated via SDP *)
  }

(** {1 DCEP Manager} *)

(** DCEP manager state (abstract) *)
type t

(** {1 Creation} *)

(** [create ~is_client] creates a new DCEP manager.

    @param is_client true for WebRTC offerer (uses even stream IDs),
                     false for answerer (uses odd stream IDs) *)
val create : is_client:bool -> t

(** {1 Message Encoding/Decoding} *)

(** [encode_open msg] encodes a DATA_CHANNEL_OPEN message.

    Wire format (12 + label + protocol bytes):
    - Message type: 1 byte (0x03)
    - Channel type: 1 byte
    - Priority: 2 bytes (big-endian)
    - Reliability param: 4 bytes
    - Label length: 2 bytes
    - Protocol length: 2 bytes
    - Label: variable
    - Protocol: variable *)
val encode_open : data_channel_open -> bytes

(** [encode_ack ()] creates a DATA_CHANNEL_ACK message (1 byte: 0x02). *)
val encode_ack : unit -> bytes

(** [decode_open buf] parses a DATA_CHANNEL_OPEN message. *)
val decode_open : bytes -> (data_channel_open, string) result

(** [is_ack buf] returns true if buffer contains DATA_CHANNEL_ACK. *)
val is_ack : bytes -> bool

(** {1 Channel Management} *)

(** [allocate_stream_id t] returns next available stream ID.

    Client uses even IDs (0, 2, 4, ...),
    Server uses odd IDs (1, 3, 5, ...). *)
val allocate_stream_id : t -> int

(** [open_channel t ~label ?protocol ?priority ?channel_type ()]
    creates a new DataChannel and returns (stream_id, open_message).

    @param label Channel name (e.g., "chat", "game-state")
    @param protocol Subprotocol (default: "")
    @param priority Priority level (default: 256)
    @param channel_type Reliability mode (default: Reliable)
    @return (stream_id, DATA_CHANNEL_OPEN message to send) *)
val open_channel
  :  t
  -> label:string
  -> ?protocol:string
  -> ?priority:int
  -> ?channel_type:channel_type
  -> unit
  -> int * bytes

(** [handle_open t ~stream_id open_msg] processes incoming OPEN.

    Creates channel in Open state and returns ACK message.

    @return (stream_id, DATA_CHANNEL_ACK message to send) *)
val handle_open : t -> stream_id:int -> data_channel_open -> int * bytes

(** [handle_ack t ~stream_id] processes incoming ACK.

    Transitions channel from Opening to Open state. *)
val handle_ack : t -> stream_id:int -> (unit, string) result

(** [close_channel t ~stream_id] closes and removes a channel. *)
val close_channel : t -> stream_id:int -> unit

(** [get_channel t ~stream_id] looks up channel by stream ID. *)
val get_channel : t -> stream_id:int -> channel option

(** [get_channel_by_label t ~label] looks up channel by label. *)
val get_channel_by_label : t -> label:string -> channel option

(** [list_channels t] returns all channels in Open state. *)
val list_channels : t -> channel list

(** {1 PPID Selection} *)

(** [ppid_for_data ~is_string channel] returns appropriate SCTP PPID.

    RFC 8831 §8 PPID values:
    - 51: WebRTC String
    - 53: WebRTC Binary *)
val ppid_for_data : is_string:bool -> channel -> int32

(** {1 Statistics} *)

type stats =
  { channels_opened : int
  ; channels_closed : int
  ; active_channels : int
  }

(** [get_stats t] returns channel statistics. *)
val get_stats : t -> stats

(** {1 Debug Utilities} *)

(** Convert channel type to human-readable string. *)
val string_of_channel_type : channel_type -> string

(** Convert channel state to string. *)
val string_of_state : channel_state -> string

(** Format channel info for debugging. *)
val pp_channel : channel -> string
