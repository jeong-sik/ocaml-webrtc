(** RFC 8832 - WebRTC Data Channel Establishment Protocol (DCEP)

    DCEP runs over SCTP with PPID 50 (WebRTC_DCEP).
    It negotiates DataChannel properties between peers.

    Message flow:
    {v
    Initiator                    Responder
       |                             |
       |--- DATA_CHANNEL_OPEN ------>|  (label, protocol, options)
       |<--- DATA_CHANNEL_ACK -------|
       |                             |
       |<======= Data Flow =========>|  (PPID based on options)
    v}

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

(** {1 Message Types (RFC 8832 §5)} *)

let msg_type_data_channel_ack = 0x02
let msg_type_data_channel_open = 0x03

(** {1 Channel Types (RFC 8832 §5.1)} *)

type channel_type =
  | Reliable (** 0x00 - Reliable ordered *)
  | ReliableUnordered (** 0x80 - Reliable unordered *)
  | PartialReliableRexmit of int (** 0x01 - Max retransmits (PR-SCTP) *)
  | PartialReliableRexmitUnordered of int (** 0x81 *)
  | PartialReliableTimed of int (** 0x02 - Max lifetime ms (PR-SCTP) *)
  | PartialReliableTimedUnordered of int (** 0x82 *)

(** Channel type to byte code *)
let channel_type_to_code = function
  | Reliable -> 0x00
  | ReliableUnordered -> 0x80
  | PartialReliableRexmit _ -> 0x01
  | PartialReliableRexmitUnordered _ -> 0x81
  | PartialReliableTimed _ -> 0x02
  | PartialReliableTimedUnordered _ -> 0x82
;;

(** Extract reliability parameter from channel type *)
let channel_type_param = function
  | Reliable | ReliableUnordered -> 0
  | PartialReliableRexmit n | PartialReliableRexmitUnordered n -> n
  | PartialReliableTimed n | PartialReliableTimedUnordered n -> n
;;

(** {1 DATA_CHANNEL_OPEN Message (RFC 8832 §5.1)} *)

type data_channel_open =
  { channel_type : channel_type
  ; priority : int (** 0-65535, higher = more important *)
  ; label : string (** Channel label (e.g., "chat") *)
  ; protocol : string (** Subprotocol (e.g., "" or "json") *)
  }

(** {1 DataChannel State} *)

type channel_state =
  | Opening (** OPEN sent, waiting for ACK *)
  | Open (** Channel is established *)
  | Closing (** Close requested *)
  | Closed (** Channel is closed *)

type channel =
  { id : int (** Stream ID (SCTP stream) *)
  ; mutable state : channel_state
  ; channel_type : channel_type
  ; label : string
  ; protocol : string
  ; priority : int
  ; negotiated : bool (** true if pre-negotiated via SDP *)
  }

(** {1 DCEP Manager State} *)

type t =
  { mutable channels : (int, channel) Hashtbl.t (** stream_id -> channel *)
  ; mutable next_stream_id : int (** Next available stream ID *)
  ; is_client : bool (** Client uses even IDs, server uses odd *)
  }
[@@warning "-69"]

(** {1 Creation} *)

let create ~is_client =
  { channels = Hashtbl.create 16
  ; next_stream_id = (if is_client then 0 else 1)
  ; (* Even for client, odd for server *)
    is_client
  }
;;

(** {1 Encoding (RFC 8832 §5.1)} *)

(** Encode DATA_CHANNEL_OPEN message *)
let encode_open (open_msg : data_channel_open) =
  let label_bytes = Bytes.of_string open_msg.label in
  let proto_bytes = Bytes.of_string open_msg.protocol in
  let label_len = Bytes.length label_bytes in
  let proto_len = Bytes.length proto_bytes in
  (* Header: type(1) + channel_type(1) + priority(2) + reliability(4) +
             label_len(2) + proto_len(2) = 12 bytes *)
  let msg_len = 12 + label_len + proto_len in
  let buf = Bytes.create msg_len in
  (* Message type *)
  Bytes.set buf 0 (Char.chr msg_type_data_channel_open);
  (* Channel type *)
  Bytes.set buf 1 (Char.chr (channel_type_to_code open_msg.channel_type));
  (* Priority (big-endian) *)
  Bytes.set_uint16_be buf 2 open_msg.priority;
  (* Reliability parameter *)
  Bytes.set_int32_be buf 4 (Int32.of_int (channel_type_param open_msg.channel_type));
  (* Label length *)
  Bytes.set_uint16_be buf 8 label_len;
  (* Protocol length *)
  Bytes.set_uint16_be buf 10 proto_len;
  (* Label *)
  Bytes.blit label_bytes 0 buf 12 label_len;
  (* Protocol *)
  Bytes.blit proto_bytes 0 buf (12 + label_len) proto_len;
  buf
;;

(** Encode DATA_CHANNEL_ACK message *)
let encode_ack () =
  let buf = Bytes.create 1 in
  Bytes.set buf 0 (Char.chr msg_type_data_channel_ack);
  buf
;;

(** {1 Decoding} *)

(** Decode DATA_CHANNEL_OPEN message *)
let decode_open buf =
  if Bytes.length buf < 12
  then Error "DATA_CHANNEL_OPEN too short"
  else (
    let msg_type = Bytes.get buf 0 |> Char.code in
    if msg_type <> msg_type_data_channel_open
    then Error (Printf.sprintf "Expected OPEN (0x03), got 0x%02x" msg_type)
    else (
      let channel_type_code = Bytes.get buf 1 |> Char.code in
      let priority = Bytes.get_uint16_be buf 2 in
      let reliability_param = Bytes.get_int32_be buf 4 |> Int32.to_int in
      let label_len = Bytes.get_uint16_be buf 8 in
      let proto_len = Bytes.get_uint16_be buf 10 in
      if Bytes.length buf < 12 + label_len + proto_len
      then Error "DATA_CHANNEL_OPEN truncated"
      else (
        let label = Bytes.sub_string buf 12 label_len in
        let protocol = Bytes.sub_string buf (12 + label_len) proto_len in
        let channel_type =
          match channel_type_code with
          | 0x00 -> Reliable
          | 0x80 -> ReliableUnordered
          | 0x01 -> PartialReliableRexmit reliability_param
          | 0x81 -> PartialReliableRexmitUnordered reliability_param
          | 0x02 -> PartialReliableTimed reliability_param
          | 0x82 -> PartialReliableTimedUnordered reliability_param
          | code ->
            (* Unknown type, default to reliable *)
            Log.warn "[DCEP] Unknown channel type 0x%02x, defaulting to Reliable" code;
            Reliable
        in
        Ok { channel_type; priority; label; protocol })))
;;

(** Check if message is DATA_CHANNEL_ACK *)
let is_ack buf =
  Bytes.length buf >= 1 && Bytes.get buf 0 |> Char.code = msg_type_data_channel_ack
;;

(** {1 Channel Management} *)

(** Allocate next stream ID *)
let allocate_stream_id t =
  let id = t.next_stream_id in
  t.next_stream_id <- t.next_stream_id + 2;
  (* Skip by 2 to maintain even/odd *)
  id
;;

(** Create and open a new DataChannel *)
let open_channel t ~label ?(protocol = "") ?(priority = 256) ?(channel_type = Reliable) ()
  =
  let id = allocate_stream_id t in
  let channel =
    { id; state = Opening; channel_type; label; protocol; priority; negotiated = false }
  in
  Hashtbl.add t.channels id channel;
  (* Generate OPEN message to send *)
  let open_msg = { channel_type; priority; label; protocol } in
  id, encode_open open_msg
;;

(** Handle incoming DATA_CHANNEL_OPEN
    @return (channel_id, ack_message) *)
let handle_open t ~stream_id (open_msg : data_channel_open) =
  let channel =
    { id = stream_id
    ; state = Open
    ; (* Immediately open upon receiving OPEN *)
      channel_type = open_msg.channel_type
    ; label = open_msg.label
    ; protocol = open_msg.protocol
    ; priority = open_msg.priority
    ; negotiated = false
    }
  in
  Hashtbl.add t.channels stream_id channel;
  stream_id, encode_ack ()
;;

(** Handle incoming DATA_CHANNEL_ACK *)
let handle_ack t ~stream_id =
  match Hashtbl.find_opt t.channels stream_id with
  | Some channel ->
    channel.state <- Open;
    Ok ()
  | None -> Error (Printf.sprintf "ACK for unknown channel %d" stream_id)
;;

(** Close a channel *)
let close_channel t ~stream_id =
  match Hashtbl.find_opt t.channels stream_id with
  | Some channel ->
    channel.state <- Closed;
    Hashtbl.remove t.channels stream_id
  | None -> ()
;;

(** Get channel by ID *)
let get_channel t ~stream_id = Hashtbl.find_opt t.channels stream_id

(** Get channel by label *)
let get_channel_by_label t ~label =
  Hashtbl.fold
    (fun _ ch acc ->
       match acc with
       | Some _ -> acc
       | None -> if ch.label = label then Some ch else None)
    t.channels
    None
;;

(** List all open channels *)
let list_channels t =
  Hashtbl.fold (fun _ ch acc -> if ch.state = Open then ch :: acc else acc) t.channels []
;;

(** {1 PPID Selection} *)

(** Get appropriate PPID for data based on channel type and data
    RFC 8831 §8: PPID values for WebRTC *)
let ppid_for_data ~is_string _channel =
  let base_ppid =
    if is_string then 51l (* WebRTC String *) else 53l (* WebRTC Binary *)
  in
  (* Could add empty string/binary handling here *)
  base_ppid
;;

(** {1 Statistics} *)

type stats =
  { channels_opened : int
  ; channels_closed : int
  ; active_channels : int
  }

let get_stats t =
  let active =
    Hashtbl.fold
      (fun _ ch count -> if ch.state = Open then count + 1 else count)
      t.channels
      0
  in
  { channels_opened = Hashtbl.length t.channels
  ; channels_closed = Hashtbl.length t.channels - active
  ; active_channels = active
  }
;;

(** {1 Debug} *)

let string_of_channel_type = function
  | Reliable -> "Reliable"
  | ReliableUnordered -> "ReliableUnordered"
  | PartialReliableRexmit n -> Printf.sprintf "PartialReliableRexmit(%d)" n
  | PartialReliableRexmitUnordered n ->
    Printf.sprintf "PartialReliableRexmitUnordered(%d)" n
  | PartialReliableTimed n -> Printf.sprintf "PartialReliableTimed(%dms)" n
  | PartialReliableTimedUnordered n ->
    Printf.sprintf "PartialReliableTimedUnordered(%dms)" n
;;

let string_of_state = function
  | Opening -> "Opening"
  | Open -> "Open"
  | Closing -> "Closing"
  | Closed -> "Closed"
;;

let pp_channel ch =
  Printf.sprintf
    "Channel[%d]: %s (%s) state=%s priority=%d"
    ch.id
    ch.label
    (string_of_channel_type ch.channel_type)
    (string_of_state ch.state)
    ch.priority
;;
