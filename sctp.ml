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
  | DATA (** Payload data *)
  | INIT (** Initiate association *)
  | INIT_ACK (** Acknowledge INIT *)
  | SACK (** Selective acknowledgment *)
  | HEARTBEAT (** Heartbeat request *)
  | HEARTBEAT_ACK (** Heartbeat acknowledgment *)
  | ABORT (** Abort association *)
  | SHUTDOWN (** Shutdown association *)
  | SHUTDOWN_ACK (** Acknowledge shutdown *)
  | ERROR (** Error indication *)
  | COOKIE_ECHO (** State cookie *)
  | COOKIE_ACK (** Cookie acknowledgment *)
  | SHUTDOWN_COMPLETE
  | FORWARD_TSN (** RFC 3758 - Partial reliability *)
  | RE_CONFIG (** RFC 6525 - Stream reconfiguration *)
  | Unknown of int
[@@deriving show, eq]

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
[@@deriving show, eq]

(** WebRTC Data Channel PPID message types - RFC 8831 *)
type message_type =
  | WebRTC_DCEP (** 50 - Data Channel Establishment Protocol *)
  | WebRTC_String (** 51 - UTF-8 string *)
  | WebRTC_Binary (** 53 - Binary data *)
  | WebRTC_String_Empty (** 56 - Empty string *)
  | WebRTC_Binary_Empty (** 57 - Empty binary *)
[@@deriving show, eq]

(** Data chunk flags *)
type data_flags =
  { end_fragment : bool (** E bit - last fragment *)
  ; begin_fragment : bool (** B bit - first fragment *)
  ; unordered : bool (** U bit - unordered delivery *)
  ; immediate : bool (** I bit - immediate transmission *)
  }

(** DATA chunk structure *)
type data_chunk =
  { flags : data_flags
  ; tsn : int32 (** Transmission Sequence Number *)
  ; stream_id : int (** Stream identifier *)
  ; stream_seq : int (** Stream sequence number *)
  ; ppid : int32 (** Payload Protocol Identifier *)
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
  ; mtu : int (** Maximum Transmission Unit *)
  ; max_retransmits : int (** Max retransmission attempts *)
  ; rto_initial_ms : int (** Initial RTO *)
  ; rto_min_ms : int
  ; rto_max_ms : int
  ; a_rwnd : int (** Advertised Receiver Window Credit *)
  ; num_outbound_streams : int
  ; num_inbound_streams : int
  ; skip_checksum_validation : bool
    (** TESTING ONLY: Skip CRC32c validation.
                                       NEVER enable in production! *)
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
  ; mutable cwnd : int (** Congestion window *)
  ; mutable ssthresh : int (** Slow start threshold *)
  }

(** {1 Default Configuration} *)

(** Performance-optimized configuration for high throughput *)
let default_config =
  { local_port = 5000
  ; remote_port = 5000
  ; (* Increased MTU for better throughput - WebRTC typically uses 1280 *)
    mtu = 1280
  ; max_retransmits = 10
  ; (* Reduced RTO for faster retransmission (RFC 6298 recommends 1s) *)
    rto_initial_ms = 1000
  ; rto_min_ms = 200
  ; (* More aggressive min RTO *)
    rto_max_ms = 60000
  ; (* Larger receive window for high bandwidth-delay product *)
    a_rwnd = 262144
  ; (* 256KB - enables better pipelining *)
    num_outbound_streams = 65535
  ; num_inbound_streams = 65535
  ; skip_checksum_validation = false (* NEVER enable in production *)
  }
;;

(** {1 String Conversions} *)

let string_of_chunk_type = function
  | DATA -> "DATA"
  | INIT -> "INIT"
  | INIT_ACK -> "INIT_ACK"
  | SACK -> "SACK"
  | HEARTBEAT -> "HEARTBEAT"
  | HEARTBEAT_ACK -> "HEARTBEAT_ACK"
  | ABORT -> "ABORT"
  | SHUTDOWN -> "SHUTDOWN"
  | SHUTDOWN_ACK -> "SHUTDOWN_ACK"
  | ERROR -> "ERROR"
  | COOKIE_ECHO -> "COOKIE_ECHO"
  | COOKIE_ACK -> "COOKIE_ACK"
  | SHUTDOWN_COMPLETE -> "SHUTDOWN_COMPLETE"
  | FORWARD_TSN -> "FORWARD_TSN"
  | RE_CONFIG -> "RE_CONFIG"
  | Unknown n -> Printf.sprintf "Unknown(%d)" n
;;

let chunk_type_of_int = function
  | 0 -> DATA
  | 1 -> INIT
  | 2 -> INIT_ACK
  | 3 -> SACK
  | 4 -> HEARTBEAT
  | 5 -> HEARTBEAT_ACK
  | 6 -> ABORT
  | 7 -> SHUTDOWN
  | 8 -> SHUTDOWN_ACK
  | 9 -> ERROR
  | 10 -> COOKIE_ECHO
  | 11 -> COOKIE_ACK
  | 14 -> SHUTDOWN_COMPLETE
  | 192 -> FORWARD_TSN
  | 130 -> RE_CONFIG
  | n -> Unknown n
;;

let int_of_chunk_type = function
  | DATA -> 0
  | INIT -> 1
  | INIT_ACK -> 2
  | SACK -> 3
  | HEARTBEAT -> 4
  | HEARTBEAT_ACK -> 5
  | ABORT -> 6
  | SHUTDOWN -> 7
  | SHUTDOWN_ACK -> 8
  | ERROR -> 9
  | COOKIE_ECHO -> 10
  | COOKIE_ACK -> 11
  | SHUTDOWN_COMPLETE -> 14
  | FORWARD_TSN -> 192
  | RE_CONFIG -> 130
  | Unknown n -> n
;;

let string_of_state = function
  | Closed -> "closed"
  | Cookie_wait -> "cookie-wait"
  | Cookie_echoed -> "cookie-echoed"
  | Established -> "established"
  | Shutdown_pending -> "shutdown-pending"
  | Shutdown_sent -> "shutdown-sent"
  | Shutdown_received -> "shutdown-received"
  | Shutdown_ack_sent -> "shutdown-ack-sent"
;;

let string_of_message_type = function
  | WebRTC_DCEP -> "DCEP"
  | WebRTC_String -> "String"
  | WebRTC_Binary -> "Binary"
  | WebRTC_String_Empty -> "String_Empty"
  | WebRTC_Binary_Empty -> "Binary_Empty"
;;

(** {1 PPID Conversions - RFC 8831} *)

let ppid_of_message_type = function
  | WebRTC_DCEP -> 50l
  | WebRTC_String -> 51l
  | WebRTC_Binary -> 53l
  | WebRTC_String_Empty -> 56l
  | WebRTC_Binary_Empty -> 57l
;;

let message_type_of_ppid = function
  | 50l -> Some WebRTC_DCEP
  | 51l -> Some WebRTC_String
  | 53l -> Some WebRTC_Binary
  | 56l -> Some WebRTC_String_Empty
  | 57l -> Some WebRTC_Binary_Empty
  | _ -> None
;;

(** {1 Association Management} *)

(** Create new SCTP association *)
let create config =
  Random.self_init ();
  { state = Closed
  ; streams = Hashtbl.create 16
  ; config
  ; my_vtag = Random.int32 Int32.max_int
  ; peer_vtag = 0l
  ; next_tsn = Random.int32 Int32.max_int
  ; last_rcvd_tsn = 0l
  ; (* IW10 - RFC 6928 Initial Window = 10 * MTU for faster ramp-up *)
    cwnd = config.mtu * 10
  ; ssthresh = config.a_rwnd
  }
;;

(** Get association state *)
let get_state assoc = assoc.state

(** Check if association is established *)
let is_established assoc = assoc.state = Established

(** Get association info as JSON *)
let association_info assoc =
  `Assoc
    [ "state", `String (string_of_state assoc.state)
    ; "streams", `Int (Hashtbl.length assoc.streams)
    ; "myVtag", `String (Int32.to_string assoc.my_vtag)
    ; "peerVtag", `String (Int32.to_string assoc.peer_vtag)
    ; "nextTsn", `String (Int32.to_string assoc.next_tsn)
    ; "cwnd", `Int assoc.cwnd
    ; "ssthresh", `Int assoc.ssthresh
    ]
;;

(** {1 Stream Management} *)

(** Open a stream *)
let open_stream assoc stream_id ?(ordered = true) () =
  let stream = { id = stream_id; ordered; next_ssn = 0; next_tsn = assoc.next_tsn } in
  Hashtbl.replace assoc.streams stream_id stream;
  stream
;;

(** Get stream by ID *)
let get_stream assoc stream_id = Hashtbl.find_opt assoc.streams stream_id

(** Close a stream *)
let close_stream assoc stream_id = Hashtbl.remove assoc.streams stream_id

(** Get all streams *)
let get_streams assoc = Hashtbl.fold (fun _ stream acc -> stream :: acc) assoc.streams []

(** {1 Encoding/Decoding} *)

(* Use shared helpers from Webrtc_common *)
let write_uint16_be = Webrtc_common.write_uint16_be
let write_uint32_be = Webrtc_common.write_uint32_be
let read_uint16_be = Webrtc_common.read_uint16_be
let read_uint32_be = Webrtc_common.read_uint32_be
let crc32c = Webrtc_common.crc32c

(** Encode DATA chunk into existing buffer - zero-copy for hot path.
    @param buf Target buffer (must have space for padded_len bytes from off)
    @param off Offset in buffer to start writing
    @param dc Data chunk to encode
    @return Number of bytes written (padded length) *)
let encode_data_chunk_into ~buf ~off dc =
  let data_len = Bytes.length dc.user_data in
  let chunk_len = 16 + data_len in
  let padded_len = (chunk_len + 3) land lnot 3 in
  (* Chunk header *)
  Bytes.set_uint8 buf off (int_of_chunk_type DATA);
  let flags =
    (if dc.flags.end_fragment then 0x01 else 0)
    lor (if dc.flags.begin_fragment then 0x02 else 0)
    lor (if dc.flags.unordered then 0x04 else 0)
    lor if dc.flags.immediate then 0x08 else 0
  in
  Bytes.set_uint8 buf (off + 1) flags;
  write_uint16_be buf (off + 2) chunk_len;
  (* DATA chunk specific *)
  write_uint32_be buf (off + 4) dc.tsn;
  write_uint16_be buf (off + 8) dc.stream_id;
  write_uint16_be buf (off + 10) dc.stream_seq;
  write_uint32_be buf (off + 12) dc.ppid;
  (* User data *)
  Bytes.blit dc.user_data 0 buf (off + 16) data_len;
  padded_len
;;

(** Encode DATA chunk - allocates new buffer (backwards compatible) *)
let encode_data_chunk dc =
  let data_len = Bytes.length dc.user_data in
  let chunk_len = 16 + data_len in
  let padded_len = (chunk_len + 3) land lnot 3 in
  let buf = Bytes.create padded_len in
  ignore (encode_data_chunk_into ~buf ~off:0 dc);
  buf
;;

(** {1 Performance Optimization - Batch Encoding} *)

(** Encode multiple DATA chunks into a single SCTP packet for reduced overhead.
    This significantly improves throughput by reducing per-packet overhead.
    @param chunks List of data chunks to bundle
    @param mtu Maximum transmission unit (limits total packet size)
    @return List of encoded packets (may be multiple if chunks exceed MTU) *)
let encode_data_chunks_batch chunks ~mtu =
  let rec bundle acc current_buf current_len = function
    | [] ->
      if current_len > 0
      then List.rev (Bytes.sub current_buf 0 current_len :: acc)
      else List.rev acc
    | dc :: rest ->
      let encoded = encode_data_chunk dc in
      let encoded_len = Bytes.length encoded in
      if current_len + encoded_len <= mtu
      then (
        (* Fits in current packet - append *)
        Bytes.blit encoded 0 current_buf current_len encoded_len;
        bundle acc current_buf (current_len + encoded_len) rest)
      else if current_len > 0
      then (
        (* Start new packet *)
        let packet = Bytes.sub current_buf 0 current_len in
        let new_buf = Bytes.create mtu in
        Bytes.blit encoded 0 new_buf 0 encoded_len;
        bundle (packet :: acc) new_buf encoded_len rest)
      else
        (* Single chunk exceeds MTU - send as is *)
        bundle (encoded :: acc) current_buf 0 rest
  in
  match chunks with
  | [] -> []
  | _ ->
    let buf = Bytes.create mtu in
    bundle [] buf 0 chunks
;;

(** Fragment large user data into MTU-sized DATA chunks.
    @param data User data to fragment
    @param stream_id Stream identifier
    @param ppid Payload Protocol Identifier
    @param start_tsn Starting TSN for fragments
    @param mtu Maximum chunk data size (MTU - 16 for DATA header)
    @return List of data chunks representing the fragmented message *)
let fragment_data ~data ~stream_id ~stream_seq ~ppid ~start_tsn ~mtu =
  let max_data_per_chunk = mtu - 16 in
  (* 16 = DATA chunk header *)
  let data_len = Bytes.length data in
  if data_len <= max_data_per_chunk
  then
    (* No fragmentation needed *)
    [ { tsn = start_tsn
      ; stream_id
      ; stream_seq
      ; ppid
      ; user_data = data
      ; flags =
          { begin_fragment = true
          ; end_fragment = true
          ; unordered = false
          ; immediate = false
          }
      }
    ]
  else (
    (* Fragment the data *)
    let num_fragments = (data_len + max_data_per_chunk - 1) / max_data_per_chunk in
    let rec make_fragments acc idx tsn offset =
      if idx >= num_fragments
      then List.rev acc
      else (
        let is_first = idx = 0 in
        let is_last = idx = num_fragments - 1 in
        let chunk_data_len = min max_data_per_chunk (data_len - offset) in
        let chunk_data = Bytes.sub data offset chunk_data_len in
        let fragment =
          { tsn
          ; stream_id
          ; stream_seq
          ; ppid
          ; user_data = chunk_data
          ; flags =
              { begin_fragment = is_first
              ; end_fragment = is_last
              ; unordered = false
              ; immediate = is_last (* Set I-bit on last fragment for faster delivery *)
              }
          }
        in
        make_fragments
          (fragment :: acc)
          (idx + 1)
          (Int32.succ tsn)
          (offset + chunk_data_len))
    in
    make_fragments [] 0 start_tsn 0)
;;

(** Decode DATA chunk from a view (buffer, offset, length) - zero-copy header parsing *)
let decode_data_chunk_view buf ~off ~len =
  if len < 16
  then Error "DATA chunk too short"
  else (
    let chunk_type = Bytes.get_uint8 buf off in
    if chunk_type <> 0
    then Error (Printf.sprintf "Not a DATA chunk (type=%d)" chunk_type)
    else (
      let flags_byte = Bytes.get_uint8 buf (off + 1) in
      let chunk_len = read_uint16_be buf (off + 2) in
      let tsn = read_uint32_be buf (off + 4) in
      let stream_id = read_uint16_be buf (off + 8) in
      let stream_seq = read_uint16_be buf (off + 10) in
      let ppid = read_uint32_be buf (off + 12) in
      let data_len = chunk_len - 16 in
      (* This copy IS necessary - app needs to own the data *)
      let user_data = Bytes.sub buf (off + 16) data_len in
      Ok
        { flags =
            { end_fragment = flags_byte land 0x01 <> 0
            ; begin_fragment = flags_byte land 0x02 <> 0
            ; unordered = flags_byte land 0x04 <> 0
            ; immediate = flags_byte land 0x08 <> 0
            }
        ; tsn
        ; stream_id
        ; stream_seq
        ; ppid
        ; user_data
        }))
;;

(** Decode DATA chunk - wrapper for backwards compatibility *)
let decode_data_chunk buf = decode_data_chunk_view buf ~off:0 ~len:(Bytes.length buf)

(** CRC32-C calculation for SCTP checksum - RFC 4960 Appendix B *)
let calculate_checksum = crc32c

(** Encode SCTP packet *)
let encode_packet packet =
  (* Calculate total chunk data size *)
  let chunks_size =
    List.fold_left (fun acc c -> acc + 4 + Bytes.length c.chunk_value) 0 packet.chunks
  in
  (* SCTP header is 12 bytes *)
  let buf = Bytes.create (12 + chunks_size) in
  (* Header *)
  write_uint16_be buf 0 packet.header.source_port;
  write_uint16_be buf 2 packet.header.dest_port;
  write_uint32_be buf 4 packet.header.verification_tag;
  (* Checksum placeholder - will be computed over whole packet *)
  write_uint32_be buf 8 0l;
  (* Chunks *)
  let offset = ref 12 in
  List.iter
    (fun chunk ->
       Bytes.set_uint8 buf !offset chunk.chunk_type;
       Bytes.set_uint8 buf (!offset + 1) chunk.chunk_flags;
       write_uint16_be buf (!offset + 2) (4 + Bytes.length chunk.chunk_value);
       Bytes.blit chunk.chunk_value 0 buf (!offset + 4) (Bytes.length chunk.chunk_value);
       offset := !offset + 4 + Bytes.length chunk.chunk_value)
    packet.chunks;
  (* Calculate and insert checksum *)
  let checksum = calculate_checksum buf in
  write_uint32_be buf 8 checksum;
  buf
;;

(** Decode SCTP packet *)
let decode_packet buf =
  if Bytes.length buf < 12
  then Error "Packet too short for SCTP header"
  else (
    let source_port = read_uint16_be buf 0 in
    let dest_port = read_uint16_be buf 2 in
    let verification_tag = read_uint32_be buf 4 in
    let checksum = read_uint32_be buf 8 in
    (* Parse chunks *)
    let chunks = ref [] in
    let offset = ref 12 in
    while !offset + 4 <= Bytes.length buf do
      let chunk_type = Bytes.get_uint8 buf !offset in
      let chunk_flags = Bytes.get_uint8 buf (!offset + 1) in
      let chunk_length = read_uint16_be buf (!offset + 2) in
      let value_len = chunk_length - 4 in
      if !offset + chunk_length <= Bytes.length buf && value_len >= 0
      then (
        let chunk_value = Bytes.sub buf (!offset + 4) value_len in
        chunks := { chunk_type; chunk_flags; chunk_length; chunk_value } :: !chunks;
        (* Round up to 4-byte boundary *)
        offset := !offset + ((chunk_length + 3) land lnot 3))
      else offset := Bytes.length buf (* Stop parsing *)
    done;
    Ok
      { header = { source_port; dest_port; verification_tag; checksum }
      ; chunks = List.rev !chunks
      })
;;

(** Check if data looks like SCTP *)
let is_sctp_data buf = Bytes.length buf >= 12 (* Minimum SCTP header size *)

(** {1 State Machine} *)

(** Set association state *)
let set_state assoc new_state = assoc.state <- new_state

(** Establish association (for testing) *)
let establish assoc = assoc.state <- Established

(** Begin shutdown *)
let begin_shutdown assoc =
  if assoc.state = Established then assoc.state <- Shutdown_pending
;;

(** {1 Pretty Printing} *)

let pp_data_chunk fmt dc =
  Format.fprintf
    fmt
    "DATA(tsn=%ld, sid=%d, ssn=%d, ppid=%ld, len=%d)"
    dc.tsn
    dc.stream_id
    dc.stream_seq
    dc.ppid
    (Bytes.length dc.user_data)
;;

let pp_stream fmt s =
  Format.fprintf fmt "Stream(id=%d, ordered=%b, ssn=%d)" s.id s.ordered s.next_ssn
;;

let pp_association fmt a =
  Format.fprintf
    fmt
    "Association(state=%s, streams=%d, vtag=%ld)"
    (string_of_state a.state)
    (Hashtbl.length a.streams)
    a.my_vtag
;;
