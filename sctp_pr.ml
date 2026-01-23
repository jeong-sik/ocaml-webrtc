(** PR-SCTP - Partial Reliability Extension

    Implements RFC 3758: SCTP Partial Reliability Extension.

    Partial Reliability allows senders to abandon messages that:
    - Exceed a time limit (timed reliability)
    - Exceed a retransmission limit
    - Are explicitly abandoned by the application

    Use cases:
    - Real-time media: Old video frames are useless
    - Gaming: Position updates supercede old ones
    - Live telemetry: Stale sensor data is worthless

    WebRTC DataChannel uses PR-SCTP with "maxRetransmits" and "maxPacketLifeTime".

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** {1 Reliability Policy} *)

(** PR-SCTP reliability policy for a message *)
type policy =
  | Reliable (** Standard SCTP - retransmit until delivered *)
  | TimedReliability of { max_lifetime_ms : int }
  (** Abandon if not delivered within max_lifetime_ms *)
  | LimitedRetransmit of { max_rtx : int } (** Abandon after max_rtx retransmissions *)

(** {1 Forward TSN Chunk (RFC 3758 §3.2)} *)

(** Stream sequence entry for Forward TSN *)
type stream_seq =
  { stream_id : int
  ; stream_seq : int (** Next expected SSN on this stream *)
  }

(** Forward TSN chunk - notifies receiver to skip abandoned TSNs *)
type forward_tsn =
  { new_cumulative_tsn : int32 (** New cumulative TSN ack point *)
  ; stream_seqs : stream_seq list (** Per-stream SSN updates *)
  }

(** {1 Message State} *)

(** State of a PR-SCTP message *)
type message_state =
  | Pending (** Queued, not yet sent *)
  | InFlight (** Sent, awaiting ACK *)
  | Abandoned (** Abandoned per policy *)
  | Delivered (** ACKed by receiver *)

(** PR-SCTP message with policy tracking *)
type message =
  { tsn : int32
  ; stream_id : int
  ; stream_seq : int
  ; policy : policy
  ; send_time : float
  ; mutable rtx_count : int
  ; mutable state : message_state
  }

(** {1 PR-SCTP State} *)

type t =
  { mutable messages : message list (** Active messages *)
  ; mutable abandoned_tsns : int32 list (** TSNs abandoned since last Forward-TSN *)
  ; mutable forward_tsn_sent : int32 (** Last Forward-TSN sent *)
  }

let create () = { messages = []; abandoned_tsns = []; forward_tsn_sent = 0l }

(** {1 Message Tracking} *)

(** Register a new message with policy *)
let track_message t ~tsn ~stream_id ~stream_seq ~policy =
  let msg =
    { tsn
    ; stream_id
    ; stream_seq
    ; policy
    ; send_time = Unix.gettimeofday ()
    ; rtx_count = 0
    ; state = Pending
    }
  in
  t.messages <- msg :: t.messages
;;

(** Mark message as sent (in-flight) *)
let mark_sent t ~tsn =
  t.messages
  <- List.map
       (fun m ->
          if m.tsn = tsn && m.state = Pending then { m with state = InFlight } else m)
       t.messages
;;

(** Mark message as delivered (ACKed) *)
let mark_delivered t ~tsn = t.messages <- List.filter (fun m -> m.tsn <> tsn) t.messages

(** Increment retransmission count *)
let record_retransmit t ~tsn =
  t.messages
  <- List.map
       (fun m -> if m.tsn = tsn then { m with rtx_count = m.rtx_count + 1 } else m)
       t.messages
;;

(** {1 Policy Enforcement} *)

(** Check if a message should be abandoned based on its policy *)
let should_abandon msg =
  match msg.policy with
  | Reliable -> false
  | TimedReliability { max_lifetime_ms } ->
    let elapsed_ms = (Unix.gettimeofday () -. msg.send_time) *. 1000.0 in
    elapsed_ms > float_of_int max_lifetime_ms
  | LimitedRetransmit { max_rtx } -> msg.rtx_count >= max_rtx
;;

(** Check and abandon messages that exceeded their policy.
    Returns list of newly abandoned TSNs. *)
let check_abandonments t =
  let newly_abandoned = ref [] in
  t.messages
  <- List.map
       (fun m ->
          if m.state = InFlight && should_abandon m
          then (
            newly_abandoned := m.tsn :: !newly_abandoned;
            { m with state = Abandoned })
          else m)
       t.messages;
  (* Track abandoned TSNs for Forward-TSN *)
  t.abandoned_tsns <- !newly_abandoned @ t.abandoned_tsns;
  !newly_abandoned
;;

(** {1 Forward-TSN Generation} *)

(** Generate Forward-TSN chunk if there are abandoned messages.
    RFC 3758 §3.5: Send when there are gaps due to abandonments. *)
let generate_forward_tsn t ~current_cumulative_tsn =
  if t.abandoned_tsns = []
  then None
  else (
    (* Find the highest TSN we can advance to *)
    let abandoned_sorted = List.sort Int32.compare t.abandoned_tsns in
    let new_cum_tsn =
      List.fold_left
        (fun acc tsn -> if Int32.succ acc = tsn then tsn else acc)
        current_cumulative_tsn
        abandoned_sorted
    in
    (* Get stream sequences for abandoned messages *)
    let stream_seqs =
      List.filter_map
        (fun m ->
           if m.state = Abandoned && m.tsn <= new_cum_tsn
           then Some { stream_id = m.stream_id; stream_seq = m.stream_seq + 1 }
           else None)
        t.messages
    in
    (* Remove processed abandonments *)
    t.abandoned_tsns <- List.filter (fun tsn -> tsn > new_cum_tsn) t.abandoned_tsns;
    t.forward_tsn_sent <- new_cum_tsn;
    (* Clean up delivered/abandoned messages *)
    t.messages
    <- List.filter (fun m -> m.state <> Abandoned || m.tsn > new_cum_tsn) t.messages;
    Some { new_cumulative_tsn = new_cum_tsn; stream_seqs })
;;

(** {1 Forward-TSN Encoding (RFC 3758 §3.2)} *)

let chunk_type_forward_tsn = 192 (* 0xC0 *)

(** Encode Forward-TSN chunk *)
let encode_forward_tsn ftsn =
  (* Chunk header: type(1) + flags(1) + length(2) + new_cum_tsn(4) + stream_seqs *)
  let stream_seq_len = List.length ftsn.stream_seqs * 4 in
  let total_len = 8 + stream_seq_len in
  let buf = Bytes.create total_len in
  (* Chunk header *)
  Bytes.set buf 0 (Char.chr chunk_type_forward_tsn);
  Bytes.set buf 1 (Char.chr 0);
  (* flags *)
  Bytes.set_uint16_be buf 2 total_len;
  (* New cumulative TSN *)
  Bytes.set_int32_be buf 4 ftsn.new_cumulative_tsn;
  (* Stream sequences *)
  List.iteri
    (fun i (ss : stream_seq) ->
       let off = 8 + (i * 4) in
       Bytes.set_uint16_be buf off ss.stream_id;
       Bytes.set_uint16_be buf (off + 2) ss.stream_seq)
    ftsn.stream_seqs;
  buf
;;

(** Decode Forward-TSN chunk *)
let decode_forward_tsn buf =
  if Bytes.length buf < 8
  then Error "Forward-TSN too short"
  else (
    let chunk_type = Bytes.get buf 0 |> Char.code in
    if chunk_type <> chunk_type_forward_tsn
    then Error (Printf.sprintf "Not Forward-TSN chunk: %d" chunk_type)
    else (
      let len = Bytes.get_uint16_be buf 2 in
      let new_cumulative_tsn = Bytes.get_int32_be buf 4 in
      (* Parse stream sequences *)
      let num_streams = (len - 8) / 4 in
      let stream_seqs =
        List.init num_streams (fun i ->
          let off = 8 + (i * 4) in
          { stream_id = Bytes.get_uint16_be buf off
          ; stream_seq = Bytes.get_uint16_be buf (off + 2)
          })
      in
      Ok { new_cumulative_tsn; stream_seqs }))
;;

(** {1 Receiver Processing} *)

(** Process received Forward-TSN.
    Returns new cumulative TSN for receiver state. *)
let process_forward_tsn ~recv_cumulative_tsn ftsn =
  (* Advance cumulative TSN if Forward-TSN is higher *)
  if ftsn.new_cumulative_tsn > recv_cumulative_tsn
  then ftsn.new_cumulative_tsn
  else recv_cumulative_tsn
;;

(** {1 Statistics} *)

type stats =
  { messages_tracked : int
  ; messages_abandoned : int
  ; forward_tsns_sent : int
  }

let get_stats t =
  let abandoned = List.length (List.filter (fun m -> m.state = Abandoned) t.messages) in
  { messages_tracked = List.length t.messages
  ; messages_abandoned = abandoned
  ; forward_tsns_sent = Int32.to_int t.forward_tsn_sent
  }
;;

(** {1 Debug} *)

let string_of_policy = function
  | Reliable -> "Reliable"
  | TimedReliability { max_lifetime_ms } ->
    Printf.sprintf "TimedReliability(%dms)" max_lifetime_ms
  | LimitedRetransmit { max_rtx } -> Printf.sprintf "LimitedRetransmit(%d)" max_rtx
;;

let string_of_state = function
  | Pending -> "Pending"
  | InFlight -> "InFlight"
  | Abandoned -> "Abandoned"
  | Delivered -> "Delivered"
;;
