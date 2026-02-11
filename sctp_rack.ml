(** RACK - Recent ACKnowledgment Algorithm (RFC 8985)
 *
 * Time-based loss detection that outperforms traditional "3 duplicate SACKs".
 * Key insight: If a later packet was ACKed, earlier unacked packets are likely lost.
 *
 * Performance: Pion (Go) achieves +71% faster loss detection with RACK.
 *
 * Algorithm:
 * {v
 *   For each ACKed packet:
 *     update rack.xmit_ts[tsn] = most_recent_ack_time
 *     for each unacked packet with tsn < acked_tsn:
 *       if (now - sent_time > rtt_min + reorder_window):
 *         mark as lost → trigger retransmit
 * v}
 *
 * @author Second Brain
 * @see RFC 8985: The RACK-TLP Loss Detection Algorithm
 *)

(** {1 Types} *)

(** Per-packet transmission info *)
type xmit_info =
  { tsn : int32 (** TSN of the packet *)
  ; mutable sent_at : float (** Timestamp when sent (mutable for RTX) *)
  ; size : int (** Packet size for cwnd accounting *)
  ; mutable retx_count : int (** Retransmission count *)
  }

(** RACK state *)
type t =
  { mutable rtt_min : float (** Minimum observed RTT (seconds) *)
  ; mutable rtt_smoothed : float (** Smoothed RTT (SRTT) *)
  ; mutable reorder_window : float (** Dynamic reordering tolerance *)
  ; mutable most_recent_ack_time : float (** Time of most recent ACK *)
  ; mutable most_recent_ack_tsn : int32 (** TSN of most recent ACK *)
  ; xmit_records : (int32, xmit_info) Hashtbl.t (** TSN → transmission info *)
  ; (* Tail Loss Probe (TLP) state *)
    mutable tlp_out : bool (** TLP probe outstanding *)
  ; mutable tlp_high_seq : int32 (** Highest TSN at TLP send time *)
  }
[@@warning "-69"]

(** {1 Constants} *)

(** Minimum reorder window (RFC 8985 §3.4) *)
let min_reorder_window = 0.001 (* 1ms *)

(** Reorder window fraction of RTT (RFC 8985 §3.4) *)
let reorder_window_frac = 0.25 (* 1/4 RTT *)

(** Maximum reorder window (RFC 8985 §3.4) *)
let max_reorder_window = 0.2 (* 200ms *)

(** TLP timeout multiplier (RFC 8985 §7.2) *)
let tlp_timeout_mult = 2.0

(** {1 Creation} *)

let create () =
  { rtt_min = Float.infinity
  ; rtt_smoothed = 0.2
  ; (* Initial guess: 200ms *)
    reorder_window = min_reorder_window
  ; most_recent_ack_time = 0.0
  ; most_recent_ack_tsn = 0l
  ; xmit_records = Hashtbl.create 1024
  ; tlp_out = false
  ; tlp_high_seq = 0l
  }
;;

(** {1 Packet Tracking} *)

(** Record packet transmission *)
let on_packet_sent t ~tsn ~size ~now =
  let info = { tsn; sent_at = now; size; retx_count = 0 } in
  Hashtbl.replace t.xmit_records tsn info
;;

(** Remove packet from tracking (ACKed or abandoned) *)
let on_packet_acked t ~tsn = Hashtbl.remove t.xmit_records tsn

(** {1 RTT Update} *)

(** Update RTT estimates on ACK (RFC 8985 §3.3) *)
let update_rtt t ~rtt_sample =
  (* Update min RTT *)
  if rtt_sample < t.rtt_min then t.rtt_min <- rtt_sample;
  (* Update smoothed RTT (Jacobson/Karels) *)
  if t.rtt_smoothed = 0.2
  then t.rtt_smoothed <- rtt_sample
  else t.rtt_smoothed <- (0.875 *. t.rtt_smoothed) +. (0.125 *. rtt_sample);
  (* Update reorder window: min(rtt/4, 200ms), at least 1ms *)
  t.reorder_window
  <- Float.max
       min_reorder_window
       (Float.min max_reorder_window (t.rtt_min *. reorder_window_frac))
;;

(** {1 RACK Loss Detection - Core Algorithm} *)

(** RACK loss detection on SACK received (RFC 8985 §3.4)

    @param now Current timestamp
    @param acked_tsns List of TSNs that were ACKed in this SACK
    @return List of TSNs detected as lost *)
let detect_loss t ~now ~acked_tsns =
  (* Update most recent ACK info *)
  List.iter
    (fun tsn ->
       match Hashtbl.find_opt t.xmit_records tsn with
       | Some info ->
         (* Calculate RTT sample for this packet *)
         let rtt_sample = now -. info.sent_at in
         if rtt_sample > 0.0 && info.retx_count = 0 then update_rtt t ~rtt_sample;
         (* Update most recent ACK tracking *)
         if Int32.compare tsn t.most_recent_ack_tsn > 0
         then (
           t.most_recent_ack_tsn <- tsn;
           t.most_recent_ack_time <- now);
         (* Remove from tracking *)
         on_packet_acked t ~tsn
       | None -> ())
    acked_tsns;
  (* RACK loss detection: scan unacked packets *)
  let loss_threshold = t.rtt_min +. t.reorder_window in
  let lost_tsns = ref [] in
  Hashtbl.iter
    (fun tsn info ->
       (* If packet was sent before most recent ACK's packet,
       and enough time has passed, mark as lost *)
       if Int32.compare tsn t.most_recent_ack_tsn < 0
       then (
         let time_since_sent = now -. info.sent_at in
         if time_since_sent > loss_threshold then lost_tsns := tsn :: !lost_tsns))
    t.xmit_records;
  (* Sort lost TSNs for ordered retransmission *)
  List.sort Int32.compare !lost_tsns
;;

(** {1 Tail Loss Probe (TLP) - RFC 8985 §7} *)

(** Calculate TLP timeout
    @return Delay in seconds before sending TLP *)
let tlp_timeout t =
  let base = Float.max t.rtt_smoothed t.rtt_min in
  tlp_timeout_mult *. base
;;

(** Should send TLP probe?
    @param now Current timestamp
    @param last_send Time of last packet sent
    @param in_flight Number of packets in flight
    @return true if TLP should be sent *)
let should_send_tlp t ~now ~last_send ~in_flight =
  in_flight > 0 && (not t.tlp_out) && now -. last_send > tlp_timeout t
;;

(** Record TLP probe sent *)
let on_tlp_sent t ~high_tsn =
  t.tlp_out <- true;
  t.tlp_high_seq <- high_tsn
;;

(** TLP probe ACKed - reset state *)
let on_tlp_acked t = t.tlp_out <- false

(** {1 Retransmission Tracking} *)

(** Mark packet as retransmitted *)
let on_packet_retransmitted t ~tsn ~now =
  match Hashtbl.find_opt t.xmit_records tsn with
  | Some info ->
    info.sent_at <- now;
    info.retx_count <- info.retx_count + 1
  | None -> ()
;;

(** {1 Statistics} *)

let get_rtt_min t = t.rtt_min
let get_rtt_smoothed t = t.rtt_smoothed
let get_reorder_window t = t.reorder_window
let get_in_flight_count t = Hashtbl.length t.xmit_records

let pp fmt t =
  Format.fprintf
    fmt
    "RACK{rtt_min=%.3fs, srtt=%.3fs, reorder=%.3fs, in_flight=%d}"
    t.rtt_min
    t.rtt_smoothed
    t.reorder_window
    (Hashtbl.length t.xmit_records)
;;

(** {1 Backward-Compatible API for sctp_reliable.ml} *)

(** Record packet send (alias for on_packet_sent) *)
let record_send t tsn = on_packet_sent t ~tsn ~size:1024 ~now:(Unix.gettimeofday ())

(** Process SACK and return (rtt_sample, lost TSNs) - RFC 8985 integration
    @param cumulative_tsn The cumulative TSN from SACK
    @param gap_blocks List of (start, end) gap blocks
    @return (rtt_sample option, lost_tsns list) *)
let process_sack t ~cumulative_tsn ~gap_blocks =
  let now = Unix.gettimeofday () in
  (* Build list of ACKed TSNs from cumulative + gaps *)
  let acked_tsns = ref [] in
  let rtt_sample = ref None in
  (* All TSNs up to and including cumulative_tsn are ACKed *)
  Hashtbl.iter
    (fun tsn info ->
       if Int32.compare tsn cumulative_tsn <= 0
       then (
         acked_tsns := tsn :: !acked_tsns;
         (* Calculate RTT sample from first ACKed packet *)
         if !rtt_sample = None && info.retx_count = 0
         then (
           let sample = now -. info.sent_at in
           if sample > 0.0 then rtt_sample := Some sample)))
    t.xmit_records;
  (* TSNs in gap blocks are also ACKed *)
  List.iter
    (fun (gap_start, gap_end) ->
       let start_tsn = Int32.add cumulative_tsn (Int32.of_int (gap_start + 1)) in
       let end_tsn = Int32.add cumulative_tsn (Int32.of_int (gap_end + 1)) in
       let rec add_range tsn =
         if Int32.compare tsn end_tsn <= 0
         then (
           acked_tsns := tsn :: !acked_tsns;
           add_range (Int32.succ tsn))
       in
       add_range start_tsn)
    gap_blocks;
  (* Run RACK loss detection *)
  let lost_tsns = detect_loss t ~now ~acked_tsns:!acked_tsns in
  (* Return (rtt_sample, lost_tsns) *)
  !rtt_sample, lost_tsns
;;
