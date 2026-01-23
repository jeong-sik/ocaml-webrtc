(** High-Performance Ring Buffer for SCTP

    Inspired by Jane Street's zero-allocation patterns:
    - Pre-allocated fixed-size array (no GC pressure)
    - Circular buffer for O(1) enqueue/dequeue
    - Avoids Hashtbl overhead for sequential TSN operations

    Reference: https://blog.janestreet.com/oxidizing-ocaml-locality/

    Performance target: Replace Hashtbl-based rtx_queue for
    ~10x throughput improvement.

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** {1 Ring Buffer Entry} *)

type entry_state =
  | Empty
  | InFlight of
      { chunk : Sctp.data_chunk
      ; mutable sent_at : float
      ; mutable retransmit_count : int
      ; mutable miss_indications : int
      ; mutable fast_retransmit : bool (** Marked for fast retransmit *)
      }
  | Acked

(** {1 Ring Buffer Type}

    Fixed-size circular buffer indexed by TSN.
    TSN wrapping is handled via modulo arithmetic.
*)

type t =
  { entries : entry_state array
  ; capacity : int
  ; mutable head_tsn : int32 (** Oldest unacked TSN *)
  ; mutable tail_tsn : int32 (** Next TSN to assign *)
  ; mutable count : int (** Number of in-flight entries *)
  ; mutable flight_bytes : int (** Total bytes in flight *)
  }

(** {1 Constants} *)

let default_capacity = 4096 (* Power of 2 for fast modulo *)

(** {1 Creation} *)

let create ?(capacity = default_capacity) ~initial_tsn () =
  { entries = Array.make capacity Empty
  ; capacity
  ; head_tsn = initial_tsn
  ; tail_tsn = initial_tsn
  ; count = 0
  ; flight_bytes = 0
  }
;;

(** {1 TSN to Index Mapping} *)

let[@inline] tsn_to_index t tsn =
  (* Fast modulo for power-of-2 capacity *)
  Int32.to_int tsn land (t.capacity - 1)
;;

(** {1 Operations} *)

let is_full t = t.count >= t.capacity
let is_empty t = t.count = 0
let flight_size t = t.flight_bytes

(** Enqueue a new data chunk for transmission.
    Returns the assigned TSN or None if buffer full.

    @param t The ring buffer
    @param chunk The data chunk to send
    @return Some(tsn) on success, None if full
*)
let enqueue t chunk =
  if is_full t
  then None
  else (
    let tsn = t.tail_tsn in
    let idx = tsn_to_index t tsn in
    let data_size = Bytes.length chunk.Sctp.user_data in
    let entry =
      InFlight
        { chunk = { chunk with tsn }
        ; sent_at = Unix.gettimeofday ()
        ; retransmit_count = 0
        ; miss_indications = 0
        ; fast_retransmit = false
        }
    in
    t.entries.(idx) <- entry;
    t.tail_tsn <- Int32.succ tsn;
    t.count <- t.count + 1;
    t.flight_bytes <- t.flight_bytes + data_size + 16;
    (* +16 for header *)
    Some tsn)
;;

(** Get the next TSN that would be assigned.
    Useful for external TSN allocation (e.g., fragmentation).

    @param t The ring buffer
    @return The next TSN to be assigned
*)
let next_tsn t = t.tail_tsn

(** Advance tail TSN without enqueuing (for external TSN allocation).
    Call this for each TSN you allocate externally.

    @param t The ring buffer
    @return The allocated TSN
*)
let alloc_tsn t =
  let tsn = t.tail_tsn in
  t.tail_tsn <- Int32.succ tsn;
  tsn
;;

(** Enqueue a chunk with pre-assigned TSN.
    For use with external TSN allocation (fragmentation).
    NOTE: Caller must ensure TSN is within valid window.

    @param t The ring buffer
    @param chunk The data chunk with TSN already set
    @return true on success, false if buffer full
*)
let enqueue_with_tsn t chunk =
  if is_full t
  then false
  else (
    let tsn = chunk.Sctp.tsn in
    let idx = tsn_to_index t tsn in
    let data_size = Bytes.length chunk.Sctp.user_data in
    let entry =
      InFlight
        { chunk
        ; (* Keep original TSN *)
          sent_at = Unix.gettimeofday ()
        ; retransmit_count = 0
        ; miss_indications = 0
        ; fast_retransmit = false
        }
    in
    t.entries.(idx) <- entry;
    t.count <- t.count + 1;
    t.flight_bytes <- t.flight_bytes + data_size + 16;
    true)
;;

(** Mark a TSN as acknowledged.
    Returns the number of bytes freed (for cwnd accounting).

    @param t The ring buffer
    @param tsn The TSN to acknowledge
    @return bytes freed, or 0 if not found/already acked
*)
let ack t tsn =
  let idx = tsn_to_index t tsn in
  match t.entries.(idx) with
  | InFlight entry when entry.chunk.tsn = tsn ->
    let data_size = Bytes.length entry.chunk.Sctp.user_data in
    let bytes_freed = data_size + 16 in
    t.entries.(idx) <- Acked;
    t.flight_bytes <- t.flight_bytes - bytes_freed;
    bytes_freed
  | _ -> 0
;;

(** Advance the head pointer, cleaning up acked entries.
    Call after processing SACKs to reclaim ring buffer space.

    @param t The ring buffer
    @return Number of entries cleaned up
*)
let advance_head t =
  let cleaned = ref 0 in
  while
    t.count > 0
    &&
    let idx = tsn_to_index t t.head_tsn in
    match t.entries.(idx) with
    | Acked ->
      t.entries.(idx) <- Empty;
      t.head_tsn <- Int32.succ t.head_tsn;
      t.count <- t.count - 1;
      incr cleaned;
      true
    | Empty ->
      (* Shouldn't happen, but handle gracefully *)
      t.head_tsn <- Int32.succ t.head_tsn;
      true
    | InFlight _ -> false
  do
    ()
  done;
  !cleaned
;;

(** Get entry for a TSN (for retransmission).

    @param t The ring buffer
    @param tsn The TSN to look up
    @return Some(chunk, retransmit_count) or None
*)
let get t tsn =
  let idx = tsn_to_index t tsn in
  match t.entries.(idx) with
  | InFlight entry when entry.chunk.tsn = tsn -> Some (entry.chunk, entry.retransmit_count)
  | _ -> None
;;

(** Mark a TSN for retransmission (increment counter, update sent_at).

    @param t The ring buffer
    @param tsn The TSN to mark
    @return true if marked, false if not found
*)
let mark_retransmit t tsn =
  let idx = tsn_to_index t tsn in
  match t.entries.(idx) with
  | InFlight entry when entry.chunk.tsn = tsn ->
    entry.retransmit_count <- entry.retransmit_count + 1;
    entry.sent_at <- Unix.gettimeofday ();
    true
  | _ -> false
;;

(** Increment miss indication counter for gap detection.

    @param t The ring buffer
    @param tsn The TSN to mark
    @return miss count after increment, or 0 if not found
*)
let incr_miss t tsn =
  let idx = tsn_to_index t tsn in
  match t.entries.(idx) with
  | InFlight entry when entry.chunk.tsn = tsn ->
    entry.miss_indications <- entry.miss_indications + 1;
    entry.miss_indications
  | _ -> 0
;;

(** Iterate over all in-flight entries.
    Useful for timeout checking.

    @param t The ring buffer
    @param f Function to call with (tsn, chunk, sent_at, retransmit_count)
*)
let iter_in_flight t f =
  let tsn = ref t.head_tsn in
  for _ = 0 to t.count - 1 do
    let idx = tsn_to_index t !tsn in
    (match t.entries.(idx) with
     | InFlight entry ->
       f entry.chunk.tsn entry.chunk entry.sent_at entry.retransmit_count
     | _ -> ());
    tsn := Int32.succ !tsn
  done
;;

(** Get all TSNs that need fast retransmit (miss_indications >= 3).

    @param t The ring buffer
    @return List of TSNs needing fast retransmit
*)
let get_fast_retransmit_candidates t =
  let candidates = ref [] in
  let tsn = ref t.head_tsn in
  for _ = 0 to t.count - 1 do
    let idx = tsn_to_index t !tsn in
    (match t.entries.(idx) with
     | InFlight entry when entry.miss_indications >= 3 ->
       candidates := entry.chunk.tsn :: !candidates
     | _ -> ());
    tsn := Int32.succ !tsn
  done;
  List.rev !candidates
;;

(** {1 SACK Processing Helpers} *)

(** Process cumulative TSN acknowledgment.
    Marks all TSNs <= cum_tsn as Acked.
    Returns (bytes_freed, rtt_sample option).
    RTT sample is from first transmission only (retransmit_count = 0).

    @param t The ring buffer
    @param cum_tsn Cumulative TSN from SACK
    @param now Current timestamp for RTT calculation
    @return (bytes_freed, Some rtt_sample) or (bytes_freed, None)
*)
let process_cumulative_ack t cum_tsn now =
  let bytes_freed = ref 0 in
  let rtt_sample = ref None in
  let tsn = ref t.head_tsn in
  (* Process all TSNs from head up to cum_tsn *)
  while Int32.compare !tsn cum_tsn <= 0 && Int32.compare !tsn t.tail_tsn < 0 do
    let idx = tsn_to_index t !tsn in
    (match t.entries.(idx) with
     | InFlight entry when entry.chunk.tsn = !tsn ->
       let data_size = Bytes.length entry.chunk.Sctp.user_data in
       bytes_freed := !bytes_freed + data_size + 16;
       (* RTT sample from first transmission only *)
       if entry.retransmit_count = 0 && !rtt_sample = None
       then rtt_sample := Some (now -. entry.sent_at);
       t.entries.(idx) <- Acked;
       t.flight_bytes <- t.flight_bytes - data_size - 16
     | _ -> ());
    tsn := Int32.succ !tsn
  done;
  !bytes_freed, !rtt_sample
;;

(** Check if a TSN is acknowledged (Acked state).

    @param t The ring buffer
    @param tsn The TSN to check
    @return true if TSN is in Acked state
*)
let is_acked t tsn =
  let idx = tsn_to_index t tsn in
  match t.entries.(idx) with
  | Acked -> true
  | InFlight entry when entry.chunk.tsn = tsn -> false
  | _ -> true (* Empty or wrong TSN = treat as acked *)
;;

(** Set fast_retransmit flag on an entry.

    @param t The ring buffer
    @param tsn The TSN to mark
    @return true if marked, false if not found
*)
let set_fast_retransmit t tsn =
  let idx = tsn_to_index t tsn in
  match t.entries.(idx) with
  | InFlight entry when entry.chunk.tsn = tsn ->
    entry.fast_retransmit <- true;
    true
  | _ -> false
;;

(** Iterate over unacked entries with TSN > base_tsn.
    Used for miss indication counting.
    Callback receives TSN and returns whether to set fast_retransmit.

    @param t The ring buffer
    @param base_tsn Only process TSNs greater than this
    @param f Function receives (tsn, miss_count) and returns true to mark fast_rtx
*)
let iter_unacked_above t base_tsn f =
  let tsn = ref t.head_tsn in
  for _ = 0 to t.count - 1 do
    let idx = tsn_to_index t !tsn in
    (match t.entries.(idx) with
     | InFlight entry when Int32.compare !tsn base_tsn > 0 ->
       entry.miss_indications <- entry.miss_indications + 1;
       if f !tsn entry.miss_indications then entry.fast_retransmit <- true
     | _ -> ());
    tsn := Int32.succ !tsn
  done
;;

(** Get entry info for gap block handling.
    Returns Some (is_acked, bytes) if entry exists.

    @param t The ring buffer
    @param tsn The TSN to look up
    @return Some (is_acked, data_bytes) or None
*)
let get_entry_info t tsn =
  let idx = tsn_to_index t tsn in
  match t.entries.(idx) with
  | InFlight entry when entry.chunk.tsn = tsn ->
    Some (false, Bytes.length entry.chunk.Sctp.user_data)
  | Acked -> Some (true, 0)
  | _ -> None
;;

(** {1 Retransmission Helpers} *)

(** Mark all in-flight entries for retransmission (timeout case).
    Increments retransmit_count and returns chunks to retransmit.

    @param t The ring buffer
    @return List of chunks to retransmit
*)
let mark_all_for_retransmit t =
  let chunks = ref [] in
  let tsn = ref t.head_tsn in
  for _ = 0 to t.count - 1 do
    let idx = tsn_to_index t !tsn in
    (match t.entries.(idx) with
     | InFlight entry ->
       entry.retransmit_count <- entry.retransmit_count + 1;
       entry.sent_at <- Unix.gettimeofday ();
       chunks := entry.chunk :: !chunks
     | _ -> ());
    tsn := Int32.succ !tsn
  done;
  List.rev !chunks
;;

(** Get and process entries marked for fast retransmit.
    Clears fast_retransmit flag, increments retransmit_count, updates sent_at.

    @param t The ring buffer
    @return List of chunks to fast retransmit
*)
let get_and_clear_fast_retransmit t =
  let chunks = ref [] in
  let tsn = ref t.head_tsn in
  for _ = 0 to t.count - 1 do
    let idx = tsn_to_index t !tsn in
    (match t.entries.(idx) with
     | InFlight entry when entry.fast_retransmit ->
       entry.fast_retransmit <- false;
       entry.retransmit_count <- entry.retransmit_count + 1;
       entry.sent_at <- Unix.gettimeofday ();
       chunks := entry.chunk :: !chunks
     | _ -> ());
    tsn := Int32.succ !tsn
  done;
  List.rev !chunks
;;

(** {1 Statistics} *)

let stats t =
  Printf.sprintf
    "RingBuffer{head=%ld, tail=%ld, count=%d/%d, flight=%d bytes}"
    t.head_tsn
    t.tail_tsn
    t.count
    t.capacity
    t.flight_bytes
;;
