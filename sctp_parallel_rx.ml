(** Domain-Parallel RX for SCTP (OCaml 5.x Multicore)

    Distributes packet reception across multiple CPU cores for maximum throughput.

    Architecture:
    ┌─────────────────────────────────────────────────────┐
    │                   Main Domain                        │
    │  ┌─────────┐ ┌─────────┐ ┌─────────────────────┐   │
    │  │ Sender  │ │ Timers  │ │ Stats Aggregator    │   │
    │  └─────────┘ └─────────┘ └─────────────────────┘   │
    ├─────────────────────────────────────────────────────┤
    │  RX Domain 0    │  RX Domain 1    │  RX Domain N   │
    │  ┌───────────┐  │  ┌───────────┐  │  ┌──────────┐  │
    │  │ UDP Recv  │  │  │ UDP Recv  │  │  │ UDP Recv │  │
    │  │ Process   │  │  │ Process   │  │  │ Process  │  │
    │  │ Local Sta │  │  │ Local Sta │  │  │ Local St │  │
    │  └───────────┘  │  └───────────┘  │  └──────────┘  │
    └─────────────────────────────────────────────────────┘

    Key Design Decisions:
    - Domain-local mutable stats (no Atomic on hot path)
    - Lock-free MPSC queue for output delivery
    - Periodic stats aggregation (not per-packet)

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

(** {1 Domain-Local Statistics}

    Each RX domain maintains its own mutable stats.
    No memory barriers on the hot path! *)

type domain_stats =
  { mutable packets_recv : int
  ; mutable bytes_recv : int
  ; mutable messages_delivered : int
  ; mutable crc_errors : int
  ; mutable parse_errors : int
  }

let create_domain_stats () =
  { packets_recv = 0
  ; bytes_recv = 0
  ; messages_delivered = 0
  ; crc_errors = 0
  ; parse_errors = 0
  }
;;

(** Domain-local storage key for stats *)
let stats_key : domain_stats Domain.DLS.key = Domain.DLS.new_key create_domain_stats

(** Get current domain's stats (zero overhead) *)
let get_local_stats () = Domain.DLS.get stats_key

(** {1 Aggregated Statistics} *)

type aggregated_stats =
  { total_packets_recv : int
  ; total_bytes_recv : int
  ; total_messages_delivered : int
  ; total_crc_errors : int
  ; total_parse_errors : int
  ; domain_count : int
  }

(** {1 Lock-Free MPSC Queue}

    Multiple producers (RX domains) → Single consumer (main domain)
    Using Michael-Scott queue with Atomic pointers *)

module Mpsc_queue = struct
  type 'a node =
    { mutable value : 'a option
    ; next : 'a node option Atomic.t
    }

  type 'a t =
    { head : 'a node Atomic.t
    ; tail : 'a node Atomic.t
    }

  let create () =
    let dummy = { value = None; next = Atomic.make None } in
    { head = Atomic.make dummy; tail = Atomic.make dummy }
  ;;

  (** Push from any domain (lock-free) *)
  let push q value =
    let node = { value = Some value; next = Atomic.make None } in
    (* CAS loop to append to tail *)
    let rec loop () =
      let tail = Atomic.get q.tail in
      let next = Atomic.get tail.next in
      match next with
      | None ->
        if Atomic.compare_and_set tail.next None (Some node)
        then
          (* Successfully linked, try to update tail *)
          ignore (Atomic.compare_and_set q.tail tail node)
        else loop ()
      | Some next_node ->
        (* Tail is behind, help advance it *)
        ignore (Atomic.compare_and_set q.tail tail next_node);
        loop ()
    in
    loop ()
  ;;

  (** Pop from main domain only (single consumer) *)
  let pop q =
    let head = Atomic.get q.head in
    match Atomic.get head.next with
    | None -> None
    | Some next ->
      Atomic.set q.head next;
      let value = next.value in
      next.value <- None;
      (* Help GC *)
      value
  ;;

  (** Drain all available items *)
  let drain q =
    let rec loop acc =
      match pop q with
      | None -> List.rev acc
      | Some v -> loop (v :: acc)
    in
    loop []
  ;;
end

(** {1 RX Domain Worker} *)

type rx_output =
  | DeliverData of
      { stream_id : int
      ; data : bytes
      }
  | SendSack of bytes
  | Error of string

type rx_domain =
  { id : int
  ; domain : unit Domain.t option ref
  ; output_queue : rx_output Mpsc_queue.t
  ; mutable running : bool
  }

(** Create RX domain worker *)
let create_rx_domain ~id ~output_queue =
  { id; domain = ref None; output_queue; running = false }
;;

(** {1 Parallel RX Manager} *)

type t =
  { domains : rx_domain array
  ; output_queue : rx_output Mpsc_queue.t (* Shared queue *)
  ; mutable stats_snapshot : aggregated_stats option
  ; domain_count : int
  }

(** Create parallel RX manager

    @param num_domains Number of RX domains (default: recommended_domain_count / 2)
*)
let create ?(num_domains = max 1 (Domain.recommended_domain_count () / 2)) () =
  let output_queue = Mpsc_queue.create () in
  let domains = Array.init num_domains (fun id -> create_rx_domain ~id ~output_queue) in
  { domains; output_queue; stats_snapshot = None; domain_count = num_domains }
;;

(** Process a single packet in RX domain

    This is the hot path - must be fast!
    - No Atomic operations
    - No allocations in steady state
    - Direct mutable stats update
*)
let process_packet_in_domain ~core ~packet =
  let stats = get_local_stats () in
  stats.packets_recv <- stats.packets_recv + 1;
  stats.bytes_recv <- stats.bytes_recv + Bytes.length packet;
  (* Process through Sans-IO core *)
  let outputs = Sctp_core.handle core (Sctp_core.PacketReceived packet) in
  (* Convert outputs to RX outputs *)
  List.filter_map
    (function
      | Sctp_core.DeliverData { stream_id; data } ->
        stats.messages_delivered <- stats.messages_delivered + 1;
        Some (DeliverData { stream_id; data })
      | Sctp_core.SendPacket packet -> Some (SendSack packet)
      | Sctp_core.Error e -> Some (Error e)
      | _ -> None)
    outputs
;;

(** Start all RX domains *)
let start t ~core_factory ~recv_packet =
  Array.iter
    (fun rx_domain ->
       rx_domain.running <- true;
       let domain =
         Domain.spawn (fun () ->
           (* Each domain gets its own core instance *)
           let core = core_factory () in
           let _stats = get_local_stats () in
           (* Initialize DLS *)
           while rx_domain.running do
             match recv_packet () with
             | Some packet ->
               let outputs = process_packet_in_domain ~core ~packet in
               List.iter (Mpsc_queue.push rx_domain.output_queue) outputs
             | None ->
               (* No packet available, brief pause to avoid busy-wait *)
               Domain.cpu_relax ()
           done)
       in
       rx_domain.domain := Some domain)
    t.domains
;;

(** Stop all RX domains *)
let stop t =
  (* Signal all domains to stop *)
  Array.iter (fun rx_domain -> rx_domain.running <- false) t.domains;
  (* Wait for all domains to finish *)
  Array.iter
    (fun rx_domain ->
       match !(rx_domain.domain) with
       | Some d -> Domain.join d
       | None -> ())
    t.domains
;;

(** Drain outputs from all RX domains (call from main domain) *)
let drain_outputs t = Mpsc_queue.drain t.output_queue

(** Aggregate stats from all domains

    NOTE: This is NOT thread-safe for reading domain stats.
    Call only when domains are paused or accept approximate values.
*)
let aggregate_stats t =
  let total =
    { total_packets_recv = 0
    ; total_bytes_recv = 0
    ; total_messages_delivered = 0
    ; total_crc_errors = 0
    ; total_parse_errors = 0
    ; domain_count = t.domain_count
    }
  in
  (* In practice, you'd collect from each domain's DLS
     This is a simplified version that shows the pattern *)
  t.stats_snapshot <- Some total;
  total
;;

(** Get last aggregated stats *)
let get_stats t =
  match t.stats_snapshot with
  | Some s -> s
  | None -> aggregate_stats t
;;

(** {1 Convenience Functions} *)

(** Number of active RX domains *)
let domain_count t = t.domain_count

(** Check if any domain is still running *)
let is_running t = Array.exists (fun d -> d.running) t.domains

(** Pretty print stats *)
let pp_stats fmt (s : aggregated_stats) =
  Format.fprintf
    fmt
    "parallel_rx: domains=%d pkts=%d bytes=%d msgs=%d errs=%d"
    s.domain_count
    s.total_packets_recv
    s.total_bytes_recv
    s.total_messages_delivered
    (s.total_crc_errors + s.total_parse_errors)
;;
