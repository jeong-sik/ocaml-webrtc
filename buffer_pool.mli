(** Zero-Allocation Buffer Pool

    Pre-allocated buffer pool inspired by AF_XDP UMEM and Jane Street's
    zero-allocation patterns. Eliminates GC pressure during high-throughput
    packet processing by reusing fixed-size buffers.

    {1 Design Philosophy}

    In high-performance networking, allocation is the enemy. Each [Bytes.create]
    triggers GC activity that can cause latency spikes. This pool pre-allocates
    buffers at startup and recycles them.

    {v
    Traditional approach (GC pressure):
    ┌─────────┐  alloc  ┌──────┐  free  ┌────┐
    │ Process │ ──────> │ Heap │ ─────> │ GC │ (pause!)
    └─────────┘         └──────┘        └────┘

    Pool approach (zero-alloc hot path):
    ┌─────────┐  alloc  ┌──────┐  free
    │ Process │ <─────> │ Pool │ ────── (instant return)
    └─────────┘         └──────┘
    v}

    Reference: https://discuss.ocaml.org/t/using-af-xdp-sockets-for-high-performance-packet-processing-in-ocaml/6106

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** {1 Configuration} *)

(** Pool configuration *)
type config =
  { buffer_size : int (** Size of each buffer in bytes *)
  ; pool_size : int (** Number of buffers in pool *)
  }

(** Default configuration: 2048 byte buffers, 1024 buffer pool (2MB total) *)
val default_config : config

(** {1 Pool Type} *)

(** Buffer pool (abstract) *)
type t

(** {1 Buffer Handle}

    Opaque handle to a pooled buffer with length tracking for partial usage.
    The handle tracks which pool it belongs to for proper return. *)

type buffer

(** {1 Creation} *)

(** [create ?config ()] creates a new buffer pool.

    All buffers are pre-allocated at creation time, so this may take
    a moment for large pools but ensures zero allocation during operation.

    @param config Pool configuration (default: 2048 bytes × 1024 buffers) *)
val create : ?config:config -> unit -> t

(** {1 Allocation and Deallocation} *)

(** [alloc t] allocates a buffer from the pool.

    {b O(1) operation} - just pops from free list.

    If the pool is exhausted, falls back to heap allocation.
    Use {!get_stats} to monitor fallback rate.

    @return A buffer handle ready for use *)
val alloc : t -> buffer

(** [free buf] returns a buffer to its pool.

    {b O(1) operation} - just pushes to free list.

    Safe to call on fallback (heap-allocated) buffers - they are
    simply left to GC. *)
val free : buffer -> unit

(** {1 Buffer Operations} *)

(** [get_bytes buf] returns the underlying bytes array and its capacity.

    Use this for direct writes. Call {!set_len} after writing.

    @return [(bytes, capacity)] *)
val get_bytes : buffer -> Bytes.t * int

(** [set_len buf len] sets the used length of the buffer.

    Must be called after writing to indicate how much data is valid. *)
val set_len : buffer -> int -> unit

(** [get_len buf] returns the current used length. *)
val get_len : buffer -> int

(** [blit_from buf ~src ~src_off ~len] copies data into the buffer.

    Also sets the buffer length to [len]. *)
val blit_from : buffer -> src:bytes -> src_off:int -> len:int -> unit

(** [blit_to buf ~dst ~dst_off] copies buffer contents to destination.

    Copies [get_len buf] bytes. *)
val blit_to : buffer -> dst:bytes -> dst_off:int -> unit

(** [to_bytes buf] extracts the used portion as a new Bytes.

    {b Warning}: This allocates! Use sparingly in hot paths.
    Prefer {!blit_to} when possible. *)
val to_bytes : buffer -> bytes

(** {1 Statistics} *)

(** Pool statistics for monitoring *)
type stats =
  { total_buffers : int (** Total buffers in pool *)
  ; free_buffers : int (** Currently available buffers *)
  ; alloc_ops : int (** Total allocation operations *)
  ; free_ops : int (** Total free operations *)
  ; fallback_allocs : int (** Heap allocations when pool exhausted *)
  ; hit_rate : float (** Pool hit rate (0.0-1.0) *)
  }

(** [get_stats t] returns current pool statistics.

    Monitor [hit_rate] - if below 0.95, consider increasing pool size. *)
val get_stats : t -> stats

(** [stats_to_string stats] formats stats for logging/debugging. *)
val stats_to_string : stats -> string

(** {1 RAII-style Usage} *)

(** [with_buffer t f] executes [f] with a buffer, auto-freeing after.

    Ensures buffer is returned to pool even if [f] raises an exception.

    Example:
    {[
      with_buffer pool (fun buf ->
        let (data, cap) = get_bytes buf in
        let len = recv sock data 0 cap in
        set_len buf len;
        process buf
      )
    ]} *)
val with_buffer : t -> (buffer -> 'a) -> 'a
