(** Zero-Allocation Buffer Pool

    Inspired by AF_XDP UMEM and Jane Street's zero-allocation patterns.
    Pre-allocates a pool of buffers to avoid GC pressure during
    high-throughput packet processing.

    Reference: https://discuss.ocaml.org/t/using-af-xdp-sockets-for-high-performance-packet-processing-in-ocaml/6106

    @author Second Brain
    @since ocaml-webrtc 0.4.0
*)

(** {1 Pool Configuration} *)

type config = {
  buffer_size: int;   (** Size of each buffer in bytes *)
  pool_size: int;     (** Number of buffers in pool *)
}

let default_config = {
  buffer_size = 2048;  (* MTU + headroom *)
  pool_size = 1024;    (* 2MB total *)
}

(** {1 Pool Type} *)

type t = {
  config: config;
  buffers: Bytes.t array;            (** Pre-allocated buffers *)
  free_list: int array;              (** Stack of free buffer indices *)
  mutable free_count: int;           (** Number of free buffers *)
  mutable alloc_count: int;          (** Stats: total allocations *)
  mutable free_op_count: int;        (** Stats: total frees *)
  mutable fallback_count: int;       (** Stats: fallback allocations when pool empty *)
}

(** {1 Creation} *)

let create ?(config=default_config) () =
  let buffers = Array.init config.pool_size (fun _ ->
    Bytes.create config.buffer_size
  ) in
  let free_list = Array.init config.pool_size (fun i -> i) in
  {
    config;
    buffers;
    free_list;
    free_count = config.pool_size;
    alloc_count = 0;
    free_op_count = 0;
    fallback_count = 0;
  }

(** {1 Buffer Handle}

    Opaque handle to a pooled buffer.
    Includes length tracking for partial usage.
*)

type buffer = {
  pool: t;
  index: int;        (** Index in pool, or -1 for fallback *)
  data: Bytes.t;
  mutable len: int;  (** Used length *)
}

(** {1 Allocation} *)

(** Allocate a buffer from the pool.
    Falls back to heap allocation if pool is exhausted.

    @param t The buffer pool
    @return A buffer handle
*)
let alloc t =
  t.alloc_count <- t.alloc_count + 1;
  if t.free_count > 0 then begin
    t.free_count <- t.free_count - 1;
    let idx = t.free_list.(t.free_count) in
    { pool = t; index = idx; data = t.buffers.(idx); len = 0 }
  end else begin
    (* Fallback: allocate from heap *)
    t.fallback_count <- t.fallback_count + 1;
    { pool = t; index = (-1); data = Bytes.create t.config.buffer_size; len = 0 }
  end

(** Return a buffer to the pool.

    @param buf The buffer to free
*)
let free buf =
  buf.pool.free_op_count <- buf.pool.free_op_count + 1;
  if buf.index >= 0 then begin
    (* Return to pool *)
    buf.pool.free_list.(buf.pool.free_count) <- buf.index;
    buf.pool.free_count <- buf.pool.free_count + 1
  end
  (* Fallback buffers are just left to GC *)

(** {1 Buffer Operations} *)

(** Get the underlying bytes for writing.

    @param buf The buffer handle
    @return The bytes array and its capacity
*)
let[@inline] get_bytes buf =
  (buf.data, buf.pool.config.buffer_size)

(** Set the used length after writing.

    @param buf The buffer handle
    @param len The new used length
*)
let[@inline] set_len buf len =
  buf.len <- len

(** Get the used length.

    @param buf The buffer handle
    @return The used length
*)
let[@inline] get_len buf =
  buf.len

(** Copy data into a buffer.

    @param buf The buffer handle
    @param src Source bytes
    @param src_off Offset in source
    @param len Length to copy
*)
let blit_from buf ~src ~src_off ~len =
  Bytes.blit src src_off buf.data 0 len;
  buf.len <- len

(** Copy data out of a buffer.

    @param buf The buffer handle
    @param dst Destination bytes
    @param dst_off Offset in destination
*)
let blit_to buf ~dst ~dst_off =
  Bytes.blit buf.data 0 dst dst_off buf.len

(** Get a sub-view of the buffer contents.
    Note: This creates a NEW Bytes (allocation!), use sparingly.

    @param buf The buffer handle
    @return Copy of the used portion
*)
let to_bytes buf =
  Bytes.sub buf.data 0 buf.len

(** {1 Statistics} *)

type stats = {
  total_buffers: int;
  free_buffers: int;
  alloc_ops: int;
  free_ops: int;
  fallback_allocs: int;
  hit_rate: float;
}

let get_stats t =
  let total_successful = t.alloc_count - t.fallback_count in
  {
    total_buffers = t.config.pool_size;
    free_buffers = t.free_count;
    alloc_ops = t.alloc_count;
    free_ops = t.free_op_count;
    fallback_allocs = t.fallback_count;
    hit_rate =
      if t.alloc_count > 0
      then float_of_int total_successful /. float_of_int t.alloc_count
      else 1.0;
  }

let stats_to_string stats =
  Printf.sprintf
    "BufferPool{total=%d, free=%d, allocs=%d, frees=%d, fallbacks=%d, hit=%.1f%%}"
    stats.total_buffers stats.free_buffers stats.alloc_ops stats.free_ops
    stats.fallback_allocs (stats.hit_rate *. 100.0)

(** {1 RAII-style Usage} *)

(** Execute a function with a pooled buffer, automatically freeing after.

    @param t The buffer pool
    @param f Function to execute with the buffer
    @return Result of f
*)
let with_buffer t f =
  let buf = alloc t in
  match f buf with
  | result ->
    free buf;
    result
  | exception e ->
    free buf;
    raise e
