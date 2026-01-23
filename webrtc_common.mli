(** WebRTC Common Utilities

    Shared byte manipulation helpers for WebRTC protocol stack.
*)

(** {1 Byte Manipulation - Big Endian} *)

(** [write_uint16_be buf offset value] writes [value] as uint16 BE at [offset] *)
val write_uint16_be : bytes -> int -> int -> unit

(** [read_uint16_be buf offset] reads uint16 BE from [offset] *)
val read_uint16_be : bytes -> int -> int

(** [write_uint32_be buf offset value] writes [value] as uint32 BE at [offset] *)
val write_uint32_be : bytes -> int -> int32 -> unit

(** [read_uint32_be buf offset] reads uint32 BE from [offset] *)
val read_uint32_be : bytes -> int -> int32

(** [write_uint48_be buf offset value] writes [value] as 6-byte BE at [offset] *)
val write_uint48_be : bytes -> int -> int64 -> unit

(** [read_uint48_be buf offset] reads 6-byte BE from [offset] *)
val read_uint48_be : bytes -> int -> int64

(** {1 Buffer Utilities} *)

(** [random_bytes len] creates buffer of [len] random bytes *)
val random_bytes : int -> bytes

(** [safe_sub_bytes buf offset len] extracts sub-bytes with bounds checking *)
val safe_sub_bytes : bytes -> int -> int -> bytes option

(** {1 CRC32c for SCTP - Hardware Accelerated} *)

(** [crc32c data] calculates CRC32c checksum using hardware acceleration
    (ARM64 CRC / x86_64 SSE4.2) when available, otherwise software fallback. *)
val crc32c : bytes -> int32

(** [crc32c_has_hardware ()] returns true if hardware CRC32c is available *)
val crc32c_has_hardware : unit -> bool

(** [crc32c_software data] pure OCaml CRC32c (table lookup, slower) *)
val crc32c_software : bytes -> int32
