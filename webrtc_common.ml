(** WebRTC Common Utilities

    Shared byte manipulation helpers for WebRTC protocol stack.
    Extracted from dtls.ml, sctp.ml, datachannel.ml to eliminate duplication.
*)

(** {1 Byte Manipulation - Big Endian} *)

(** Write uint16 in big-endian format *)
let write_uint16_be buf offset value =
  Bytes.set_uint16_be buf offset value

(** Read uint16 in big-endian format *)
let read_uint16_be buf offset =
  Bytes.get_uint16_be buf offset

(** Write uint32 in big-endian format *)
let write_uint32_be buf offset value =
  Bytes.set_int32_be buf offset value

(** Read uint32 in big-endian format *)
let read_uint32_be buf offset =
  Bytes.get_int32_be buf offset

(** Write uint48 (6 bytes) in big-endian format - used for DTLS sequence numbers *)
let write_uint48_be buf offset value =
  let high = Int64.to_int (Int64.shift_right_logical value 32) in
  let mid = Int64.to_int (Int64.logand (Int64.shift_right_logical value 16) 0xFFFFL) in
  let low = Int64.to_int (Int64.logand value 0xFFFFL) in
  Bytes.set_uint16_be buf offset high;
  Bytes.set_uint16_be buf (offset + 2) mid;
  Bytes.set_uint16_be buf (offset + 4) low

(** Read uint48 (6 bytes) in big-endian format *)
let read_uint48_be buf offset =
  let high = Int64.of_int (Bytes.get_uint16_be buf offset) in
  let mid = Int64.of_int (Bytes.get_uint16_be buf (offset + 2)) in
  let low = Int64.of_int (Bytes.get_uint16_be buf (offset + 4)) in
  Int64.logor
    (Int64.shift_left high 32)
    (Int64.logor (Int64.shift_left mid 16) low)

(** {1 Buffer Utilities} *)

(** Create a buffer filled with random bytes *)
let random_bytes len =
  let buf = Bytes.create len in
  for i = 0 to len - 1 do
    Bytes.set_uint8 buf i (Random.int 256)
  done;
  buf

(** Safe sub-bytes extraction with bounds checking *)
let safe_sub_bytes buf offset len =
  if offset < 0 || len < 0 || offset + len > Bytes.length buf then
    None
  else
    Some (Bytes.sub buf offset len)

(** {1 CRC32c for SCTP - Hardware Accelerated} *)

(** Hardware-accelerated CRC32c (ARM64 CRC / x86_64 SSE4.2) *)
external crc32c_fast : bytes -> int32 = "caml_crc32c_fast"

(** Check if hardware acceleration is available *)
external crc32c_has_hardware : unit -> bool = "caml_crc32c_has_hardware"

(** CRC32c lookup table (Castagnoli polynomial) - Software fallback *)
let crc32c_table =
  lazy (
    let table = Array.make 256 0l in
    for i = 0 to 255 do
      let crc = ref (Int32.of_int i) in
      for _ = 0 to 7 do
        if Int32.logand !crc 1l <> 0l then
          crc := Int32.logxor (Int32.shift_right_logical !crc 1) 0x82F63B78l
        else
          crc := Int32.shift_right_logical !crc 1
      done;
      table.(i) <- !crc
    done;
    table
  )

(** Software CRC32c (fallback if C stub unavailable) *)
let crc32c_software data =
  let table = Lazy.force crc32c_table in
  let crc = ref 0xFFFFFFFFl in
  for i = 0 to Bytes.length data - 1 do
    let byte = Int32.of_int (Bytes.get_uint8 data i) in
    let index = Int32.to_int (Int32.logand (Int32.logxor !crc byte) 0xFFl) in
    crc := Int32.logxor (Int32.shift_right_logical !crc 8) table.(index)
  done;
  Int32.logxor !crc 0xFFFFFFFFl

(** Calculate CRC32c checksum - Uses hardware acceleration when available *)
let crc32c = crc32c_fast
