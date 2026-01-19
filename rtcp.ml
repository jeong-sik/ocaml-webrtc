(** RTCP (RFC 3550) - Minimal SR/RR encoding and decoding. *)

open Webrtc_common

type packet_type =
  | SR
  | RR
  | SDES
  | BYE
  | APP
  | RTPFB
  | PSFB
  | XR
  | Unknown of int

type report_block = {
  ssrc : int32;
  fraction_lost : int;
  cumulative_lost : int32;
  highest_seq : int32;
  jitter : int32;
  last_sr : int32;
  dlsr : int32;
}

type sender_info = {
  ntp_sec : int32;
  ntp_frac : int32;
  rtp_timestamp : int32;
  packet_count : int32;
  octet_count : int32;
}

type sender_report = {
  ssrc : int32;
  sender_info : sender_info;
  report_blocks : report_block list;
}

type receiver_report = {
  ssrc : int32;
  report_blocks : report_block list;
}

type packet =
  | Sender_report of sender_report
  | Receiver_report of receiver_report
  | Unknown_packet of packet_type * bytes

let packet_type_of_int = function
  | 200 -> SR
  | 201 -> RR
  | 202 -> SDES
  | 203 -> BYE
  | 204 -> APP
  | 205 -> RTPFB
  | 206 -> PSFB
  | 207 -> XR
  | n -> Unknown n

let int_of_packet_type = function
  | SR -> 200
  | RR -> 201
  | SDES -> 202
  | BYE -> 203
  | APP -> 204
  | RTPFB -> 205
  | PSFB -> 206
  | XR -> 207
  | Unknown n -> n

let read_int24_be buf off =
  let b0 = Bytes.get_uint8 buf off in
  let b1 = Bytes.get_uint8 buf (off + 1) in
  let b2 = Bytes.get_uint8 buf (off + 2) in
  let v = (b0 lsl 16) lor (b1 lsl 8) lor b2 in
  if (b0 land 0x80) <> 0 then
    v - 0x1000000
  else
    v

let write_int24_be buf off (v : int32) =
  let v = Int32.to_int v in
  let v = if v < 0 then v + 0x1000000 else v in
  Bytes.set_uint8 buf off ((v lsr 16) land 0xFF);
  Bytes.set_uint8 buf (off + 1) ((v lsr 8) land 0xFF);
  Bytes.set_uint8 buf (off + 2) (v land 0xFF)

let encode_report_block buf off (rb : report_block) =
  write_uint32_be buf off rb.ssrc;
  Bytes.set_uint8 buf (off + 4) (rb.fraction_lost land 0xFF);
  write_int24_be buf (off + 5) rb.cumulative_lost;
  write_uint32_be buf (off + 8) rb.highest_seq;
  write_uint32_be buf (off + 12) rb.jitter;
  write_uint32_be buf (off + 16) rb.last_sr;
  write_uint32_be buf (off + 20) rb.dlsr

let decode_report_block buf off =
  let ssrc = read_uint32_be buf off in
  let fraction_lost = Bytes.get_uint8 buf (off + 4) in
  let cumulative_lost = Int32.of_int (read_int24_be buf (off + 5)) in
  let highest_seq = read_uint32_be buf (off + 8) in
  let jitter = read_uint32_be buf (off + 12) in
  let last_sr = read_uint32_be buf (off + 16) in
  let dlsr = read_uint32_be buf (off + 20) in
  {
    ssrc;
    fraction_lost;
    cumulative_lost;
    highest_seq;
    jitter;
    last_sr;
    dlsr;
  }

let encode packet =
  let (packet_type, count, body_len, write_body) =
    match packet with
    | Sender_report sr ->
      let count = List.length sr.report_blocks in
      if count > 31 then invalid_arg "RTCP SR report_blocks must be <= 31";
      let body_len = 4 + 20 + (count * 24) in
      let write_body buf off =
        write_uint32_be buf off sr.ssrc;
        write_uint32_be buf (off + 4) sr.sender_info.ntp_sec;
        write_uint32_be buf (off + 8) sr.sender_info.ntp_frac;
        write_uint32_be buf (off + 12) sr.sender_info.rtp_timestamp;
        write_uint32_be buf (off + 16) sr.sender_info.packet_count;
        write_uint32_be buf (off + 20) sr.sender_info.octet_count;
        let rb_off = ref (off + 24) in
        List.iter (fun rb ->
          encode_report_block buf !rb_off rb;
          rb_off := !rb_off + 24
        ) sr.report_blocks
      in
      (SR, count, body_len, write_body)
    | Receiver_report rr ->
      let count = List.length rr.report_blocks in
      if count > 31 then invalid_arg "RTCP RR report_blocks must be <= 31";
      let body_len = 4 + (count * 24) in
      let write_body buf off =
        write_uint32_be buf off rr.ssrc;
        let rb_off = ref (off + 4) in
        List.iter (fun rb ->
          encode_report_block buf !rb_off rb;
          rb_off := !rb_off + 24
        ) rr.report_blocks
      in
      (RR, count, body_len, write_body)
    | Unknown_packet (pt, data) ->
      let body_len = Bytes.length data in
      let write_body buf off =
        Bytes.blit data 0 buf off body_len
      in
      (pt, 0, body_len, write_body)
  in
  if body_len mod 4 <> 0 then
    invalid_arg "RTCP body length must be 32-bit aligned";
  let total_len = 4 + body_len in
  let length_words = (total_len / 4) - 1 in
  let buf = Bytes.create total_len in
  let b0 = (2 lsl 6) lor (count land 0x1F) in
  Bytes.set_uint8 buf 0 b0;
  Bytes.set_uint8 buf 1 (int_of_packet_type packet_type land 0xFF);
  write_uint16_be buf 2 length_words;
  write_body buf 4;
  buf

let decode data =
  let len = Bytes.length data in
  if len < 4 then
    Error "RTCP packet too short"
  else
    let b0 = Bytes.get_uint8 data 0 in
    let version = b0 lsr 6 in
    let padding = (b0 land 0x20) <> 0 in
    let count = b0 land 0x1F in
    let pt = Bytes.get_uint8 data 1 in
    let length_words = read_uint16_be data 2 in
    let total_len = (length_words + 1) * 4 in
    if version <> 2 then
      Error "RTCP version mismatch"
    else if len < total_len then
      Error "RTCP packet truncated"
    else
      let padding_len =
        if not padding then 0
        else Bytes.get_uint8 data (total_len - 1)
      in
      let payload_len = total_len - padding_len in
      if padding && (padding_len = 0 || padding_len > total_len - 4) then
        Error "RTCP padding invalid"
      else
        let body_len = payload_len - 4 in
        let body_off = 4 in
        let packet_type = packet_type_of_int pt in
        match packet_type with
        | SR ->
          if body_len < 24 + (count * 24) then
            Error "RTCP SR body too short"
          else
            let ssrc = read_uint32_be data body_off in
            let sender_info = {
              ntp_sec = read_uint32_be data (body_off + 4);
              ntp_frac = read_uint32_be data (body_off + 8);
              rtp_timestamp = read_uint32_be data (body_off + 12);
              packet_count = read_uint32_be data (body_off + 16);
              octet_count = read_uint32_be data (body_off + 20);
            } in
            let rb_off = ref (body_off + 24) in
            let blocks = ref [] in
            for _ = 1 to count do
              let rb = decode_report_block data !rb_off in
              blocks := rb :: !blocks;
              rb_off := !rb_off + 24
            done;
            Ok (Sender_report { ssrc; sender_info; report_blocks = List.rev !blocks })
        | RR ->
          if body_len < 4 + (count * 24) then
            Error "RTCP RR body too short"
          else
            let ssrc = read_uint32_be data body_off in
            let rb_off = ref (body_off + 4) in
            let blocks = ref [] in
            for _ = 1 to count do
              let rb = decode_report_block data !rb_off in
              blocks := rb :: !blocks;
              rb_off := !rb_off + 24
            done;
            Ok (Receiver_report { ssrc; report_blocks = List.rev !blocks })
        | _ ->
          let body = Bytes.sub data body_off body_len in
          Ok (Unknown_packet (packet_type, body))

let decode_compound data =
  let len = Bytes.length data in
  let rec loop off acc =
    if off = len then
      Ok (List.rev acc)
    else if off + 4 > len then
      Error "RTCP compound truncated"
    else
      let length_words = read_uint16_be data (off + 2) in
      let total_len = (length_words + 1) * 4 in
      if off + total_len > len then
        Error "RTCP compound length invalid"
      else
        match decode (Bytes.sub data off total_len) with
        | Ok pkt -> loop (off + total_len) (pkt :: acc)
        | Error _ as err -> err
  in
  loop 0 []
