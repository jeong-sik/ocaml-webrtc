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

(** SDES item type (RFC 3550). *)
type sdes_item_type =
  | CNAME
  | NAME
  | EMAIL
  | PHONE
  | LOC
  | TOOL
  | NOTE
  | PRIV
  | Unknown_item of int

type sdes_item = {
  item_type : sdes_item_type;
  value : string;
}

type sdes_chunk = {
  ssrc : int32;
  items : sdes_item list;
}

type bye_packet = {
  ssrcs : int32 list;
  reason : string option;
}

type app_packet = {
  subtype : int;
  ssrc : int32;
  name : string;
  data : bytes;
}

type packet =
  | Sender_report of sender_report
  | Receiver_report of receiver_report
  | Source_description of sdes_chunk list
  | Bye of bye_packet
  | App of app_packet
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

let sdes_item_type_of_int = function
  | 1 -> CNAME
  | 2 -> NAME
  | 3 -> EMAIL
  | 4 -> PHONE
  | 5 -> LOC
  | 6 -> TOOL
  | 7 -> NOTE
  | 8 -> PRIV
  | n -> Unknown_item n

let int_of_sdes_item_type = function
  | CNAME -> 1
  | NAME -> 2
  | EMAIL -> 3
  | PHONE -> 4
  | LOC -> 5
  | TOOL -> 6
  | NOTE -> 7
  | PRIV -> 8
  | Unknown_item n -> n

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

let sdes_chunk_length items =
  let items_len =
    List.fold_left (fun acc item -> acc + 2 + String.length item.value) 0 items
  in
  let base = 4 + items_len + 1 in
  let padding = (4 - (base mod 4)) mod 4 in
  base + padding

let encode_sdes_chunk (chunk : sdes_chunk) =
  let total_len = sdes_chunk_length chunk.items in
  let buf = Bytes.create total_len in
  write_uint32_be buf 0 chunk.ssrc;
  let pos = ref 4 in
  List.iter (fun item ->
    let item_type = int_of_sdes_item_type item.item_type in
    let len = String.length item.value in
    Bytes.set_uint8 buf !pos item_type; incr pos;
    Bytes.set_uint8 buf !pos len; incr pos;
    Bytes.blit_string item.value 0 buf !pos len;
    pos := !pos + len
  ) chunk.items;
  Bytes.set_uint8 buf !pos 0;  (* END *)
  buf

let decode_sdes_chunk buf off limit =
  if off + 4 > limit then
    Error "RTCP SDES chunk truncated"
  else
    let ssrc = read_uint32_be buf off in
    let pos = ref (off + 4) in
    let items = ref [] in
    let error = ref None in
    let saw_end = ref false in
    while (not !saw_end) && !pos < limit && !error = None do
      let item_type = Bytes.get_uint8 buf !pos in
      if item_type = 0 then begin
        incr pos;
        saw_end := true
      end else if !pos + 2 > limit then
        error := Some "RTCP SDES item header truncated"
      else begin
        let len = Bytes.get_uint8 buf (!pos + 1) in
        if !pos + 2 + len > limit then
          error := Some "RTCP SDES item truncated"
        else begin
          let value = Bytes.sub_string buf (!pos + 2) len in
          items := { item_type = sdes_item_type_of_int item_type; value } :: !items;
          pos := !pos + 2 + len
        end
      end
    done;
    begin match !error with
    | Some msg -> Error msg
    | None ->
      if not !saw_end then
        Error "RTCP SDES missing end marker"
      else
        let consumed = !pos - off in
        let padding = (4 - (consumed mod 4)) mod 4 in
        let next = !pos + padding in
        Ok ({ ssrc; items = List.rev !items }, next)
    end

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
    | Source_description chunks ->
      let count = List.length chunks in
      if count > 31 then invalid_arg "RTCP SDES chunks must be <= 31";
      let encoded_chunks = List.map encode_sdes_chunk chunks in
      let body_len = List.fold_left (fun acc b -> acc + Bytes.length b) 0 encoded_chunks in
      let write_body buf off =
        let pos = ref off in
        List.iter (fun chunk ->
          Bytes.blit chunk 0 buf !pos (Bytes.length chunk);
          pos := !pos + Bytes.length chunk
        ) encoded_chunks
      in
      (SDES, count, body_len, write_body)
    | Bye bye ->
      let count = List.length bye.ssrcs in
      if count < 1 || count > 31 then invalid_arg "RTCP BYE ssrcs must be 1..31";
      let ssrc_len = count * 4 in
      let reason_len =
        match bye.reason with
        | None -> 0
        | Some r ->
          let len = String.length r in
          if len > 255 then invalid_arg "RTCP BYE reason too long";
          (* 1 byte length + string + padding to 32-bit boundary *)
          let total = 1 + len in
          let padding = (4 - (total mod 4)) mod 4 in
          total + padding
      in
      let body_len = ssrc_len + reason_len in
      let write_body buf off =
        let pos = ref off in
        List.iter (fun ssrc ->
          write_uint32_be buf !pos ssrc;
          pos := !pos + 4
        ) bye.ssrcs;
        match bye.reason with
        | None -> ()
        | Some r ->
          let len = String.length r in
          Bytes.set_uint8 buf !pos len;
          Bytes.blit_string r 0 buf (!pos + 1) len;
          (* Zero-fill padding *)
          let total = 1 + len in
          let padding = (4 - (total mod 4)) mod 4 in
          for i = 0 to padding - 1 do
            Bytes.set_uint8 buf (!pos + total + i) 0
          done
      in
      (BYE, count, body_len, write_body)
    | App app ->
      if app.subtype < 0 || app.subtype > 31 then
        invalid_arg "RTCP APP subtype must be 0..31";
      if String.length app.name <> 4 then
        invalid_arg "RTCP APP name must be exactly 4 characters";
      let data_len = Bytes.length app.data in
      if data_len mod 4 <> 0 then
        invalid_arg "RTCP APP data length must be 32-bit aligned";
      let body_len = 4 + 4 + data_len in  (* SSRC + name + data *)
      let write_body buf off =
        write_uint32_be buf off app.ssrc;
        Bytes.blit_string app.name 0 buf (off + 4) 4;
        Bytes.blit app.data 0 buf (off + 8) data_len
      in
      (APP, app.subtype, body_len, write_body)
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
        | SDES ->
          let limit = body_off + body_len in
          let rec loop idx off acc =
            if idx = count then
              Ok (Source_description (List.rev acc))
            else
              match decode_sdes_chunk data off limit with
              | Error e -> Error e
              | Ok (chunk, next) -> loop (idx + 1) next (chunk :: acc)
          in
          loop 0 body_off []
        | BYE ->
          let ssrc_len = count * 4 in
          if body_len < ssrc_len then
            Error "RTCP BYE body too short"
          else
            let ssrcs = ref [] in
            for i = 0 to count - 1 do
              let ssrc = read_uint32_be data (body_off + i * 4) in
              ssrcs := ssrc :: !ssrcs
            done;
            let reason =
              let reason_off = body_off + ssrc_len in
              if reason_off >= body_off + body_len then
                None
              else
                let len = Bytes.get_uint8 data reason_off in
                if reason_off + 1 + len > body_off + body_len then
                  None  (* Malformed, but be lenient *)
                else
                  Some (Bytes.sub_string data (reason_off + 1) len)
            in
            Ok (Bye { ssrcs = List.rev !ssrcs; reason })
        | APP ->
          if body_len < 8 then
            Error "RTCP APP body too short"
          else
            let ssrc = read_uint32_be data body_off in
            let name = Bytes.sub_string data (body_off + 4) 4 in
            let data_len = body_len - 8 in
            let app_data = Bytes.sub data (body_off + 8) data_len in
            Ok (App { subtype = count; ssrc; name; data = app_data })
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

(** Helper: Create SDES packet with a single CNAME item. *)
let make_sdes_cname ~ssrc ~cname =
  Source_description [{
    ssrc;
    items = [{ item_type = CNAME; value = cname }]
  }]

(** Helper: Create BYE packet. *)
let make_bye ?reason ssrcs =
  Bye { ssrcs; reason }

(** Calculate RTCP transmission interval (RFC 3550 Section 6.3).

    The algorithm:
    1. If senders <= 25% of members, split bandwidth between senders/receivers
    2. Calculate interval based on members, bandwidth, and avg packet size
    3. Apply minimum interval (5 seconds, or 2.5 seconds if initial)
    4. Apply randomization factor (not done here, caller should add jitter)
*)
let calculate_rtcp_interval ~members ~senders ~rtcp_bw ~we_sent ~avg_rtcp_size ~initial =
  let members = float_of_int (max 1 members) in
  let senders = float_of_int (max 0 senders) in

  (* RFC 3550 Section 6.3.1: Bandwidth allocation *)
  let (n, c) =
    if senders <= members *. 0.25 then
      (* Senders <= 25%: allocate 25% of RTCP bandwidth to senders *)
      if we_sent then
        (senders, rtcp_bw *. 0.25)
      else
        (members -. senders, rtcp_bw *. 0.75)
    else
      (* Senders > 25%: share bandwidth equally *)
      (members, rtcp_bw)
  in

  (* Calculate interval: (avg_rtcp_size * n) / c *)
  let interval =
    if c <= 0.0 then 5.0
    else (avg_rtcp_size *. n) /. c
  in

  (* Apply minimum *)
  let t_min = if initial then 2.5 else 5.0 in
  max interval t_min
