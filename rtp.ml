(** RTP (RFC 3550) - Minimal header encode/decode for audio media. *)

open Webrtc_common

type extension = {
  profile : int;
  data : bytes;
}

type header = {
  version : int;
  padding : bool;
  extension : extension option;
  marker : bool;
  payload_type : int;
  sequence : int;
  timestamp : int32;
  ssrc : int32;
  csrc : int32 list;
  padding_len : int;
}

type packet = {
  header : header;
  payload : bytes;
}

let default_header ?(payload_type = 111) ?(sequence = 0) ?(timestamp = 0l) ?(ssrc = 0l) () =
  {
    version = 2;
    padding = false;
    extension = None;
    marker = false;
    payload_type;
    sequence;
    timestamp;
    ssrc;
    csrc = [];
    padding_len = 0;
  }

let next_sequence seq =
  (seq + 1) land 0xFFFF

let encode header ~payload =
  if header.version <> 2 then
    Error "RTP version must be 2"
  else if header.payload_type < 0 || header.payload_type > 127 then
    Error "RTP payload_type must be 0..127"
  else if header.sequence < 0 || header.sequence > 0xFFFF then
    Error "RTP sequence must be 0..65535"
  else if List.length header.csrc > 15 then
    Error "RTP CSRC count must be <= 15"
  else begin
    let ext_len =
      match header.extension with
      | None -> 0
      | Some ext ->
        let data_len = Bytes.length ext.data in
        if data_len mod 4 <> 0 then
          -1
        else
          4 + data_len
    in
    if ext_len = -1 then
      Error "RTP extension data length must be multiple of 4"
    else if header.padding_len < 0 then
      Error "RTP padding_len must be >= 0"
    else begin
      let csrc_len = 4 * List.length header.csrc in
      let header_len = 12 + csrc_len + ext_len in
      let total_len = header_len + Bytes.length payload + header.padding_len in
      if header.padding_len > 0 && total_len < header_len + 1 then
        Error "RTP padding_len invalid"
      else begin
        let buf = Bytes.create total_len in
        let b0 =
          ((header.version land 0x3) lsl 6) lor
          (if header.padding || header.padding_len > 0 then 0x20 else 0) lor
          (if header.extension <> None then 0x10 else 0) lor
          (List.length header.csrc land 0x0F)
        in
        let b1 =
          (if header.marker then 0x80 else 0) lor
          (header.payload_type land 0x7F)
        in
        Bytes.set_uint8 buf 0 b0;
        Bytes.set_uint8 buf 1 b1;
        write_uint16_be buf 2 header.sequence;
        write_uint32_be buf 4 header.timestamp;
        write_uint32_be buf 8 header.ssrc;
        let offset = ref 12 in
        List.iter (fun csrc_id ->
          write_uint32_be buf !offset csrc_id;
          offset := !offset + 4
        ) header.csrc;
        (match header.extension with
         | None -> ()
         | Some ext ->
           write_uint16_be buf !offset ext.profile;
           let words = Bytes.length ext.data / 4 in
           write_uint16_be buf (!offset + 2) words;
           Bytes.blit ext.data 0 buf (!offset + 4) (Bytes.length ext.data);
           offset := !offset + 4 + Bytes.length ext.data);
        Bytes.blit payload 0 buf !offset (Bytes.length payload);
        if header.padding_len > 0 then begin
          let pad_start = !offset + Bytes.length payload in
          Bytes.fill buf pad_start (header.padding_len - 1) '\x00';
          Bytes.set_uint8 buf (pad_start + header.padding_len - 1) header.padding_len
        end;
        Ok buf
      end
    end
  end

let decode data =
  let len = Bytes.length data in
  if len < 12 then
    Error "RTP packet too short"
  else
    let b0 = Bytes.get_uint8 data 0 in
    let b1 = Bytes.get_uint8 data 1 in
    let version = b0 lsr 6 in
    let padding = (b0 land 0x20) <> 0 in
    let has_extension = (b0 land 0x10) <> 0 in
    let csrc_count = b0 land 0x0F in
    let marker = (b1 land 0x80) <> 0 in
    let payload_type = b1 land 0x7F in
    if version <> 2 then
      Error "RTP version mismatch"
    else if len < (12 + (4 * csrc_count)) then
      Error "RTP packet missing CSRC list"
    else
      let sequence = read_uint16_be data 2 in
      let timestamp = read_uint32_be data 4 in
      let ssrc = read_uint32_be data 8 in
      let offset = ref 12 in
      let csrc =
        let rec loop acc i =
          if i = 0 then
            List.rev acc
          else
            let id = read_uint32_be data !offset in
            offset := !offset + 4;
            loop (id :: acc) (i - 1)
        in
        loop [] csrc_count
      in
      let extension =
        if not has_extension then
          Ok None
        else if len < !offset + 4 then
          Error "RTP packet missing extension header"
        else
          let profile = read_uint16_be data !offset in
          let words = read_uint16_be data (!offset + 2) in
          let ext_len = words * 4 in
          let ext_start = !offset + 4 in
          if len < ext_start + ext_len then
            Error "RTP packet missing extension data"
          else
            let ext_data = Bytes.sub data ext_start ext_len in
            offset := ext_start + ext_len;
            Ok (Some { profile; data = ext_data })
      in
      match extension with
      | Error _ as err -> err
      | Ok ext ->
        let payload_start = !offset in
        if payload_start > len then
          Error "RTP payload offset invalid"
        else
          let padding_len =
            if not padding then 0
            else if len = 0 then 0
            else Bytes.get_uint8 data (len - 1)
          in
          if padding && (padding_len = 0 || padding_len > (len - payload_start)) then
            Error "RTP padding length invalid"
          else
            let payload_end = len - padding_len in
            let payload_len = payload_end - payload_start in
            if payload_len < 0 then
              Error "RTP payload length invalid"
            else
              let payload = Bytes.sub data payload_start payload_len in
              let header = {
                version;
                padding;
                extension = ext;
                marker;
                payload_type;
                sequence;
                timestamp;
                ssrc;
                csrc;
                padding_len;
              } in
              Ok { header; payload }
