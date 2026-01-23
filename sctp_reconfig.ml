(** RFC 6525 - SCTP Re-configuration chunk helpers

    Provides encode/decode utilities for RE-CONFIG chunk parameters.
*)

open Webrtc_common

type reconfig_param =
  | Outgoing_ssn_reset of
      { request_seq : int32
      ; response_seq : int32
      ; last_tsn : int32
      ; streams : int list
      }
  | Incoming_ssn_reset of
      { request_seq : int32
      ; response_seq : int32
      ; last_tsn : int32
      ; streams : int list
      }
  | Reconfig_response of
      { response_seq : int32
      ; result : int32
      }
  | Add_outgoing_streams of
      { request_seq : int32
      ; new_streams : int
      }
  | Add_incoming_streams of
      { request_seq : int32
      ; new_streams : int
      }
  | Unknown of int * bytes

type t = reconfig_param list

let param_outgoing_ssn_reset = 0x000D
let param_incoming_ssn_reset = 0x000E
let param_reconfig_response = 0x0010
let param_add_outgoing = 0x0011
let param_add_incoming = 0x0012
let result_success = 0l
let result_in_progress = 1l
let result_denied = 2l
let result_error = 3l
let pad4 len = (len + 3) land lnot 3

let encode_stream_list streams =
  let buf = Bytes.create (List.length streams * 2) in
  List.iteri (fun i sid -> write_uint16_be buf (i * 2) sid) streams;
  buf
;;

let decode_stream_list buf =
  let len = Bytes.length buf in
  if len mod 2 <> 0
  then Error "Invalid stream list length"
  else (
    let rec loop idx acc =
      if idx >= len
      then Ok (List.rev acc)
      else (
        let sid = read_uint16_be buf idx in
        loop (idx + 2) (sid :: acc))
    in
    loop 0 [])
;;

let build_param param_type body =
  let length = 4 + Bytes.length body in
  let padded_len = pad4 length in
  let buf = Bytes.create padded_len in
  write_uint16_be buf 0 param_type;
  write_uint16_be buf 2 length;
  Bytes.blit body 0 buf 4 (Bytes.length body);
  buf
;;

let encode_param = function
  | Outgoing_ssn_reset { request_seq; response_seq; last_tsn; streams } ->
    let streams_buf = encode_stream_list streams in
    let body = Bytes.create (12 + Bytes.length streams_buf) in
    write_uint32_be body 0 request_seq;
    write_uint32_be body 4 response_seq;
    write_uint32_be body 8 last_tsn;
    Bytes.blit streams_buf 0 body 12 (Bytes.length streams_buf);
    build_param param_outgoing_ssn_reset body
  | Incoming_ssn_reset { request_seq; response_seq; last_tsn; streams } ->
    let streams_buf = encode_stream_list streams in
    let body = Bytes.create (12 + Bytes.length streams_buf) in
    write_uint32_be body 0 request_seq;
    write_uint32_be body 4 response_seq;
    write_uint32_be body 8 last_tsn;
    Bytes.blit streams_buf 0 body 12 (Bytes.length streams_buf);
    build_param param_incoming_ssn_reset body
  | Reconfig_response { response_seq; result } ->
    let body = Bytes.create 8 in
    write_uint32_be body 0 response_seq;
    write_uint32_be body 4 result;
    build_param param_reconfig_response body
  | Add_outgoing_streams { request_seq; new_streams } ->
    let body = Bytes.create 8 in
    write_uint32_be body 0 request_seq;
    write_uint16_be body 4 new_streams;
    write_uint16_be body 6 0;
    build_param param_add_outgoing body
  | Add_incoming_streams { request_seq; new_streams } ->
    let body = Bytes.create 8 in
    write_uint32_be body 0 request_seq;
    write_uint16_be body 4 new_streams;
    write_uint16_be body 6 0;
    build_param param_add_incoming body
  | Unknown (param_type, body) -> build_param param_type body
;;

let encode_params params = Bytes.concat Bytes.empty (List.map encode_param params)

let decode_param param_type body =
  let body_len = Bytes.length body in
  match param_type with
  | t when t = param_outgoing_ssn_reset || t = param_incoming_ssn_reset ->
    if body_len < 12
    then Error "Reset request too short"
    else (
      let request_seq = read_uint32_be body 0 in
      let response_seq = read_uint32_be body 4 in
      let last_tsn = read_uint32_be body 8 in
      let stream_bytes = Bytes.sub body 12 (body_len - 12) in
      match decode_stream_list stream_bytes with
      | Error e -> Error e
      | Ok streams ->
        if t = param_outgoing_ssn_reset
        then Ok (Outgoing_ssn_reset { request_seq; response_seq; last_tsn; streams })
        else Ok (Incoming_ssn_reset { request_seq; response_seq; last_tsn; streams }))
  | t when t = param_reconfig_response ->
    if body_len < 8
    then Error "Reconfig response too short"
    else (
      let response_seq = read_uint32_be body 0 in
      let result = read_uint32_be body 4 in
      Ok (Reconfig_response { response_seq; result }))
  | t when t = param_add_outgoing || t = param_add_incoming ->
    if body_len < 8
    then Error "Add streams parameter too short"
    else (
      let request_seq = read_uint32_be body 0 in
      let new_streams = read_uint16_be body 4 in
      if t = param_add_outgoing
      then Ok (Add_outgoing_streams { request_seq; new_streams })
      else Ok (Add_incoming_streams { request_seq; new_streams }))
  | _ -> Ok (Unknown (param_type, body))
;;

let decode_params buf =
  let len = Bytes.length buf in
  let rec loop offset acc =
    if offset + 4 > len
    then Ok (List.rev acc)
    else (
      let param_type = read_uint16_be buf offset in
      let param_len = read_uint16_be buf (offset + 2) in
      if param_len < 4 || offset + param_len > len
      then Error "Invalid parameter length"
      else (
        let body_len = param_len - 4 in
        let body = Bytes.sub buf (offset + 4) body_len in
        match decode_param param_type body with
        | Error e -> Error e
        | Ok param ->
          let next = offset + pad4 param_len in
          loop next (param :: acc)))
  in
  loop 0 []
;;

let to_raw_chunk params : Sctp.raw_chunk =
  let value = encode_params params in
  { Sctp.chunk_type = Sctp.int_of_chunk_type Sctp.RE_CONFIG
  ; chunk_flags = 0
  ; chunk_length = 4 + Bytes.length value
  ; chunk_value = value
  }
;;

let of_raw_chunk (chunk : Sctp.raw_chunk) =
  if chunk.chunk_type <> Sctp.int_of_chunk_type Sctp.RE_CONFIG
  then Error "Not a RE-CONFIG chunk"
  else decode_params chunk.chunk_value
;;
