(** Minimal SRTP/SRTCP pipeline for a single SSRC. *)

open Webrtc_common

type t = {
  profile : Srtp.profile;
  local_keys : Srtp.session_keys;
  remote_keys : Srtp.session_keys;
  ssrc : int32;
  payload_type : int;
  mutable send_seq : int;
  mutable send_roc : int32;
  mutable recv_seq : int option;
  mutable recv_roc : int32;
  mutable send_rtcp_index : int32;
}

let create ~profile ~local_keys ~remote_keys ~ssrc ~payload_type =
  {
    profile;
    local_keys;
    remote_keys;
    ssrc;
    payload_type;
    send_seq = 0;
    send_roc = 0l;
    recv_seq = None;
    recv_roc = 0l;
    send_rtcp_index = 0l;
  }

let advance_send_seq t =
  let next = (t.send_seq + 1) land 0xFFFF in
  if next = 0 then t.send_roc <- Int32.succ t.send_roc;
  t.send_seq <- next

let advance_rtcp_index t =
  let next = Int32.logand (Int32.succ t.send_rtcp_index) 0x7FFFFFFFl in
  t.send_rtcp_index <- next

let estimate_roc t seq =
  match t.recv_seq with
  | None -> t.recv_roc
  | Some last ->
    if seq < last && (last - seq) > 0x8000 then
      Int32.succ t.recv_roc
    else
      t.recv_roc

let protect_rtp t ?(marker = false) ~timestamp ~payload () =
  let header =
    Rtp.default_header
      ~payload_type:t.payload_type
      ~sequence:t.send_seq
      ~timestamp
      ~ssrc:t.ssrc
      ()
  in
  let header = { header with marker } in
  match Rtp.encode header ~payload with
  | Error e -> Error e
  | Ok packet ->
    match Srtp.protect_rtp ~profile:t.profile ~keys:t.local_keys
            ~roc:t.send_roc ~packet with
    | Ok _ as ok ->
      advance_send_seq t;
      ok
    | Error _ as err -> err

let unprotect_rtp t ~packet =
  if Bytes.length packet < 4 then
    Error "RTP packet too short"
  else
    let seq = read_uint16_be packet 2 in
    let roc = estimate_roc t seq in
    match Srtp.unprotect_rtp ~profile:t.profile ~keys:t.remote_keys
            ~roc ~packet with
    | Error e -> Error e
    | Ok plaintext ->
      match Rtp.decode plaintext with
      | Ok pkt ->
        t.recv_seq <- Some pkt.Rtp.header.sequence;
        t.recv_roc <- roc;
        Ok pkt
      | Error e -> Error e

let protect_rtcp t ?(encrypt = true) ~packet () =
  let data = Rtcp.encode packet in
  match Srtp.protect_rtcp ~profile:t.profile ~keys:t.local_keys
          ~index:t.send_rtcp_index ~encrypt ~packet:data with
  | Ok _ as ok ->
    advance_rtcp_index t;
    ok
  | Error _ as err -> err

let unprotect_rtcp t ~packet =
  match Srtp.unprotect_rtcp ~profile:t.profile ~keys:t.remote_keys ~packet with
  | Error e -> Error e
  | Ok (plaintext, index) ->
    match Rtcp.decode plaintext with
    | Ok rtcp -> Ok (rtcp, index)
    | Error e -> Error e
