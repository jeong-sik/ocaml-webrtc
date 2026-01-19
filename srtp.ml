(** SRTP/SRTCP (RFC 3711) - Minimal AES-CTR + HMAC-SHA1-80 implementation. *)

open Webrtc_common

type profile =
  | AES_128_CM_HMAC_SHA1_80

type keying = {
  master_key : bytes;
  master_salt : bytes;
}

type roc = int32

type context = {
  profile : profile;
  ssrc : int32;
  keying : keying;
  mutable roc : roc;
  mutable last_seq : int;
  mutable srtcp_index : int32;
}

let create ~profile ~keying ~ssrc =
  if Bytes.length keying.master_key <> 16 then
    invalid_arg "SRTP master_key must be 16 bytes";
  if Bytes.length keying.master_salt <> 14 then
    invalid_arg "SRTP master_salt must be 14 bytes";
  {
    profile;
    ssrc;
    keying;
    roc = 0l;
    last_seq = 0;
    srtcp_index = 0l;
  }

let srtp_auth_tag_len = 10

let hmac_sha1 ~key ~data =
  let mac = Digestif.SHA1.hmac_bytes ~key data in
  Bytes.of_string (Digestif.SHA1.to_raw_string mac)

let increment_counter ctr =
  let hi = Bytes.get_uint8 ctr 14 in
  let lo = Bytes.get_uint8 ctr 15 in
  let v = ((hi lsl 8) lor lo) + 1 in
  Bytes.set_uint8 ctr 14 ((v lsr 8) land 0xFF);
  Bytes.set_uint8 ctr 15 (v land 0xFF)

let aes_cm_prf ~master_key ~master_salt ~label ~index ~len =
  let counter = Bytes.make 16 '\x00' in
  Bytes.blit master_salt 0 counter 0 14;
  let index_buf = Bytes.create 6 in
  write_uint48_be index_buf 0 index;
  Bytes.set_uint8 counter 10 ((Bytes.get_uint8 counter 10) lxor (label land 0xFF));
  for i = 0 to 5 do
    let pos = 10 + i in
    Bytes.set_uint8 counter pos
      ((Bytes.get_uint8 counter pos) lxor (Bytes.get_uint8 index_buf i))
  done;
  let key = Mirage_crypto.AES.ECB.of_secret (Bytes.to_string master_key) in
  let rec loop remaining acc =
    if remaining <= 0 then
      Bytes.concat Bytes.empty (List.rev acc)
    else begin
      let out = Mirage_crypto.AES.ECB.encrypt ~key (Bytes.to_string counter) in
      increment_counter counter;
      loop (remaining - 16) (Bytes.of_string out :: acc)
    end
  in
  let stream = loop len [] in
  Bytes.sub stream 0 len

let derive_keys keying =
  let master_key = keying.master_key in
  let master_salt = keying.master_salt in
  let enc_key = aes_cm_prf ~master_key ~master_salt ~label:0x00 ~index:0L ~len:16 in
  let auth_key = aes_cm_prf ~master_key ~master_salt ~label:0x01 ~index:0L ~len:20 in
  let salt_key = aes_cm_prf ~master_key ~master_salt ~label:0x02 ~index:0L ~len:14 in
  (enc_key, auth_key, salt_key)

let build_iv ~salt_key ~ssrc ~roc ~seq =
  let iv = Bytes.make 16 '\x00' in
  Bytes.blit salt_key 0 iv 0 14;
  let ssrc_be = Bytes.create 4 in
  write_uint32_be ssrc_be 0 ssrc;
  let roc_be = Bytes.create 4 in
  write_uint32_be roc_be 0 roc;
  let seq_be = Bytes.create 2 in
  write_uint16_be seq_be 0 seq;
  for i = 0 to 3 do
    Bytes.set_uint8 iv (4 + i)
      ((Bytes.get_uint8 iv (4 + i)) lxor (Bytes.get_uint8 ssrc_be i))
  done;
  for i = 0 to 3 do
    Bytes.set_uint8 iv (10 + i)
      ((Bytes.get_uint8 iv (10 + i)) lxor (Bytes.get_uint8 roc_be i))
  done;
  Bytes.set_uint8 iv 14 ((Bytes.get_uint8 iv 14) lxor (Bytes.get_uint8 seq_be 0));
  Bytes.set_uint8 iv 15 ((Bytes.get_uint8 iv 15) lxor (Bytes.get_uint8 seq_be 1));
  iv

let aes_ctr ~key ~iv ~data =
  let key = Mirage_crypto.AES.CTR.of_secret (Bytes.to_string key) in
  let ctr = Mirage_crypto.AES.CTR.ctr_of_octets (Bytes.to_string iv) in
  let data = Bytes.to_string data in
  Bytes.of_string (Mirage_crypto.AES.CTR.encrypt ~key ~ctr data)

let update_roc ctx seq =
  if seq < ctx.last_seq && (ctx.last_seq - seq) > 0x8000 then
    ctx.roc <- Int32.add ctx.roc 1l;
  ctx.last_seq <- seq

let protect_rtp ctx ~rtp =
  if Bytes.length rtp < 12 then
    Error "SRTP: RTP packet too short"
  else
    let (enc_key, auth_key, salt_key) = derive_keys ctx.keying in
    let pkt_ssrc = read_uint32_be rtp 8 in
    if pkt_ssrc <> ctx.ssrc then
      Error "SRTP: SSRC mismatch"
    else
    let seq = read_uint16_be rtp 2 in
    update_roc ctx seq;
    let roc = ctx.roc in
    let payload_offset =
      let cc = Bytes.get_uint8 rtp 0 land 0x0F in
      let x = (Bytes.get_uint8 rtp 0 land 0x10) <> 0 in
      let base = 12 + (cc * 4) in
      if not x then base
      else
        let ext_len = read_uint16_be rtp (base + 2) in
        base + 4 + (ext_len * 4)
    in
    if payload_offset > Bytes.length rtp then
      Error "SRTP: RTP header length invalid"
    else
      let payload = Bytes.sub rtp payload_offset (Bytes.length rtp - payload_offset) in
      let iv = build_iv ~salt_key ~ssrc:ctx.ssrc ~roc ~seq in
      let encrypted = aes_ctr ~key:enc_key ~iv ~data:payload in
      let out = Bytes.copy rtp in
      Bytes.blit encrypted 0 out payload_offset (Bytes.length encrypted);
      let roc_be = Bytes.create 4 in
      write_uint32_be roc_be 0 roc;
      let auth_input = Bytes.cat out roc_be in
      let tag = hmac_sha1 ~key:(Bytes.to_string auth_key) ~data:auth_input in
      let tag = Bytes.sub tag 0 srtp_auth_tag_len in
      Ok (Bytes.cat out tag)

let unprotect_rtp ctx ~rtp =
  if Bytes.length rtp < 12 + srtp_auth_tag_len then
    Error "SRTP: RTP packet too short"
  else
    let (enc_key, auth_key, salt_key) = derive_keys ctx.keying in
    let auth_tag_off = Bytes.length rtp - srtp_auth_tag_len in
    let packet = Bytes.sub rtp 0 auth_tag_off in
    let recv_tag = Bytes.sub rtp auth_tag_off srtp_auth_tag_len in
    let pkt_ssrc = read_uint32_be packet 8 in
    if pkt_ssrc <> ctx.ssrc then
      Error "SRTP: SSRC mismatch"
    else
    let seq = read_uint16_be packet 2 in
    update_roc ctx seq;
    let roc = ctx.roc in
    let roc_be = Bytes.create 4 in
    write_uint32_be roc_be 0 roc;
    let auth_input = Bytes.cat packet roc_be in
    let expected = hmac_sha1 ~key:(Bytes.to_string auth_key) ~data:auth_input in
    let expected = Bytes.sub expected 0 srtp_auth_tag_len in
    if not (Bytes.equal expected recv_tag) then
      Error "SRTP: authentication failed"
    else
      let payload_offset =
        let cc = Bytes.get_uint8 packet 0 land 0x0F in
        let x = (Bytes.get_uint8 packet 0 land 0x10) <> 0 in
        let base = 12 + (cc * 4) in
        if not x then base
        else
          let ext_len = read_uint16_be packet (base + 2) in
          base + 4 + (ext_len * 4)
      in
      if payload_offset > Bytes.length packet then
        Error "SRTP: RTP header length invalid"
      else
        let payload = Bytes.sub packet payload_offset (Bytes.length packet - payload_offset) in
        let iv = build_iv ~salt_key ~ssrc:ctx.ssrc ~roc ~seq in
        let decrypted = aes_ctr ~key:enc_key ~iv ~data:payload in
        let out = Bytes.copy packet in
        Bytes.blit decrypted 0 out payload_offset (Bytes.length decrypted);
        Ok out

let protect_rtcp ctx ~rtcp =
  if Bytes.length rtcp < 8 then
    Error "SRTCP: RTCP packet too short"
  else
    let (_enc_key, auth_key, _salt_key) = derive_keys ctx.keying in
    ctx.srtcp_index <- Int32.add ctx.srtcp_index 1l;
    let index_be = Bytes.create 4 in
    write_uint32_be index_be 0 ctx.srtcp_index;
    let data = Bytes.cat rtcp index_be in
    let tag = hmac_sha1 ~key:(Bytes.to_string auth_key) ~data in
    let tag = Bytes.sub tag 0 srtp_auth_tag_len in
    Ok (Bytes.cat data tag)

let unprotect_rtcp ctx ~rtcp =
  if Bytes.length rtcp < 8 + 4 + srtp_auth_tag_len then
    Error "SRTCP: RTCP packet too short"
  else
    let (_enc_key, auth_key, _salt_key) = derive_keys ctx.keying in
    let tag_off = Bytes.length rtcp - srtp_auth_tag_len in
    let data = Bytes.sub rtcp 0 tag_off in
    let recv_tag = Bytes.sub rtcp tag_off srtp_auth_tag_len in
    let expected = hmac_sha1 ~key:(Bytes.to_string auth_key) ~data in
    let expected = Bytes.sub expected 0 srtp_auth_tag_len in
    if not (Bytes.equal expected recv_tag) then
      Error "SRTCP: authentication failed"
    else
      (* Drop SRTCP index (last 4 bytes before tag) *)
      let payload_len = Bytes.length data - 4 in
      Ok (Bytes.sub data 0 payload_len)
