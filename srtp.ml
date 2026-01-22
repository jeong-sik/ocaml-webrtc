(** SRTP (RFC 3711, RFC 7714) - AES-CM + HMAC-SHA1 and AES-GCM AEAD primitives. *)

open Webrtc_common

type profile =
  | SRTP_AES128_CM_HMAC_SHA1_80
  | SRTP_AES128_CM_HMAC_SHA1_32
  | SRTP_NULL_HMAC_SHA1_80
  | SRTP_NULL_HMAC_SHA1_32
  | SRTP_AEAD_AES_128_GCM
  | SRTP_AEAD_AES_256_GCM

type master = {
  key : bytes;
  salt : bytes;
}

type session_keys = {
  srtp_encryption_key : bytes;
  srtp_auth_key : bytes;
  srtp_salt_key : bytes;
  srtcp_encryption_key : bytes;
  srtcp_auth_key : bytes;
  srtcp_salt_key : bytes;
}

type params = {
  cipher_key_len : int;
  cipher_salt_len : int;
  auth_key_len : int;
  srtp_auth_tag_len : int;
  srtcp_auth_tag_len : int;
}

let params_of_profile = function
  | SRTP_AES128_CM_HMAC_SHA1_80 ->
    { cipher_key_len = 16; cipher_salt_len = 14; auth_key_len = 20;
      srtp_auth_tag_len = 10; srtcp_auth_tag_len = 10; }
  | SRTP_AES128_CM_HMAC_SHA1_32 ->
    { cipher_key_len = 16; cipher_salt_len = 14; auth_key_len = 20;
      srtp_auth_tag_len = 4; srtcp_auth_tag_len = 10; }
  | SRTP_NULL_HMAC_SHA1_80 ->
    { cipher_key_len = 0; cipher_salt_len = 0; auth_key_len = 20;
      srtp_auth_tag_len = 10; srtcp_auth_tag_len = 10; }
  | SRTP_NULL_HMAC_SHA1_32 ->
    { cipher_key_len = 0; cipher_salt_len = 0; auth_key_len = 20;
      srtp_auth_tag_len = 4; srtcp_auth_tag_len = 10; }
  | SRTP_AEAD_AES_128_GCM ->
    (* RFC 7714: 16-byte key, 12-byte salt, no separate auth key, 16-byte tag *)
    { cipher_key_len = 16; cipher_salt_len = 12; auth_key_len = 0;
      srtp_auth_tag_len = 16; srtcp_auth_tag_len = 16; }
  | SRTP_AEAD_AES_256_GCM ->
    (* RFC 7714: 32-byte key, 12-byte salt, no separate auth key, 16-byte tag *)
    { cipher_key_len = 32; cipher_salt_len = 12; auth_key_len = 0;
      srtp_auth_tag_len = 16; srtcp_auth_tag_len = 16; }

let is_aead_profile = function
  | SRTP_AEAD_AES_128_GCM | SRTP_AEAD_AES_256_GCM -> true
  | _ -> false

let xor_into buf off value =
  let b = Bytes.get_uint8 buf off in
  Bytes.set_uint8 buf off (b lxor value)

let xor_uint32_be buf off value =
  for i = 0 to 3 do
    let shift = (3 - i) * 8 in
    let byte = Int32.(to_int (shift_right_logical value shift)) land 0xFF in
    xor_into buf (off + i) byte
  done

let xor_uint48_be buf off value =
  for i = 0 to 5 do
    let shift = (5 - i) * 8 in
    let byte = Int64.(to_int (shift_right_logical value shift)) land 0xFF in
    xor_into buf (off + i) byte
  done

let int64_to_uint48_be value =
  let buf = Bytes.create 6 in
  for i = 0 to 5 do
    let shift = (5 - i) * 8 in
    let byte = Int64.(to_int (shift_right_logical value shift)) land 0xFF in
    Bytes.set_uint8 buf i byte
  done;
  buf

let derive_key ~master ~label ~key_derivation_rate ~index ~out_len =
  if out_len < 0 then
    Error "Invalid output length"
  else if out_len = 0 then
    Ok Bytes.empty
  else if index < 0L || index > 0xFFFFFFFFFFFFL then
    Error "Index must be 48-bit"
  else if Bytes.length master.key <> 16
       && Bytes.length master.key <> 24
       && Bytes.length master.key <> 32 then
    Error "Master key length must be 16/24/32 bytes"
  else if Bytes.length master.salt <> 14 then
    Error "Master salt length must be 14 bytes"
  else
    let r =
      if key_derivation_rate = 0L then 0L
      else Int64.div index key_derivation_rate
    in
    let key_id = Bytes.create 7 in
    Bytes.set_uint8 key_id 0 (label land 0xFF);
    let r_bytes = int64_to_uint48_be r in
    Bytes.blit r_bytes 0 key_id 1 6;

    (* Right-align key_id (7 bytes) with master_salt (14 bytes). *)
    let key_id_full = Bytes.make 14 '\x00' in
    Bytes.blit key_id 0 key_id_full 7 7;

    let x = Bytes.create 14 in
    for i = 0 to 13 do
      let v = Bytes.get_uint8 master.salt i lxor Bytes.get_uint8 key_id_full i in
      Bytes.set_uint8 x i v
    done;

    (* IV = x * 2^16 => append 2 zero bytes. *)
    let iv = Bytes.create 16 in
    Bytes.blit x 0 iv 0 14;
    Bytes.set_uint8 iv 14 0;
    Bytes.set_uint8 iv 15 0;

    let key = Mirage_crypto.AES.CTR.of_secret (Bytes.to_string master.key) in
    let ctr = Mirage_crypto.AES.CTR.ctr_of_octets (Bytes.to_string iv) in
    let stream = Mirage_crypto.AES.CTR.stream ~key ~ctr out_len in
    Ok (Bytes.of_string stream)

let derive_session_keys ~profile ~master ~key_derivation_rate ~index =
  let params = params_of_profile profile in
  let derive label len =
    derive_key ~master ~label ~key_derivation_rate ~index ~out_len:len
  in
  match derive 0x00 params.cipher_key_len,
        derive 0x01 params.auth_key_len,
        derive 0x02 params.cipher_salt_len,
        derive 0x03 params.cipher_key_len,
        derive 0x04 params.auth_key_len,
        derive 0x05 params.cipher_salt_len with
  | Ok srtp_key, Ok srtp_auth, Ok srtp_salt,
    Ok srtcp_key, Ok srtcp_auth, Ok srtcp_salt ->
    Ok {
      srtp_encryption_key = srtp_key;
      srtp_auth_key = srtp_auth;
      srtp_salt_key = srtp_salt;
      srtcp_encryption_key = srtcp_key;
      srtcp_auth_key = srtcp_auth;
      srtcp_salt_key = srtcp_salt;
    }
  | Error e, _, _, _, _, _
  | _, Error e, _, _, _, _
  | _, _, Error e, _, _, _
  | _, _, _, Error e, _, _
  | _, _, _, _, Error e, _
  | _, _, _, _, _, Error e ->
    Error e

let srtp_iv ~salt ~ssrc ~index =
  if Bytes.length salt <> 14 then
    Error "SRTP salt must be 14 bytes"
  else if index < 0L || index > 0xFFFFFFFFFFFFL then
    Error "SRTP index must be 48-bit"
  else
    let iv = Bytes.create 16 in
    Bytes.blit salt 0 iv 0 14;
    Bytes.set_uint8 iv 14 0;
    Bytes.set_uint8 iv 15 0;
    xor_uint32_be iv 4 ssrc;
    xor_uint48_be iv 8 index;
    Ok iv

let aes_cm_crypt ~key ~iv ~payload =
  if Bytes.length iv <> 16 then
    Error "IV must be 16 bytes"
  else if Bytes.length key <> 16
       && Bytes.length key <> 24
       && Bytes.length key <> 32 then
    Error "AES-CM key must be 16/24/32 bytes"
  else if Bytes.length payload = 0 then
    Ok Bytes.empty
  else
    let ctr = Mirage_crypto.AES.CTR.ctr_of_octets (Bytes.to_string iv) in
    let aes_key = Mirage_crypto.AES.CTR.of_secret (Bytes.to_string key) in
    let ciphertext = Mirage_crypto.AES.CTR.encrypt ~key:aes_key ~ctr (Bytes.to_string payload) in
    Ok (Bytes.of_string ciphertext)

let hmac_sha1 ~key ~data =
  let module H = Digestif.SHA1 in
  let raw = H.hmac_string ~key:(Bytes.to_string key) (Bytes.to_string data)
            |> H.to_raw_string in
  Bytes.of_string raw

let srtp_auth_tag ~auth_key ~packet ~roc ~tag_len =
  let roc_bytes = Bytes.create 4 in
  Bytes.set_int32_be roc_bytes 0 roc;
  let msg = Bytes.cat packet roc_bytes in
  let full = hmac_sha1 ~key:auth_key ~data:msg in
  Bytes.sub full 0 tag_len

let srtcp_auth_tag ~auth_key ~packet ~tag_len =
  let full = hmac_sha1 ~key:auth_key ~data:packet in
  Bytes.sub full 0 tag_len

let constant_time_eq a b =
  if Bytes.length a <> Bytes.length b then
    false
  else
    let diff = ref 0 in
    for i = 0 to Bytes.length a - 1 do
      diff := !diff lor (Bytes.get_uint8 a i lxor Bytes.get_uint8 b i)
    done;
    !diff = 0

let srtp_index ~roc ~seq =
  if seq < 0 || seq > 0xFFFF then
    Error "Sequence must be 16-bit"
  else
    let roc64 = Int64.logand (Int64.of_int32 roc) 0xFFFFFFFFL in
    let idx = Int64.logor (Int64.shift_left roc64 16) (Int64.of_int seq) in
    Ok idx

(* ═══════════════════════════════════════════════════════════════════════════
   AES-GCM AEAD (RFC 7714)
   ═══════════════════════════════════════════════════════════════════════════ *)

let gcm_tag_len = 16  (* RFC 7714: 16-byte authentication tag *)
let gcm_iv_len = 12   (* RFC 7714: 12-byte IV/nonce *)

(** XOR 12-byte value into buffer at offset *)
let xor_bytes12 dst off src =
  for i = 0 to 11 do
    let d = Bytes.get_uint8 dst (off + i) in
    let s = Bytes.get_uint8 src i in
    Bytes.set_uint8 dst (off + i) (d lxor s)
  done

(** Build SRTP AES-GCM IV (RFC 7714 Section 8.1)
    IV = salt XOR (0x00 || 0x00 || SSRC || 0x00 || 0x00 || index)
    where index is 48-bit (ROC || SEQ) *)
let srtp_gcm_iv ~salt ~ssrc ~index =
  if Bytes.length salt <> 12 then
    Error "GCM salt must be 12 bytes"
  else if index < 0L || index > 0xFFFFFFFFFFFFL then
    Error "SRTP index must be 48-bit"
  else
    (* Build: 0x00 0x00 SSRC[4] 0x00 0x00 index[6] = 12 bytes *)
    let iv = Bytes.make 12 '\x00' in
    (* SSRC at offset 2-5 *)
    write_uint32_be iv 2 ssrc;
    (* index (48-bit) at offset 6-11 *)
    for i = 0 to 5 do
      let shift = (5 - i) * 8 in
      let byte = Int64.(to_int (shift_right_logical index shift)) land 0xFF in
      Bytes.set_uint8 iv (6 + i) byte
    done;
    (* XOR with salt *)
    for i = 0 to 11 do
      let v = Bytes.get_uint8 iv i lxor Bytes.get_uint8 salt i in
      Bytes.set_uint8 iv i v
    done;
    Ok iv

(** Build SRTCP AES-GCM IV (RFC 7714 Section 9.1)
    IV = salt XOR (0x00 || 0x00 || SSRC || 0x00 || 0x00 || 0x00 || 0x00 || SRTCP_index)
    where SRTCP_index is 32-bit (with E-bit cleared) *)
let srtcp_gcm_iv ~salt ~ssrc ~index =
  if Bytes.length salt <> 12 then
    Error "GCM salt must be 12 bytes"
  else
    let idx32 = Int32.logand index 0x7FFFFFFFl in
    (* Build: 0x00 0x00 SSRC[4] 0x00 0x00 0x00 0x00 index[4] = 12 bytes *)
    let iv = Bytes.make 12 '\x00' in
    (* SSRC at offset 2-5 *)
    write_uint32_be iv 2 ssrc;
    (* index (32-bit) at offset 8-11 *)
    write_uint32_be iv 8 idx32;
    (* XOR with salt *)
    for i = 0 to 11 do
      let v = Bytes.get_uint8 iv i lxor Bytes.get_uint8 salt i in
      Bytes.set_uint8 iv i v
    done;
    Ok iv

(** AES-GCM encrypt (RFC 7714) *)
let aes_gcm_encrypt ~key ~iv ~aad ~plaintext =
  if Bytes.length iv <> 12 then
    Error "AES-GCM IV must be 12 bytes"
  else if Bytes.length key <> 16 && Bytes.length key <> 32 then
    Error "AES-GCM key must be 16 or 32 bytes"
  else
    let key_str = Bytes.to_string key in
    let iv_str = Bytes.to_string iv in
    let aad_str = Bytes.to_string aad in
    let plaintext_str = Bytes.to_string plaintext in
    let cipher_key = Mirage_crypto.AES.GCM.of_secret key_str in
    let ciphertext_and_tag = Mirage_crypto.AES.GCM.authenticate_encrypt
      ~key:cipher_key
      ~nonce:iv_str
      ~adata:aad_str
      plaintext_str
    in
    Ok (Bytes.of_string ciphertext_and_tag)

(** AES-GCM decrypt (RFC 7714) *)
let aes_gcm_decrypt ~key ~iv ~aad ~ciphertext_and_tag =
  if Bytes.length iv <> 12 then
    Error "AES-GCM IV must be 12 bytes"
  else if Bytes.length key <> 16 && Bytes.length key <> 32 then
    Error "AES-GCM key must be 16 or 32 bytes"
  else if Bytes.length ciphertext_and_tag < gcm_tag_len then
    Error "Ciphertext too short for GCM tag"
  else
    let key_str = Bytes.to_string key in
    let iv_str = Bytes.to_string iv in
    let aad_str = Bytes.to_string aad in
    let ciphertext_str = Bytes.to_string ciphertext_and_tag in
    let cipher_key = Mirage_crypto.AES.GCM.of_secret key_str in
    match Mirage_crypto.AES.GCM.authenticate_decrypt
      ~key:cipher_key
      ~nonce:iv_str
      ~adata:aad_str
      ciphertext_str
    with
    | Some plaintext -> Ok (Bytes.of_string plaintext)
    | None -> Error "AES-GCM authentication failed"

(* ═══════════════════════════════════════════════════════════════════════════
   GCM-specific protect/unprotect (called from main functions when AEAD)
   ═══════════════════════════════════════════════════════════════════════════ *)

(** Protect RTP with AES-GCM (RFC 7714 Section 8)
    AAD = RTP header (first 12 bytes minimum, excluding payload) *)
let protect_rtp_gcm ~keys ~roc ~packet =
  match Rtp.decode packet with
  | Error e -> Error e
  | Ok { Rtp.header; payload } ->
    let index_result = srtp_index ~roc ~seq:header.sequence in
    (match index_result with
     | Error e -> Error e
     | Ok index ->
       match srtp_gcm_iv ~salt:keys.srtp_salt_key ~ssrc:header.ssrc ~index with
       | Error e -> Error e
       | Ok iv ->
         (* AAD = RTP header (excluding payload) *)
         let header_len = Bytes.length packet - Bytes.length payload in
         let aad = Bytes.sub packet 0 header_len in
         match aes_gcm_encrypt ~key:keys.srtp_encryption_key ~iv ~aad ~plaintext:payload with
         | Error e -> Error e
         | Ok ciphertext_and_tag ->
           (* Output = RTP header || encrypted payload || tag *)
           Ok (Bytes.cat aad ciphertext_and_tag))

(** Unprotect SRTP with AES-GCM (RFC 7714 Section 8) *)
let unprotect_rtp_gcm ~keys ~roc ~packet =
  if Bytes.length packet <= 12 + gcm_tag_len then
    Error "SRTP-GCM packet too short"
  else
    (* Decode header to get SSRC and sequence *)
    let header_result = Rtp.decode_header packet in
    match header_result with
    | Error e -> Error e
    | Ok (header, header_len) ->
      let index_result = srtp_index ~roc ~seq:header.Rtp.sequence in
      (match index_result with
       | Error e -> Error e
       | Ok index ->
         match srtp_gcm_iv ~salt:keys.srtp_salt_key ~ssrc:header.Rtp.ssrc ~index with
         | Error e -> Error e
         | Ok iv ->
           let aad = Bytes.sub packet 0 header_len in
           let ciphertext_and_tag = Bytes.sub packet header_len (Bytes.length packet - header_len) in
           match aes_gcm_decrypt ~key:keys.srtp_encryption_key ~iv ~aad ~ciphertext_and_tag with
           | Error e -> Error e
           | Ok plaintext ->
             (* Reconstruct decrypted RTP packet *)
             Ok (Bytes.cat aad plaintext))

(** Protect RTCP with AES-GCM (RFC 7714 Section 9) *)
let protect_rtcp_gcm ~keys ~index ~packet =
  if Bytes.length packet < 8 then
    Error "RTCP packet too short"
  else
    let idx32 = Int32.logand index 0x7FFFFFFFl in
    let ssrc = read_uint32_be packet 4 in
    match srtcp_gcm_iv ~salt:keys.srtcp_salt_key ~ssrc ~index:idx32 with
    | Error e -> Error e
    | Ok iv ->
      (* AAD = RTCP header (first 8 bytes) || E-bit || SRTCP index *)
      let e_index = Int32.logor idx32 0x80000000l in (* E=1 for encrypted *)
      let e_index_bytes = Bytes.create 4 in
      write_uint32_be e_index_bytes 0 e_index;
      let aad = Bytes.cat (Bytes.sub packet 0 8) e_index_bytes in
      let payload = Bytes.sub packet 8 (Bytes.length packet - 8) in
      match aes_gcm_encrypt ~key:keys.srtcp_encryption_key ~iv ~aad ~plaintext:payload with
      | Error e -> Error e
      | Ok ciphertext_and_tag ->
        (* Output = RTCP header || encrypted payload || tag || E-bit || index *)
        let result = Bytes.concat Bytes.empty [
          Bytes.sub packet 0 8;  (* RTCP header *)
          ciphertext_and_tag;     (* ciphertext + tag *)
          e_index_bytes;          (* E-bit || SRTCP index *)
        ] in
        Ok result

(** Unprotect SRTCP with AES-GCM (RFC 7714 Section 9) *)
let unprotect_rtcp_gcm ~keys ~packet =
  (* Minimum: 8 (header) + 16 (tag) + 4 (index) = 28 bytes *)
  if Bytes.length packet < 28 then
    Error "SRTCP-GCM packet too short"
  else
    (* E-bit + index is last 4 bytes *)
    let index_off = Bytes.length packet - 4 in
    let e_index_bytes = Bytes.sub packet index_off 4 in
    let raw_index = Bytes.get_int32_be e_index_bytes 0 in
    let idx32 = Int32.logand raw_index 0x7FFFFFFFl in
    let ssrc = read_uint32_be packet 4 in
    match srtcp_gcm_iv ~salt:keys.srtcp_salt_key ~ssrc ~index:idx32 with
    | Error e -> Error e
    | Ok iv ->
      (* AAD = RTCP header (first 8 bytes) || E-bit || SRTCP index *)
      let aad = Bytes.cat (Bytes.sub packet 0 8) e_index_bytes in
      (* ciphertext+tag is between header and index *)
      let ciphertext_and_tag = Bytes.sub packet 8 (index_off - 8) in
      match aes_gcm_decrypt ~key:keys.srtcp_encryption_key ~iv ~aad ~ciphertext_and_tag with
      | Error e -> Error e
      | Ok plaintext ->
        (* Reconstruct decrypted RTCP packet *)
        let result = Bytes.cat (Bytes.sub packet 0 8) plaintext in
        Ok (result, idx32)

(* ═══════════════════════════════════════════════════════════════════════════
   Main protect/unprotect functions (dispatch to GCM or AES-CM based on profile)
   ═══════════════════════════════════════════════════════════════════════════ *)

let protect_rtp ~profile ~keys ~roc ~packet =
  (* AEAD profiles use GCM-specific path *)
  if is_aead_profile profile then
    protect_rtp_gcm ~keys ~roc ~packet
  else
    let params = params_of_profile profile in
    let tag_len = params.srtp_auth_tag_len in
    match Rtp.decode packet with
    | Error e -> Error e
    | Ok { Rtp.header; payload } ->
      let index_result = srtp_index ~roc ~seq:header.sequence in
      (match index_result with
       | Error e -> Error e
       | Ok index ->
         let payload_result =
           if params.cipher_key_len = 0 then
             Ok payload
           else
             match srtp_iv ~salt:keys.srtp_salt_key ~ssrc:header.ssrc ~index with
             | Error e -> Error e
             | Ok iv ->
               aes_cm_crypt ~key:keys.srtp_encryption_key ~iv ~payload
         in
         match payload_result with
         | Error e -> Error e
         | Ok encrypted_payload ->
           (match Rtp.encode header ~payload:encrypted_payload with
            | Error e -> Error e
            | Ok encrypted_packet ->
              let tag = srtp_auth_tag
                ~auth_key:keys.srtp_auth_key
                ~packet:encrypted_packet
                ~roc
                ~tag_len
              in
              Ok (Bytes.cat encrypted_packet tag)))

let unprotect_rtp ~profile ~keys ~roc ~packet =
  (* AEAD profiles use GCM-specific path *)
  if is_aead_profile profile then
    unprotect_rtp_gcm ~keys ~roc ~packet
  else
    let params = params_of_profile profile in
    let tag_len = params.srtp_auth_tag_len in
    if Bytes.length packet <= tag_len then
      Error "SRTP packet too short"
    else
      let rtp_len = Bytes.length packet - tag_len in
      let rtp_packet = Bytes.sub packet 0 rtp_len in
      let tag = Bytes.sub packet rtp_len tag_len in
      let expected = srtp_auth_tag
        ~auth_key:keys.srtp_auth_key
        ~packet:rtp_packet
        ~roc
        ~tag_len
      in
      if not (constant_time_eq tag expected) then
        Error "SRTP authentication failed"
      else
        match Rtp.decode rtp_packet with
        | Error e -> Error e
        | Ok { Rtp.header; payload } ->
          let index_result = srtp_index ~roc ~seq:header.sequence in
          (match index_result with
           | Error e -> Error e
           | Ok index ->
             let payload_result =
               if params.cipher_key_len = 0 then
                 Ok payload
               else
                 match srtp_iv ~salt:keys.srtp_salt_key ~ssrc:header.ssrc ~index with
                 | Error e -> Error e
                 | Ok iv ->
                   aes_cm_crypt ~key:keys.srtp_encryption_key ~iv ~payload
             in
             match payload_result with
             | Error e -> Error e
             | Ok decrypted_payload ->
               (match Rtp.encode header ~payload:decrypted_payload with
                | Error e -> Error e
                | Ok decrypted_packet -> Ok decrypted_packet))

let protect_rtcp ~profile ~keys ~index ~encrypt ~packet =
  (* AEAD profiles use GCM-specific path (always encrypted for GCM) *)
  if is_aead_profile profile then
    protect_rtcp_gcm ~keys ~index ~packet
  else
    let params = params_of_profile profile in
    let tag_len = params.srtcp_auth_tag_len in
    let idx32 = Int32.logand index 0x7FFFFFFFl in
    if Int32.compare index 0l < 0 || Int32.compare index 0x7FFFFFFFl > 0 then
      Error "SRTCP index must be 31-bit"
    else if Bytes.length packet < 8 then
      Error "RTCP packet too short"
    else
      let ssrc = read_uint32_be packet 4 in
      let encrypted_result =
        if (not encrypt) || params.cipher_key_len = 0 then
          Ok packet
        else
          let payload_len = Bytes.length packet - 8 in
          let payload = Bytes.sub packet 8 payload_len in
          let index64 = Int64.logand (Int64.of_int32 idx32) 0x7FFFFFFFL in
          match srtp_iv ~salt:keys.srtcp_salt_key ~ssrc ~index:index64 with
          | Error e -> Error e
          | Ok iv ->
            (match aes_cm_crypt ~key:keys.srtcp_encryption_key ~iv ~payload with
             | Error e -> Error e
             | Ok encrypted_payload ->
               let out = Bytes.copy packet in
               Bytes.blit encrypted_payload 0 out 8 payload_len;
               Ok out)
      in
      match encrypted_result with
      | Error e -> Error e
      | Ok encrypted_packet ->
        let index_field =
          let v = if encrypt then Int32.logor idx32 0x80000000l else idx32 in
          let b = Bytes.create 4 in
          write_uint32_be b 0 v;
          b
        in
        let auth_input = Bytes.cat encrypted_packet index_field in
        let tag = srtcp_auth_tag
          ~auth_key:keys.srtcp_auth_key
          ~packet:auth_input
          ~tag_len
        in
        Ok (Bytes.concat Bytes.empty [encrypted_packet; index_field; tag])

let unprotect_rtcp ~profile ~keys ~packet =
  (* AEAD profiles use GCM-specific path *)
  if is_aead_profile profile then
    unprotect_rtcp_gcm ~keys ~packet
  else
    let params = params_of_profile profile in
    let tag_len = params.srtcp_auth_tag_len in
    if Bytes.length packet < 12 + tag_len then
      Error "SRTCP packet too short"
    else
      let index_off = Bytes.length packet - tag_len - 4 in
      let base = Bytes.sub packet 0 index_off in
      let index_field = Bytes.sub packet index_off 4 in
      let tag = Bytes.sub packet (index_off + 4) tag_len in
      let auth_input = Bytes.cat base index_field in
      let expected = srtcp_auth_tag
        ~auth_key:keys.srtcp_auth_key
        ~packet:auth_input
        ~tag_len
      in
      if not (constant_time_eq tag expected) then
        Error "SRTCP authentication failed"
      else
        let raw_index = Bytes.get_int32_be index_field 0 in
        let encrypt = (Bytes.get_uint8 index_field 0 land 0x80) <> 0 in
        let idx32 = Int32.logand raw_index 0x7FFFFFFFl in
        if Bytes.length base < 8 then
          Error "RTCP packet too short"
        else if (not encrypt) || params.cipher_key_len = 0 then
          Ok (base, idx32)
        else
          let ssrc = read_uint32_be base 4 in
          let payload_len = Bytes.length base - 8 in
          let payload = Bytes.sub base 8 payload_len in
          let index64 = Int64.logand (Int64.of_int32 idx32) 0x7FFFFFFFL in
          match srtp_iv ~salt:keys.srtcp_salt_key ~ssrc ~index:index64 with
          | Error e -> Error e
          | Ok iv ->
            (match aes_cm_crypt ~key:keys.srtcp_encryption_key ~iv ~payload with
             | Error e -> Error e
             | Ok decrypted_payload ->
               let out = Bytes.copy base in
               Bytes.blit decrypted_payload 0 out 8 payload_len;
               Ok (out, idx32))
