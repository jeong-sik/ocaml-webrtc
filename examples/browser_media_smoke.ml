(** Browser interop smoke: DTLS-SRTP + RTP/RTCP (RR/SDES). *)

open Webrtc

let read_all_stdin () =
  let buf = Buffer.create 4096 in
  (try
     while true do
       let line = input_line stdin in
       Buffer.add_string buf line;
       Buffer.add_char buf '\n'
     done
   with
   | End_of_file -> ());
  Buffer.contents buf
;;

let read_file path =
  let ic = open_in_bin path in
  let len = in_channel_length ic in
  let buf = really_input_string ic len in
  close_in ic;
  buf
;;

let load_pem ~env ~path ~label =
  match Sys.getenv_opt env, path with
  | Some v, _ when String.trim v <> "" -> v
  | _, Some p -> read_file p
  | _ -> failwith (Printf.sprintf "%s missing (set %s or pass --%s)" label env label)
;;

let hex_colon raw =
  let hex = "0123456789ABCDEF" in
  let buf = Buffer.create (String.length raw * 3) in
  String.iteri
    (fun i ch ->
       if i > 0 then Buffer.add_char buf ':';
       let v = Char.code ch in
       Buffer.add_char buf hex.[v lsr 4];
       Buffer.add_char buf hex.[v land 0xF])
    raw;
  Buffer.contents buf
;;

let fingerprint_of_pem pem =
  match X509.Certificate.decode_pem_multiple pem with
  | Error (`Msg msg) -> failwith ("certificate decode failed: " ^ msg)
  | Ok [] -> failwith "certificate chain is empty"
  | Ok (cert :: _) ->
    let raw = X509.Certificate.fingerprint `SHA256 cert in
    hex_colon raw
;;

let is_dtls_packet data =
  Bytes.length data >= 3
  &&
  let ctype = Bytes.get_uint8 data 0 in
  let vmaj = Bytes.get_uint8 data 1 in
  let vmin = Bytes.get_uint8 data 2 in
  ctype >= 20 && ctype <= 23 && vmaj = 254 && vmin = 253
;;

let is_rtp_or_rtcp data = Bytes.length data > 0 && Bytes.get_uint8 data 0 land 0xC0 = 0x80
let is_rtcp data = Bytes.length data > 1 && Bytes.get_uint8 data 1 >= 192
let advance_rtcp_index idx = Int32.logand (Int32.succ idx) 0x7FFFFFFFl

let () =
  Random.self_init ();
  let listen_ip = ref "0.0.0.0" in
  let listen_port = ref 5004 in
  let advertise_ip = ref None in
  let cert_path = ref None in
  let key_path = ref None in
  let payload_type = ref 111 in
  let cname = ref "ocaml-webrtc" in
  let ssrc_override = ref None in
  let specs =
    [ "--listen-ip", Arg.Set_string listen_ip, "Listen IP (default 0.0.0.0)"
    ; "--listen-port", Arg.Set_int listen_port, "Listen port (default 5004)"
    ; ( "--public-ip"
      , Arg.String (fun v -> advertise_ip := Some v)
      , "Public IP for SDP candidate" )
    ; "--cert", Arg.String (fun v -> cert_path := Some v), "Certificate PEM path"
    ; "--key", Arg.String (fun v -> key_path := Some v), "Private key PEM path"
    ; "--payload-type", Arg.Set_int payload_type, "RTP payload type (default 111)"
    ; "--cname", Arg.Set_string cname, "RTCP SDES CNAME"
    ; ( "--ssrc"
      , Arg.Int (fun v -> ssrc_override := Some (Int32.of_int v))
      , "Local SSRC (int)" )
    ]
  in
  Arg.parse specs (fun _ -> ()) "browser_media_smoke";
  let cert_pem = load_pem ~env:"WEBRTC_CERT_PEM" ~path:!cert_path ~label:"cert" in
  let key_pem = load_pem ~env:"WEBRTC_KEY_PEM" ~path:!key_path ~label:"key" in
  let public_ip =
    match !advertise_ip with
    | Some ip -> ip
    | None ->
      if !listen_ip = "0.0.0.0"
      then failwith "--public-ip required when listen-ip is 0.0.0.0"
      else !listen_ip
  in
  let local_ufrag = Ice.generate_ufrag () in
  let local_pwd = Ice.generate_pwd () in
  let fingerprint =
    { Sdp.hash_func = "sha-256"; fingerprint = fingerprint_of_pem cert_pem }
  in
  Printf.printf "Paste browser offer SDP, then Ctrl-D:\n%!";
  let offer_sdp = read_all_stdin () in
  let offer =
    match Sdp.parse offer_sdp with
    | Ok s -> s
    | Error e -> failwith ("SDP parse failed: " ^ e)
  in
  let media =
    match Sdp.find_media_by_type offer Sdp.Audio with
    | Some m -> m
    | None ->
      (match offer.media with
       | m :: _ -> m
       | [] -> failwith "offer has no media sections")
  in
  let _remote_ice =
    match Sdp.resolve_ice_credentials offer media with
    | Some creds -> creds
    | None -> "", ""
  in
  let answer =
    Sdp.create_answer ~offer ~ice_ufrag:local_ufrag ~ice_pwd:local_pwd ~fingerprint
  in
  let answer =
    { answer with
      ice_lite = true
    ; origin = { answer.origin with unicast_address = public_ip }
    ; media =
        List.map
          (fun m ->
             let open Sdp in
             { m with setup = Some "passive" })
          answer.media
    }
  in
  let candidate =
    { Ice.foundation =
        Ice.generate_foundation ~candidate_type:Ice.Host ~base_address:public_ip ()
    ; component = 1
    ; transport = Ice.UDP
    ; priority =
        Ice.calculate_priority ~candidate_type:Ice.Host ~local_pref:65535 ~component:1
    ; address = public_ip
    ; port = !listen_port
    ; cand_type = Ice.Host
    ; base_address = None
    ; base_port = None
    ; related_address = None
    ; related_port = None
    ; extensions = [ "generation", "0" ]
    }
  in
  let answer = Sdp.add_candidate_from_ice answer candidate ~media_index:0 in
  Printf.printf "\n----- ANSWER SDP -----\n%s\n%!" (Sdp.to_string answer);
  let dtls_config =
    { Dtls.default_server_config with
      certificate = Some cert_pem
    ; private_key = Some key_pem
    ; srtp_profiles = [ Srtp.SRTP_AES128_CM_HMAC_SHA1_80 ]
    ; verify_peer = false
    }
  in
  let dtls = Dtls.create dtls_config in
  let local_ssrc =
    match !ssrc_override with
    | Some v -> v
    | None -> Int32.of_int (Random.bits ())
  in
  let media_state = ref None in
  let local_keys = ref None in
  let remote_keys = ref None in
  let peer_addr = ref None in
  let last_seq = ref None in
  let remote_ssrc = ref None in
  let rtcp_index = ref 0l in
  let rtcp_sent = ref false in
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_of_string !listen_ip, !listen_port));
  let buf = Bytes.create 2048 in
  let set_peer addr = if !peer_addr = None then peer_addr := Some addr in
  let send_bytes data =
    match !peer_addr with
    | None -> ()
    | Some addr -> ignore (Unix.sendto sock data 0 (Bytes.length data) [] addr)
  in
  let send_dtls records = List.iter send_bytes records in
  let send_rtcp_report () =
    match !local_keys, !remote_ssrc with
    | Some keys, Some r_ssrc ->
      let report_block =
        { Rtcp.ssrc = r_ssrc
        ; fraction_lost = 0
        ; cumulative_lost = 0l
        ; highest_seq = Int32.of_int (Option.value ~default:0 !last_seq)
        ; jitter = 0l
        ; last_sr = 0l
        ; dlsr = 0l
        }
      in
      let rr =
        Rtcp.Receiver_report { ssrc = local_ssrc; report_blocks = [ report_block ] }
      in
      let sdes =
        Rtcp.Source_description
          [ { ssrc = local_ssrc; items = [ { item_type = Rtcp.CNAME; value = !cname } ] }
          ]
      in
      let compound = Bytes.concat Bytes.empty [ Rtcp.encode rr; Rtcp.encode sdes ] in
      (match
         Srtp.protect_rtcp
           ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
           ~keys
           ~index:!rtcp_index
           ~encrypt:true
           ~packet:compound
       with
       | Ok protected ->
         rtcp_index := advance_rtcp_index !rtcp_index;
         send_bytes protected
       | Error e -> Log.error "[RTCP] protect failed: %s" e)
    | _ -> ()
  in
  let handle_stun msg addr =
    match msg.Stun.msg_class, msg.Stun.msg_method with
    | Stun.Request, Stun.Binding ->
      let has_integrity =
        List.exists
          (fun attr -> attr.Stun.attr_type = Stun.MESSAGE_INTEGRITY)
          msg.attributes
      in
      let integrity_ok =
        (not has_integrity) || Stun.verify_integrity msg ~key:local_pwd
      in
      if integrity_ok
      then (
        let ip, port =
          match addr with
          | Unix.ADDR_INET (a, p) -> Unix.string_of_inet_addr a, p
          | _ -> "0.0.0.0", 0
        in
        let mapped_address = { Stun.family = Stun.IPv4; port; ip } in
        let response =
          Stun.create_binding_response ~transaction_id:msg.transaction_id ~mapped_address
          |> Stun.add_message_integrity ~key:local_pwd
          |> Stun.add_fingerprint
        in
        let bytes = Stun.encode response in
        peer_addr := Some addr;
        ignore (Unix.sendto sock bytes 0 (Bytes.length bytes) [] addr))
    | _ -> ()
  in
  let handle_dtls data addr =
    set_peer addr;
    let ip, port =
      match addr with
      | Unix.ADDR_INET (a, p) -> Unix.string_of_inet_addr a, p
      | _ -> "0.0.0.0", 0
    in
    match Dtls.handle_record_as_server dtls data ~client_addr:(ip, port) with
    | Ok (records, _app) ->
      send_dtls records;
      if Dtls.is_established dtls && !media_state = None
      then (
        match
          Dtls_srtp.session_keys_of_dtls
            ~dtls
            ~role:Dtls_srtp.Server
            ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
            ()
        with
        | Ok (local, remote) ->
          local_keys := Some local;
          remote_keys := Some remote;
          media_state
          := Some
               (Media_transport.create
                  ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80
                  ~local_keys:local
                  ~remote_keys:remote
                  ~ssrc:local_ssrc
                  ~payload_type:!payload_type);
          Printf.printf "[DTLS] established, SRTP ready\n%!"
        | Error e -> Log.error "[DTLS] SRTP key export failed: %s" e)
    | Error e -> Log.error "[DTLS] error: %s" e
  in
  let handle_rtp data =
    match !media_state with
    | None -> ()
    | Some media ->
      (match Media_transport.unprotect_rtp media ~packet:data with
       | Ok pkt ->
         remote_ssrc := Some pkt.Rtp.header.ssrc;
         last_seq := Some pkt.Rtp.header.sequence;
         if not !rtcp_sent
         then (
           send_rtcp_report ();
           rtcp_sent := true)
       | Error e -> Log.error "[RTP] unprotect failed: %s" e)
  in
  let handle_rtcp data =
    match !remote_keys with
    | None -> ()
    | Some keys ->
      (match
         Srtp.unprotect_rtcp ~profile:Srtp.SRTP_AES128_CM_HMAC_SHA1_80 ~keys ~packet:data
       with
       | Ok (plaintext, _index) ->
         (match Rtcp.decode_compound plaintext with
          | Ok _ -> ()
          | Error e -> Log.error "[RTCP] decode failed: %s" e);
         if not !rtcp_sent
         then (
           send_rtcp_report ();
           rtcp_sent := true)
       | Error e -> Log.error "[RTCP] unprotect failed: %s" e)
  in
  Printf.printf "Listening on %s:%d\n%!" !listen_ip !listen_port;
  while true do
    let len, addr = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
    let data = Bytes.sub buf 0 len in
    if Stun.is_stun_message data
    then (
      match Stun.decode data with
      | Ok msg -> handle_stun msg addr
      | Error _ -> ())
    else if is_dtls_packet data || not (Dtls.is_established dtls)
    then handle_dtls data addr
    else if is_rtp_or_rtcp data
    then if is_rtcp data then handle_rtcp data else handle_rtp data
    else ()
  done
;;
