(** Example: WebRTC DataChannel

    This example demonstrates the full WebRTC DataChannel stack:
    - ICE candidate gathering
    - SDP offer creation
    - SCTP DataChannel setup

    Usage:
      dune exec examples/datachannel.exe

    Note: This is a simulation showing API usage.
    Real P2P communication requires signaling server exchange.
*)

open Webrtc

let () =
  (* Initialize RNG (new API) *)
  Mirage_crypto_rng_unix.use_default ();

  Printf.printf "=== WebRTC DataChannel Example ===\n\n";

  (* Create ICE agent *)
  let ice_config = {
    Ice.default_config with
    ice_servers = [
      { Ice.urls = ["stun:stun.l.google.com:19302"];
        username = None;
        credential = None };
    ];
    role = Ice.Controlling;
  } in
  let ice = Ice.create ice_config in

  Printf.printf "1. Creating ICE agent...\n";
  let (ufrag, pwd) = Ice.get_local_credentials ice in
  Printf.printf "   Local credentials:\n";
  Printf.printf "   ufrag: %s\n" ufrag;
  Printf.printf "   pwd: %s\n\n" pwd;

  (* Gather candidates *)
  Printf.printf "2. Gathering ICE candidates...\n";
  Lwt_main.run (Ice.gather_candidates ice);

  let candidates = Ice.get_local_candidates ice in
  Printf.printf "   Found %d candidate(s)\n\n" (List.length candidates);

  (* Print candidates *)
  List.iteri (fun i c ->
    Printf.printf "   [%d] %s %s:%d (%s)\n"
      i
      (Ice.string_of_transport c.Ice.transport)
      c.Ice.address
      c.Ice.port
      (Ice.string_of_candidate_type c.Ice.cand_type)
  ) candidates;

  (* Create DTLS context *)
  Printf.printf "\n3. Creating DTLS context...\n";
  let _dtls = Dtls.create Dtls.default_client_config in
  (* In production, fingerprint would be derived from the DTLS certificate *)
  let fingerprint : Sdp.fingerprint = {
    hash_func = "sha-256";
    fingerprint = "AB:CD:EF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC";
  } in
  Printf.printf "   DTLS fingerprint: %s\n" fingerprint.fingerprint;

  (* Create SDP offer for DataChannel *)
  Printf.printf "\n4. Creating SDP offer...\n";
  let offer = Sdp.create_datachannel_offer
    ~ice_ufrag:ufrag
    ~ice_pwd:pwd
    ~fingerprint
    ~sctp_port:5000
  in
  let offer_sdp = Sdp.to_string offer in
  Printf.printf "   SDP offer created (%d bytes)\n" (String.length offer_sdp);

  (* Print a portion of the SDP *)
  Printf.printf "\n   --- SDP Offer Preview ---\n";
  String.split_on_char '\n' offer_sdp
  |> List.filteri (fun i _ -> i < 10)
  |> List.iter (fun line -> Printf.printf "   %s\n" line);
  Printf.printf "   ...\n";

  (* Create SCTP association *)
  Printf.printf "\n5. Creating SCTP association...\n";
  let sctp = Sctp.create Sctp.default_config in
  Printf.printf "   SCTP state: %s\n"
    (Sctp.string_of_state (Sctp.get_state sctp));

  (* Open a DataChannel *)
  Printf.printf "\n6. Opening DataChannel...\n";
  let dcep_open : Dcep.data_channel_open = {
    channel_type = Dcep.Reliable;
    priority = 256;
    label = "test-channel";
    protocol = "";
  } in
  let dcep_bytes = Dcep.encode_open dcep_open in
  Printf.printf "   DCEP OPEN message created (%d bytes)\n" (Bytes.length dcep_bytes);
  Printf.printf "   Channel label: %s\n" dcep_open.label;
  Printf.printf "   Channel type: %s\n"
    (Dcep.string_of_channel_type dcep_open.channel_type);

  (* Summary *)
  Printf.printf "\n=== Example Complete ===\n";
  Printf.printf "In production, you would:\n";
  Printf.printf "  1. Exchange SDP via signaling server\n";
  Printf.printf "  2. Exchange ICE candidates\n";
  Printf.printf "  3. Run ICE connectivity checks\n";
  Printf.printf "  4. Complete DTLS handshake\n";
  Printf.printf "  5. Establish SCTP association\n";
  Printf.printf "  6. Send/receive data through DataChannels\n"
