(** WebRTC DataChannel Example

    Full WebRTC DataChannel stack demonstration:
    - ICE (RFC 8445) - NAT Traversal
    - DTLS (RFC 6347) - Encryption
    - SCTP (RFC 4960) - Reliable Transport
    - DCEP (draft-ietf-rtcweb-data-protocol) - DataChannel Establishment

    This example shows the complete flow for creating a WebRTC DataChannel
    between two peers using the pure OCaml implementation.

    Usage:
      dune exec ./examples/datachannel.exe

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

open Webrtc

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║       WebRTC DataChannel Demo (Full Stack)                   ║\n";
  Printf.printf "╠═══════════════════════════════════════════════════════════════╣\n";
  Printf.printf "║  ICE (RFC 8445)  → NAT Traversal                             ║\n";
  Printf.printf "║  DTLS (RFC 6347) → Encryption                                ║\n";
  Printf.printf "║  SCTP (RFC 4960) → Reliable Transport                        ║\n";
  Printf.printf "║  DCEP            → DataChannel Protocol                      ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  (* === Phase 1: ICE Candidate Gathering === *)
  Printf.printf "═══ Phase 1: ICE Candidate Gathering ═══\n\n";
  let ice_config =
    { Ice.default_config with role = Ice.Controlling; aggressive_nomination = true }
  in
  let agent = Ice.create ice_config in
  (* Get local credentials for SDP *)
  let ufrag, pwd = Ice.get_local_credentials agent in
  Printf.printf "Local ICE Credentials:\n";
  Printf.printf "  a=ice-ufrag:%s\n" ufrag;
  Printf.printf "  a=ice-pwd:%s\n\n" pwd;
  (* Gather candidates *)
  Printf.printf "Gathering ICE candidates...\n";
  let _ = Lwt_main.run (Ice.gather_candidates agent) in
  let candidates = Ice.get_local_candidates agent in
  Printf.printf "Found %d candidates:\n" (List.length candidates);
  List.iteri
    (fun i c ->
       Printf.printf
         "  [%d] %s %s:%d (priority: %d)\n"
         i
         (Ice.string_of_candidate_type c.Ice.cand_type)
         c.address
         c.port
         c.priority)
    candidates;
  Printf.printf "\n";
  (* === Phase 2: DTLS Configuration === *)
  Printf.printf "═══ Phase 2: DTLS Configuration ═══\n\n";
  let dtls_config = Dtls.default_client_config in
  let dtls = Dtls.create dtls_config in
  Printf.printf "DTLS Configuration:\n";
  Printf.printf "  Role: Client (initiator)\n";
  Printf.printf "  Retransmit timeout: %dms\n" dtls_config.retransmit_timeout_ms;
  Printf.printf "  Max retransmits: %d\n\n" dtls_config.max_retransmits;
  Format.printf "DTLS State: %a@.@." Dtls.pp_state (Dtls.get_state dtls);
  (* === Phase 3: SCTP Association === *)
  Printf.printf "═══ Phase 3: SCTP Configuration ═══\n\n";
  let sctp_config = Sctp.default_config in
  let sctp = Sctp_core.create ~config:sctp_config () in
  Printf.printf "SCTP Configuration:\n";
  Printf.printf "  MTU: %d bytes\n" sctp_config.Sctp.mtu;
  Printf.printf
    "  Streams: outbound=%d, inbound=%d\n"
    sctp_config.Sctp.num_outbound_streams
    sctp_config.Sctp.num_inbound_streams;
  Printf.printf "  Receiver window: %d bytes\n\n" sctp_config.Sctp.a_rwnd;
  let stats = Sctp_core.get_stats sctp in
  Printf.printf "SCTP Initial Stats:\n";
  Printf.printf "  Messages sent: %d\n" stats.Sctp_core.messages_sent;
  Printf.printf "  Messages received: %d\n" stats.Sctp_core.messages_recv;
  Printf.printf "  SACKs sent: %d\n\n" stats.Sctp_core.sacks_sent;
  (* === Phase 4: DCEP DataChannel Setup === *)
  Printf.printf "═══ Phase 4: DCEP DataChannel Setup ═══\n\n";
  let dcep = Dcep.create ~is_client:true in
  Printf.printf "DCEP ready for DataChannel creation\n\n";
  (* Create a test channel *)
  let stream_id, open_msg =
    Dcep.open_channel dcep ~label:"test-channel" ~protocol:"binary" ()
  in
  Printf.printf "Created DataChannel:\n";
  Printf.printf "  Stream ID: %d\n" stream_id;
  Printf.printf "  Label: test-channel\n";
  Printf.printf "  Protocol: binary\n";
  Printf.printf "  DCEP OPEN message: %d bytes\n\n" (Bytes.length open_msg);
  (* === Phase 5: Full Stack Integration === *)
  Printf.printf "═══ Phase 5: ICE-DTLS-SCTP Transport ═══\n\n";
  let transport_config =
    { Ice_dtls_transport.default_config with
      is_controlling = true
    ; mtu = 1200
    ; sctp_port = 5000
    }
  in
  let transport = Ice_dtls_transport.create ~config:transport_config () in
  Printf.printf "ICE-DTLS-SCTP Transport created:\n";
  Printf.printf
    "  State: %s\n"
    (Ice_dtls_transport.string_of_state (Ice_dtls_transport.get_state transport));
  Printf.printf "  MTU: %d\n" transport_config.mtu;
  Printf.printf "  SCTP Port: %d\n\n" transport_config.sctp_port;
  (* Set up callbacks *)
  Ice_dtls_transport.on_local_candidate transport (fun c ->
    Printf.printf "  → ICE Candidate: %s:%d\n" c.Ice.address c.port);
  Ice_dtls_transport.on_state_change transport (fun state ->
    Printf.printf "  → State changed: %s\n" (Ice_dtls_transport.string_of_state state));
  Ice_dtls_transport.on_channel_open transport (fun sid label ->
    Printf.printf "  → DataChannel opened: [%d] %s\n" sid label);
  Ice_dtls_transport.on_channel_data transport (fun sid data ->
    Printf.printf "  → Data on channel %d: %s\n" sid (Bytes.to_string data));
  Printf.printf "Callbacks registered\n\n";
  (* === Summary === *)
  Printf.printf "═══════════════════════════════════════════════════════════════\n";
  Printf.printf "                    WebRTC Stack Summary\n";
  Printf.printf "═══════════════════════════════════════════════════════════════\n\n";
  Printf.printf "┌─────────────────────────────────────────────────────────────┐\n";
  Printf.printf "│ Layer          │ Module                │ Status            │\n";
  Printf.printf "├─────────────────────────────────────────────────────────────┤\n";
  Printf.printf "│ Application    │ (your code)           │ Ready             │\n";
  Printf.printf "│ DCEP           │ Dcep                  │ ✓ Initialized     │\n";
  Printf.printf "│ SCTP           │ Sctp_core             │ ✓ Initialized     │\n";
  Printf.printf "│ DTLS           │ Dtls                  │ ✓ Initialized     │\n";
  Printf.printf
    "│ ICE            │ Ice                   │ ✓ %d candidates   │\n"
    (List.length candidates);
  Printf.printf "│ UDP            │ Unix sockets          │ ✓ Available       │\n";
  Printf.printf "└─────────────────────────────────────────────────────────────┘\n\n";
  Printf.printf "To test peer-to-peer connection:\n";
  Printf.printf "1. Run this demo on two machines\n";
  Printf.printf "2. Exchange ICE candidates and credentials via signaling\n";
  Printf.printf "3. Call Ice.add_remote_candidate with peer's candidates\n";
  Printf.printf "4. Call Ice.set_remote_credentials with peer's ufrag/pwd\n";
  Printf.printf "5. ICE will establish connectivity through NAT\n";
  Printf.printf "6. DTLS handshake secures the connection\n";
  Printf.printf "7. SCTP provides reliable delivery\n";
  Printf.printf "8. DataChannels are ready for use!\n"
;;
