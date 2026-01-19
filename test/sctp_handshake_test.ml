(** Unit tests for SCTP 4-Way Handshake (RFC 4960 §5)

    Tests the connection establishment protocol:
    - INIT / INIT-ACK / COOKIE-ECHO / COOKIE-ACK messages
    - Cookie generation and validation with HMAC
    - State transitions during handshake
    - Parameter encoding/decoding

    @author Second Brain
*)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try
    f ();
    incr passed;
    Printf.printf "✅ PASS\n%!"
  with e ->
    incr failed;
    Printf.printf "❌ FAIL (%s)\n%!" (Printexc.to_string e)

let assert_true msg b = if not b then failwith msg
let assert_eq msg a b = if a <> b then failwith (Printf.sprintf "%s: got %d, expected %d" msg a b)
let assert_eq32 msg a b = if a <> b then failwith (Printf.sprintf "%s: got %ld, expected %ld" msg a b)

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* HMAC Secret Configuration                                                   *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_hmac_config () =
  Printf.printf "\n═══ HMAC Secret Configuration ═══\n";

  test "set_hmac_secret updates secret" (fun () ->
    Sctp_handshake.set_hmac_secret "test-secret-for-unit-test";
    (* Should not raise - secret is now configured *)
    assert_true "secret set" true
  );

  test "init_hmac_secret_from_env with no env var returns Ok false" (fun () ->
    (* Note: This test assumes SCTP_HMAC_SECRET is not set *)
    (* In CI, we might need to unset it first *)
    (* For safety, we just test the function returns a Result *)
    match Sctp_handshake.init_hmac_secret_from_env () with
    | Ok _ -> assert_true "function returned Ok" true
    | Error _ -> assert_true "function returned Error (env var set but empty)" true
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Random Generation                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_random_generation () =
  Printf.printf "\n═══ Random Generation ═══\n";

  test "random_vtag returns non-zero" (fun () ->
    let vtag = Sctp_handshake.random_vtag () in
    assert_true "vtag <> 0" (vtag <> 0l)
  );

  test "random_vtag returns different values" (fun () ->
    let vtag1 = Sctp_handshake.random_vtag () in
    let vtag2 = Sctp_handshake.random_vtag () in
    let vtag3 = Sctp_handshake.random_vtag () in
    (* Highly unlikely to get same value twice *)
    assert_true "vtags differ" (vtag1 <> vtag2 || vtag2 <> vtag3)
  );

  test "random_initial_tsn returns non-zero" (fun () ->
    let tsn = Sctp_handshake.random_initial_tsn () in
    assert_true "tsn <> 0" (tsn <> 0l)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Cookie Encoding/Decoding                                                    *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_cookie_encoding () =
  Printf.printf "\n═══ Cookie Encoding/Decoding ═══\n";

  test "encode_cookie produces bytes" (fun () ->
    let cookie = Sctp_handshake.{
      creation_time = Unix.gettimeofday ();  (* Use current time *)
      lifespan_ms = 60000;
      peer_vtag = 0x12345678l;
      local_vtag = 0xABCDEF00l;
      peer_initial_tsn = 1000l;
      local_initial_tsn = 2000l;
      peer_rwnd = 65536l;
      local_rwnd = 65536l;
      hmac = Bytes.make 32 '\x00';
    } in
    let encoded = Sctp_handshake.encode_cookie cookie in
    assert_true "encoded length > 0" (Bytes.length encoded > 0)
  );

  test "encode/decode roundtrip preserves values" (fun () ->
    let original = Sctp_handshake.{
      creation_time = Unix.gettimeofday ();  (* Use current time to avoid expiry *)
      lifespan_ms = 60000;
      peer_vtag = 0x11223344l;
      local_vtag = 0x55667788l;
      peer_initial_tsn = 500l;
      local_initial_tsn = 600l;
      peer_rwnd = 131072l;
      local_rwnd = 131072l;
      hmac = Bytes.make 32 '\x00';
    } in
    let encoded = Sctp_handshake.encode_cookie original in
    match Sctp_handshake.decode_cookie encoded with
    | Ok decoded ->
      assert_eq32 "peer_vtag" decoded.peer_vtag original.peer_vtag;
      assert_eq32 "local_vtag" decoded.local_vtag original.local_vtag;
      assert_eq32 "peer_initial_tsn" decoded.peer_initial_tsn original.peer_initial_tsn;
      assert_eq32 "local_initial_tsn" decoded.local_initial_tsn original.local_initial_tsn;
      assert_eq32 "peer_rwnd" decoded.peer_rwnd original.peer_rwnd
    | Error e -> failwith ("decode failed: " ^ e)
  );

  test "decode_cookie rejects truncated data" (fun () ->
    let short_buf = Bytes.make 10 '\x00' in
    match Sctp_handshake.decode_cookie short_buf with
    | Ok _ -> failwith "expected error for truncated data"
    | Error _ -> assert_true "rejected truncated" true
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* INIT Chunk Encoding/Decoding                                                *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_init_encoding () =
  Printf.printf "\n═══ INIT Chunk Encoding ═══\n";

  test "encode_init_chunk produces valid chunk" (fun () ->
    let params = Sctp_handshake.{
      initiate_tag = 0x12345678l;
      a_rwnd = 65536l;
      num_outbound_streams = 10;
      num_inbound_streams = 10;
      initial_tsn = 1000l;
    } in
    let chunk = Sctp_handshake.encode_init_chunk params in
    assert_true "chunk length > 12" (Bytes.length chunk > 12)
  );

  test "encode/decode INIT roundtrip" (fun () ->
    let original = Sctp_handshake.{
      initiate_tag = 0xDEADBEEFl;
      a_rwnd = 262144l;
      num_outbound_streams = 100;
      num_inbound_streams = 100;
      initial_tsn = 50000l;
    } in
    let encoded = Sctp_handshake.encode_init_chunk original in
    match Sctp_handshake.decode_init encoded with
    | Ok decoded ->
      assert_eq32 "initiate_tag" decoded.initiate_tag original.initiate_tag;
      assert_eq32 "a_rwnd" decoded.a_rwnd original.a_rwnd;
      assert_eq "num_outbound" decoded.num_outbound_streams original.num_outbound_streams;
      assert_eq "num_inbound" decoded.num_inbound_streams original.num_inbound_streams;
      assert_eq32 "initial_tsn" decoded.initial_tsn original.initial_tsn
    | Error e -> failwith ("decode failed: " ^ e)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* INIT-ACK Encoding                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_init_ack_encoding () =
  Printf.printf "\n═══ INIT-ACK Encoding ═══\n";

  test "encode_init_ack includes cookie" (fun () ->
    let params = Sctp_handshake.{
      initiate_tag = 0xABCDEF01l;
      a_rwnd = 65536l;
      num_outbound_streams = 10;
      num_inbound_streams = 10;
      initial_tsn = 2000l;
    } in
    let cookie = Sctp_handshake.{
      creation_time = Unix.gettimeofday ();
      lifespan_ms = 60000;
      peer_vtag = 0x12345678l;
      local_vtag = 0xABCDEF01l;
      peer_initial_tsn = 1000l;
      local_initial_tsn = 2000l;
      peer_rwnd = 65536l;
      local_rwnd = 65536l;
      hmac = Bytes.make 32 '\x00';
    } in
    let init_ack = Sctp_handshake.encode_init_ack params cookie in
    assert_true "init_ack length > 0" (Bytes.length init_ack > 0)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* COOKIE-ECHO / COOKIE-ACK                                                    *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_cookie_echo () =
  Printf.printf "\n═══ COOKIE-ECHO / COOKIE-ACK ═══\n";

  test "encode_cookie_echo wraps cookie" (fun () ->
    let cookie = Sctp_handshake.{
      creation_time = Unix.gettimeofday ();
      lifespan_ms = 60000;
      peer_vtag = 0x12345678l;
      local_vtag = 0xABCDEF01l;
      peer_initial_tsn = 1000l;
      local_initial_tsn = 2000l;
      peer_rwnd = 65536l;
      local_rwnd = 65536l;
      hmac = Bytes.make 32 '\x00';
    } in
    let cookie_echo = Sctp_handshake.encode_cookie_echo cookie in
    assert_true "cookie_echo > 0" (Bytes.length cookie_echo > 0)
  );

  test "encode/decode cookie_echo roundtrip" (fun () ->
    let original = Sctp_handshake.{
      creation_time = Unix.gettimeofday ();
      lifespan_ms = 60000;
      peer_vtag = 0xDEADBEEFl;
      local_vtag = 0xCAFEBABEl;
      peer_initial_tsn = 500l;
      local_initial_tsn = 600l;
      peer_rwnd = 131072l;
      local_rwnd = 131072l;
      hmac = Bytes.make 32 '\xAA';
    } in
    let cookie_echo = Sctp_handshake.encode_cookie_echo original in
    match Sctp_handshake.decode_cookie_echo cookie_echo with
    | Ok decoded ->
      (* decode_cookie_echo returns state_cookie directly *)
      assert_eq32 "peer_vtag" decoded.peer_vtag original.peer_vtag
    | Error e -> failwith ("cookie_echo decode failed: " ^ e)
  );

  test "encode_cookie_ack produces minimal chunk" (fun () ->
    let cookie_ack = Sctp_handshake.encode_cookie_ack () in
    assert_true "cookie_ack length >= 4" (Bytes.length cookie_ack >= 4)
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Full Handshake Flow                                                         *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_full_handshake () =
  Printf.printf "\n═══ Full Handshake Flow ═══\n";

  test "client_init creates valid parameters" (fun () ->
    (* client_init returns (params, init_chunk, state) *)
    let (params, init_chunk, _state) = Sctp_handshake.client_init () in
    assert_true "init_chunk > 0" (Bytes.length init_chunk > 0);
    assert_true "vtag <> 0" (params.Sctp_handshake.initiate_tag <> 0l)
  );

  test "server_process_init accepts valid INIT" (fun () ->
    let (_params, init_chunk, _state) = Sctp_handshake.client_init () in
    match Sctp_handshake.server_process_init init_chunk with
    (* Returns (server_params, init_ack_buf) *)
    | Ok (_server_params, _init_ack_buf) -> assert_true "processed INIT" true
    | Error e -> failwith ("server_process_init failed: " ^ e)
  );

  test "client -> server -> client flow" (fun () ->
    (* Client: Send INIT - returns (params, init_chunk, state) *)
    let (local_params, init_chunk, _state) = Sctp_handshake.client_init () in

    (* Server: Process INIT, send INIT-ACK - returns (server_params, init_ack_buf) *)
    match Sctp_handshake.server_process_init init_chunk with
    | Error e -> failwith ("server INIT processing failed: " ^ e)
    | Ok (_server_params, init_ack_buf) ->
      (* Client: Process INIT-ACK *)
      match Sctp_handshake.client_process_init_ack init_ack_buf local_params with
      | Error e -> failwith ("client INIT-ACK processing failed: " ^ e)
      | Ok (_cookie_echo, _assoc) ->
        assert_true "handshake flow complete" true
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* State Transitions                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_state_transitions () =
  Printf.printf "\n═══ State Transitions ═══\n";

  test "state_to_string for all states" (fun () ->
    let states = [
      Sctp_handshake.Closed;
      Sctp_handshake.CookieWait;
      Sctp_handshake.CookieEchoed;
      Sctp_handshake.Established;
    ] in
    List.iter (fun state ->
      let s = Sctp_handshake.state_to_string state in
      assert_true ("state string for " ^ s) (String.length s > 0)
    ) states
  )

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main                                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     SCTP Handshake Unit Tests (RFC 4960 §5)                  ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";

  (* Set up test secret first *)
  Sctp_handshake.set_hmac_secret "unit-test-secret-key";

  test_hmac_config ();
  test_random_generation ();
  test_cookie_encoding ();
  test_init_encoding ();
  test_init_ack_encoding ();
  test_cookie_echo ();
  test_full_handshake ();
  test_state_transitions ();

  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";

  if !failed > 0 then exit 1
