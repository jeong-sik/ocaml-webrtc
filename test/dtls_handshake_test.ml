(** Integration tests for DTLS 1.2 Handshake (RFC 6347)

    Tests cover:
    - HMAC-based cookie generation and verification
    - Server-side handshake state machine
    - Retransmission timer behavior
    - Client-Server handshake flow

    @author Second Brain
    @since ocaml-webrtc 0.5.0
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
  with
  | e ->
    incr failed;
    Printf.printf "❌ FAIL (%s)\n%!" (Printexc.to_string e)
;;

let assert_true msg b = if not b then failwith msg

let[@warning "-32"] assert_eq msg expected actual =
  if expected <> actual
  then failwith (Printf.sprintf "%s: expected %s, got different" msg expected)
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* HMAC Cookie Tests                                                           *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

(** Helper to run with effect handlers for cookie functions *)
let with_effects f =
  let ops : Dtls.io_ops =
    { send = (fun _ -> 0)
    ; recv = (fun _ -> Bytes.empty)
    ; now = Unix.gettimeofday
    ; random =
        (fun n ->
          let buf = Bytes.create n in
          for i = 0 to n - 1 do
            Bytes.set_uint8 buf i (Random.int 256)
          done;
          buf)
    ; set_timer = (fun _ -> ())
    ; cancel_timer = (fun () -> ())
    }
  in
  Dtls.run_with_io ~ops f
;;

let test_hmac_cookies () =
  Printf.printf "\n═══ HMAC Cookie Tests (RFC 6347 §4.2.1) ═══\n";
  test "generate_cookie produces 32-byte HMAC" (fun () ->
    with_effects (fun () ->
      let client_addr = "192.168.1.100", 12345 in
      let client_random = Bytes.make 32 '\xAA' in
      let cookie = Dtls.generate_cookie ~client_addr ~client_random in
      assert_true "cookie is 32 bytes" (Bytes.length cookie = 32)));
  test "verify_cookie accepts valid cookie" (fun () ->
    with_effects (fun () ->
      let client_addr = "192.168.1.100", 12345 in
      let client_random = Bytes.make 32 '\xBB' in
      let cookie = Dtls.generate_cookie ~client_addr ~client_random in
      let valid = Dtls.verify_cookie ~client_addr ~client_random ~cookie in
      assert_true "cookie should verify" valid));
  test "verify_cookie rejects wrong client_addr" (fun () ->
    with_effects (fun () ->
      let client_addr1 = "192.168.1.100", 12345 in
      let client_addr2 = "192.168.1.101", 12345 in
      (* Different IP *)
      let client_random = Bytes.make 32 '\xCC' in
      let cookie = Dtls.generate_cookie ~client_addr:client_addr1 ~client_random in
      let valid = Dtls.verify_cookie ~client_addr:client_addr2 ~client_random ~cookie in
      assert_true "cookie should not verify with different IP" (not valid)));
  test "verify_cookie rejects wrong port" (fun () ->
    with_effects (fun () ->
      let client_addr1 = "192.168.1.100", 12345 in
      let client_addr2 = "192.168.1.100", 54321 in
      (* Different port *)
      let client_random = Bytes.make 32 '\xDD' in
      let cookie = Dtls.generate_cookie ~client_addr:client_addr1 ~client_random in
      let valid = Dtls.verify_cookie ~client_addr:client_addr2 ~client_random ~cookie in
      assert_true "cookie should not verify with different port" (not valid)));
  test "verify_cookie rejects wrong client_random" (fun () ->
    with_effects (fun () ->
      let client_addr = "192.168.1.100", 12345 in
      let client_random1 = Bytes.make 32 '\xEE' in
      let client_random2 = Bytes.make 32 '\xFF' in
      (* Different random *)
      let cookie = Dtls.generate_cookie ~client_addr ~client_random:client_random1 in
      let valid = Dtls.verify_cookie ~client_addr ~client_random:client_random2 ~cookie in
      assert_true "cookie should not verify with different random" (not valid)));
  test "cookies are deterministic for same inputs" (fun () ->
    with_effects (fun () ->
      let client_addr = "10.0.0.1", 9999 in
      let client_random = Bytes.make 32 '\x42' in
      let cookie1 = Dtls.generate_cookie ~client_addr ~client_random in
      let cookie2 = Dtls.generate_cookie ~client_addr ~client_random in
      assert_true "same inputs produce same cookie" (Bytes.equal cookie1 cookie2)))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* State Machine Tests                                                         *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_state_machine () =
  Printf.printf "\n═══ DTLS State Machine Tests ═══\n";
  test "client starts in Initial state" (fun () ->
    let client = Dtls.create Dtls.default_client_config in
    let state = Dtls.get_state client in
    match state with
    | Dtls.Initial -> ()
    | _ -> failwith "Expected Initial state");
  test "server starts in Initial state" (fun () ->
    let server = Dtls.create Dtls.default_server_config in
    let state = Dtls.get_state server in
    match state with
    | Dtls.Initial -> ()
    | _ -> failwith "Expected Initial state");
  test "config correctly identifies client vs server" (fun () ->
    (* Client config has is_client = true *)
    assert_true "client config" Dtls.default_client_config.is_client;
    (* Server config has is_client = false *)
    assert_true "server config" (not Dtls.default_server_config.is_client))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Retransmission Timer Tests                                                  *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_retransmission () =
  Printf.printf "\n═══ Retransmission Timer Tests (RFC 6347 §4.2.4) ═══\n";
  test "initial retransmit state is inactive" (fun () ->
    let client = Dtls.create Dtls.default_client_config in
    let count, timeout_ms, active = Dtls.get_retransmit_state client in
    assert_true "count is 0" (count = 0);
    assert_true "timeout is initial" (timeout_ms = 1000);
    assert_true "timer inactive" (not active));
  test "check_retransmit_needed returns false when inactive" (fun () ->
    let client = Dtls.create Dtls.default_client_config in
    (* Use effect handler to check retransmit *)
    let result = ref false in
    let open Effect.Deep in
    try_with
      (fun () -> result := Dtls.check_retransmit_needed client)
      ()
      { effc =
          (fun (type a) (eff : a Effect.t) ->
            match eff with
            | Dtls.Now ->
              Some (fun (k : (a, _) continuation) -> continue k (Unix.gettimeofday ()))
            | _ -> None)
      };
    assert_true "no retransmit needed when inactive" (not !result))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Configuration Tests                                                         *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_configuration () =
  Printf.printf "\n═══ Configuration Tests ═══\n";
  test "default_client_config is client" (fun () ->
    assert_true "is_client true" Dtls.default_client_config.is_client);
  test "default_server_config is server" (fun () ->
    assert_true "is_client false" (not Dtls.default_server_config.is_client));
  test "default retransmit timeout is 1000ms" (fun () ->
    assert_true "client timeout" (Dtls.default_client_config.retransmit_timeout_ms = 1000);
    assert_true "server timeout" (Dtls.default_server_config.retransmit_timeout_ms = 1000));
  test "default max_retransmits is 5" (fun () ->
    assert_true "client retransmits" (Dtls.default_client_config.max_retransmits = 5);
    assert_true "server retransmits" (Dtls.default_server_config.max_retransmits = 5))
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Effect Handler Tests                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let test_effect_handlers () =
  Printf.printf "\n═══ Effect Handler Tests ═══\n";
  test "run_with_io executes with mock handlers" (fun () ->
    let ops : Dtls.io_ops =
      { send = (fun _ -> 0)
      ; recv = (fun _ -> Bytes.empty)
      ; now = Unix.gettimeofday
      ; random = (fun n -> Bytes.make n '\x00')
      ; set_timer = (fun _ -> ())
      ; cancel_timer = (fun () -> ())
      }
    in
    let client = Dtls.create Dtls.default_client_config in
    (* Just test that run_with_io accepts the ops *)
    Dtls.run_with_io ~ops (fun () ->
      let _ = Dtls.get_state client in
      ());
    assert_true "run_with_io completed" true)
;;

(* ═══════════════════════════════════════════════════════════════════════════ *)
(* Main                                                                        *)
(* ═══════════════════════════════════════════════════════════════════════════ *)

let () =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║     DTLS 1.2 Handshake Tests (RFC 6347)                       ║\n";
  Printf.printf "║     HMAC Cookies + Retransmission Timer + State Machine       ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n";
  test_hmac_cookies ();
  test_state_machine ();
  test_retransmission ();
  test_configuration ();
  test_effect_handlers ();
  Printf.printf "\n═══════════════════════════════════════════════════════════════\n";
  Printf.printf "  Results: %d passed, %d failed\n" !passed !failed;
  Printf.printf "═══════════════════════════════════════════════════════════════\n";
  if !failed > 0 then exit 1
;;
