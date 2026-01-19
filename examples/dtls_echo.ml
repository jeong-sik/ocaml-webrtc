(** Example: DTLS Echo Server/Client

    This example demonstrates DTLS handshake and encrypted communication
    between a client and server in-process (simulated network).

    The example shows:
    - DTLS client/server handshake
    - Cookie exchange for DoS protection
    - Encrypted data transfer
    - Key export for SRTP (optional)

    Usage:
      dune exec examples/dtls_echo.exe
*)

open Webrtc

(** Simulated network - messages are exchanged through a queue *)
let client_to_server = Queue.create ()
let server_to_client = Queue.create ()

let send_to_server data = Queue.push data client_to_server
let send_to_client data = Queue.push data server_to_client
let recv_from_server () =
  if Queue.is_empty server_to_client then None
  else Some (Queue.pop server_to_client)
let recv_from_client () =
  if Queue.is_empty client_to_server then None
  else Some (Queue.pop client_to_server)

(** Process DTLS records and send responses *)
let process_server_records records =
  List.iter (fun r -> send_to_client r) records

let process_client_records records =
  List.iter (fun r -> send_to_server r) records

(** Custom I/O ops for the example *)
let make_io_ops () =
  {
    Dtls.send = (fun _ -> 0);  (* We handle record sending manually *)
    recv = (fun _ -> Bytes.empty);
    now = Unix.gettimeofday;
    random = (fun n ->
      (* Use Mirage_crypto_rng for secure random *)
      Bytes.of_string (Mirage_crypto_rng.generate n)
    );
    set_timer = (fun _ -> ());
    cancel_timer = (fun () -> ());
  }

(** Run DTLS handshake between client and server *)
let run_handshake () =
  Printf.printf "=== DTLS Echo Example ===\n\n";

  let io_ops = make_io_ops () in

  (* Create client and server *)
  let client = Dtls.create Dtls.default_client_config in
  let server = Dtls.create Dtls.default_server_config in

  Printf.printf "1. Client sends ClientHello...\n";

  (* Client: Start handshake - sends ClientHello *)
  Dtls.run_with_io ~ops:io_ops (fun () ->
    match Dtls.start_handshake client with
    | Ok records ->
      Printf.printf "   Sent %d record(s)\n" (List.length records);
      process_client_records records
    | Error e ->
      Printf.eprintf "   Error: %s\n" e;
      exit 1
  );

  Printf.printf "2. Server processes ClientHello...\n";

  (* Server: Process ClientHello, send HelloVerifyRequest with cookie *)
  Dtls.run_with_io ~ops:io_ops (fun () ->
    match recv_from_client () with
    | Some data ->
      let client_addr = ("127.0.0.1", 5000) in
      begin match Dtls.handle_record_as_server server data ~client_addr with
      | Ok (records, _app_data) ->
        Printf.printf "   Server state: %s\n" (Format.asprintf "%a" Dtls.pp_state (Dtls.get_state server));
        Printf.printf "   Sent %d record(s) (HelloVerifyRequest)\n" (List.length records);
        process_server_records records
      | Error e ->
        Printf.eprintf "   Error: %s\n" e;
        exit 1
      end
    | None ->
      Printf.eprintf "   No data from client!\n";
      exit 1
  );

  Printf.printf "3. Client processes HelloVerifyRequest...\n";

  (* Client: Process HelloVerifyRequest, resend ClientHello with cookie *)
  Dtls.run_with_io ~ops:io_ops (fun () ->
    match recv_from_server () with
    | Some data ->
      begin match Dtls.handle_record client data with
      | Ok (records, _app_data) ->
        Printf.printf "   Client state: %s\n" (Format.asprintf "%a" Dtls.pp_state (Dtls.get_state client));
        Printf.printf "   Sent %d record(s) (ClientHello with cookie)\n" (List.length records);
        process_client_records records
      | Error e ->
        Printf.eprintf "   Error: %s\n" e;
        exit 1
      end
    | None ->
      Printf.eprintf "   No data from server!\n";
      exit 1
  );

  Printf.printf "4. Server processes ClientHello with cookie...\n";

  (* Server: Process ClientHello with cookie, send server flight *)
  Dtls.run_with_io ~ops:io_ops (fun () ->
    match recv_from_client () with
    | Some data ->
      let client_addr = ("127.0.0.1", 5000) in
      begin match Dtls.handle_record_as_server server data ~client_addr with
      | Ok (records, _app_data) ->
        Printf.printf "   Server state: %s\n" (Format.asprintf "%a" Dtls.pp_state (Dtls.get_state server));
        Printf.printf "   Sent %d record(s) (ServerHello...ServerHelloDone)\n" (List.length records);
        process_server_records records
      | Error e ->
        Printf.eprintf "   Error: %s\n" e;
        exit 1
      end
    | None ->
      Printf.eprintf "   No data from client!\n";
      exit 1
  );

  (* Continue handshake - process remaining messages *)
  let rec process_remaining iterations =
    if iterations > 10 then begin
      Printf.eprintf "Too many iterations!\n";
      exit 1
    end;

    let client_done = Dtls.is_established client in
    let server_done = Dtls.is_established server in

    if client_done && server_done then
      Printf.printf "\n✅ Handshake complete!\n\n"
    else begin
      (* Client processes server messages *)
      Dtls.run_with_io ~ops:io_ops (fun () ->
        match recv_from_server () with
        | Some data ->
          begin match Dtls.handle_record client data with
          | Ok (records, _) ->
            if records <> [] then begin
              Printf.printf "   Client -> Server: %d record(s)\n" (List.length records);
              process_client_records records
            end
          | Error e ->
            Printf.eprintf "   Client error: %s\n" e
          end
        | None -> ()
      );

      (* Server processes client messages *)
      Dtls.run_with_io ~ops:io_ops (fun () ->
        match recv_from_client () with
        | Some data ->
          let client_addr = ("127.0.0.1", 5000) in
          begin match Dtls.handle_record_as_server server data ~client_addr with
          | Ok (records, _) ->
            if records <> [] then begin
              Printf.printf "   Server -> Client: %d record(s)\n" (List.length records);
              process_server_records records
            end
          | Error e ->
            Printf.eprintf "   Server error: %s\n" e
          end
        | None -> ()
      );

      process_remaining (iterations + 1)
    end
  in

  Printf.printf "5. Completing handshake...\n";
  process_remaining 0;

  (* Show negotiated cipher suite *)
  begin match Dtls.get_cipher_suite client with
  | Some cs ->
    Printf.printf "Cipher suite: %s\n"
      (match cs with
       | Dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 -> "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256"
       | Dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 -> "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
       | Dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 -> "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384"
       | Dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 -> "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
  | None ->
    Printf.printf "No cipher suite negotiated\n"
  end;

  (* Test encrypted data transfer *)
  Printf.printf "\n=== Testing Encrypted Echo ===\n\n";

  let test_message = Bytes.of_string "Hello, DTLS World!" in
  Printf.printf "Client sends: %s\n" (Bytes.to_string test_message);

  (* Client encrypts and sends *)
  begin match Dtls.encrypt client test_message with
  | Ok encrypted ->
    Printf.printf "Encrypted: %d bytes\n" (Bytes.length encrypted);

    (* Server decrypts *)
    begin match Dtls.decrypt server encrypted with
    | Ok decrypted ->
      Printf.printf "Server received: %s\n" (Bytes.to_string decrypted);

      (* Server echoes back *)
      begin match Dtls.encrypt server decrypted with
      | Ok echo_encrypted ->
        Printf.printf "Server echoes: %d encrypted bytes\n" (Bytes.length echo_encrypted);

        (* Client receives echo *)
        begin match Dtls.decrypt client echo_encrypted with
        | Ok echo_decrypted ->
          Printf.printf "Client received echo: %s\n\n" (Bytes.to_string echo_decrypted);

          if Bytes.equal test_message echo_decrypted then
            Printf.printf "✅ Echo test PASSED!\n"
          else
            Printf.printf "❌ Echo test FAILED - data mismatch!\n"

        | Error e -> Printf.eprintf "Client decrypt error: %s\n" e
        end
      | Error e -> Printf.eprintf "Server encrypt error: %s\n" e
      end
    | Error e -> Printf.eprintf "Server decrypt error: %s\n" e
    end
  | Error e -> Printf.eprintf "Client encrypt error: %s\n" e
  end

let () =
  (* Initialize RNG *)
  Mirage_crypto_rng_unix.use_default ();
  run_handshake ()
