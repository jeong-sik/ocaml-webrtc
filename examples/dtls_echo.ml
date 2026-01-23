(** DTLS Echo Server/Client Example

    RFC 6347 - Datagram Transport Layer Security Version 1.2

    This example demonstrates:
    - Creating DTLS server and client
    - DTLS handshake with cookie validation
    - Encrypted data exchange
    - Effect-based I/O abstraction

    Usage:
      Server: dune exec ./examples/dtls_echo.exe -- server 12345
      Client: dune exec ./examples/dtls_echo.exe -- client 127.0.0.1 12345

    @author Second Brain
    @since ocaml-webrtc 0.5.0
*)

open Webrtc

let run_server port =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║           DTLS Echo Server (RFC 6347)                        ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  Printf.printf "➤ Starting server on port %d...\n%!" port;
  (* Create UDP socket *)
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.setsockopt sock Unix.SO_REUSEADDR true;
  Unix.bind sock (Unix.ADDR_INET (Unix.inet_addr_any, port));
  Printf.printf "➤ Waiting for DTLS ClientHello...\n%!";
  (* Create DTLS server context *)
  let dtls = Dtls.create Dtls.default_server_config in
  (* Receive buffer *)
  let buf = Bytes.create 65536 in
  (* Simple I/O ops for testing *)
  let client_addr = ref ("0.0.0.0", 0) in
  let ops : Dtls.io_ops =
    { send =
        (fun data ->
          let ip, p = !client_addr in
          let addr = Unix.ADDR_INET (Unix.inet_addr_of_string ip, p) in
          Unix.sendto sock data 0 (Bytes.length data) [] addr)
    ; recv = (fun _ -> Bytes.empty)
    ; now = Unix.gettimeofday
    ; random =
        (fun n ->
          let b = Bytes.create n in
          for i = 0 to n - 1 do
            Bytes.set_uint8 b i (Random.int 256)
          done;
          b)
    ; set_timer = (fun _ -> ())
    ; cancel_timer = (fun () -> ())
    }
  in
  (* Main loop *)
  let rec loop () =
    let len, src = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
    let data = Bytes.sub buf 0 len in
    let from_addr =
      match src with
      | Unix.ADDR_INET (addr, p) -> Unix.string_of_inet_addr addr, p
      | _ -> "0.0.0.0", 0
    in
    client_addr := from_addr;
    Printf.printf "➤ Received %d bytes from %s:%d\n%!" len (fst from_addr) (snd from_addr);
    Dtls.run_with_io ~ops (fun () ->
      match Dtls.handle_record_as_server dtls data ~client_addr:from_addr with
      | Ok (responses, app_data) ->
        (* Send any response records *)
        List.iter
          (fun r ->
             let _ = ops.send r in
             ())
          responses;
        (* Echo back any application data *)
        (match app_data with
         | Some plaintext ->
           Printf.printf "➤ Decrypted: %s\n%!" (Bytes.to_string plaintext);
           (match Dtls.encrypt dtls plaintext with
            | Ok encrypted ->
              let _ = ops.send encrypted in
              Printf.printf "➤ Echoed back\n%!"
            | Error e -> Log.error "Encrypt error: %s" e)
         | None ->
           if Dtls.is_established dtls then Printf.printf "➤ DTLS handshake complete!\n%!")
      | Error e -> Log.error "Error: %s" e);
    loop ()
  in
  loop ()
;;

let run_client host port =
  Printf.printf "╔═══════════════════════════════════════════════════════════════╗\n";
  Printf.printf "║           DTLS Echo Client (RFC 6347)                        ║\n";
  Printf.printf "╚═══════════════════════════════════════════════════════════════╝\n\n";
  Printf.printf "➤ Connecting to %s:%d...\n%!" host port;
  (* Create UDP socket *)
  let sock = Unix.socket Unix.PF_INET Unix.SOCK_DGRAM 0 in
  Unix.setsockopt_float sock Unix.SO_RCVTIMEO 5.0;
  let server_addr =
    let host_entry = Unix.gethostbyname host in
    Unix.ADDR_INET (host_entry.Unix.h_addr_list.(0), port)
  in
  (* Create DTLS client context *)
  let dtls = Dtls.create Dtls.default_client_config in
  (* I/O ops *)
  let buf = Bytes.create 65536 in
  let ops : Dtls.io_ops =
    { send = (fun data -> Unix.sendto sock data 0 (Bytes.length data) [] server_addr)
    ; recv =
        (fun _ ->
          let len, _ = Unix.recvfrom sock buf 0 (Bytes.length buf) [] in
          Bytes.sub buf 0 len)
    ; now = Unix.gettimeofday
    ; random =
        (fun n ->
          let b = Bytes.create n in
          for i = 0 to n - 1 do
            Bytes.set_uint8 b i (Random.int 256)
          done;
          b)
    ; set_timer = (fun _ -> ())
    ; cancel_timer = (fun () -> ())
    }
  in
  Dtls.run_with_io ~ops (fun () ->
    (* Start handshake *)
    Printf.printf "➤ Starting DTLS handshake...\n%!";
    match Dtls.start_handshake dtls with
    | Ok records ->
      List.iter
        (fun r ->
           let _ = ops.send r in
           ())
        records;
      (* Process handshake *)
      let rec handshake_loop () =
        if Dtls.is_established dtls
        then Printf.printf "➤ DTLS handshake complete!\n%!"
        else (
          let response = ops.recv 0 in
          Printf.printf "➤ Received %d bytes\n%!" (Bytes.length response);
          match Dtls.handle_record dtls response with
          | Ok (responses, _) ->
            List.iter
              (fun r ->
                 let _ = ops.send r in
                 ())
              responses;
            handshake_loop ()
          | Error e -> Log.error "Handshake error: %s" e)
      in
      handshake_loop ();
      (* Send test message *)
      if Dtls.is_established dtls
      then (
        let test_msg = Bytes.of_string "Hello, DTLS World!" in
        Printf.printf "➤ Sending: %s\n%!" (Bytes.to_string test_msg);
        match Dtls.encrypt dtls test_msg with
        | Ok encrypted ->
          let _ = ops.send encrypted in
          (* Wait for echo *)
          let reply = ops.recv 0 in
          (match Dtls.decrypt dtls reply with
           | Ok decrypted ->
             Printf.printf "➤ Received echo: %s\n%!" (Bytes.to_string decrypted)
           | Error e -> Log.error "Decrypt error: %s" e)
        | Error e -> Log.error "Encrypt error: %s" e)
    | Error e -> Log.error "Handshake start error: %s" e);
  Unix.close sock
;;

let () =
  if Array.length Sys.argv < 2
  then (
    Printf.printf "Usage:\n";
    Printf.printf "  Server: %s server <port>\n" Sys.argv.(0);
    Printf.printf "  Client: %s client <host> <port>\n" Sys.argv.(0);
    exit 1);
  match Sys.argv.(1) with
  | "server" ->
    let port = if Array.length Sys.argv > 2 then int_of_string Sys.argv.(2) else 12345 in
    run_server port
  | "client" ->
    let host = if Array.length Sys.argv > 2 then Sys.argv.(2) else "127.0.0.1" in
    let port = if Array.length Sys.argv > 3 then int_of_string Sys.argv.(3) else 12345 in
    run_client host port
  | _ ->
    Log.error "Unknown mode: %s" Sys.argv.(1);
    exit 1
;;
