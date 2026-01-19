(** Example: STUN Client for NAT Discovery

    This example demonstrates using the STUN module to discover
    your public IP address and port when behind NAT.

    Usage:
      dune exec examples/stun_client.exe [-- <server>]

    Default STUN server: stun.l.google.com:19302
*)

open Webrtc

let () =
  (* Initialize RNG (new API) *)
  Mirage_crypto_rng_unix.use_default ();

  (* Get server from command line or use default *)
  let server =
    if Array.length Sys.argv > 1 then
      Sys.argv.(1)
    else
      "stun.l.google.com:19302"
  in

  Printf.printf "=== STUN Client Example ===\n";
  Printf.printf "Server: %s\n\n" server;

  (* Send binding request (synchronous) *)
  match Stun.binding_request_sync ~server ~timeout:5.0 () with
  | Ok result ->
    Printf.printf "✅ STUN Binding Success!\n\n";
    Printf.printf "Local Address:  %s:%d\n"
      result.local_address.ip
      result.local_address.port;
    Printf.printf "Public Address: %s:%d\n"
      result.mapped_address.ip
      result.mapped_address.port;
    Printf.printf "RTT: %.2f ms\n" result.rtt_ms;
    begin match result.server_software with
    | Some sw -> Printf.printf "Server: %s\n" sw
    | None -> ()
    end;
    Printf.printf "\n"

  | Error e ->
    Printf.eprintf "❌ STUN Error: %s\n" e;
    exit 1
