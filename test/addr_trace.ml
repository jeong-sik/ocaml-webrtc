(** Trace socket addresses and connected state *)
open Webrtc

let () =
  Printf.printf "=== Address Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:54000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:54001 () in

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  Printf.printf "Before connect:\n";
  Printf.printf "  Sender local: %s:%d\n"
    (Udp_transport.local_endpoint sender_udp).host
    (Udp_transport.local_endpoint sender_udp).port;
  Printf.printf "  Receiver local: %s:%d\n"
    (Udp_transport.local_endpoint receiver_udp).host
    (Udp_transport.local_endpoint receiver_udp).port;

  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:54001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:54000;

  Printf.printf "\nAfter connect:\n";
  Printf.printf "  Sender remote: %s:%d\n"
    (Option.get (Udp_transport.remote_endpoint sender_udp)).host
    (Option.get (Udp_transport.remote_endpoint sender_udp)).port;
  Printf.printf "  Receiver remote: %s:%d\n"
    (Option.get (Udp_transport.remote_endpoint receiver_udp)).host
    (Option.get (Udp_transport.remote_endpoint receiver_udp)).port;

  (* Now send a test packet and see what address it comes from *)
  let data = Bytes.make 100 'X' in
  ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);

  (* Tick receiver to see the packet *)
  Sctp_full_transport.tick receiver;

  let r_udp = Udp_transport.get_stats receiver_udp in
  Printf.printf "\nReceiver got %d packets\n" r_udp.packets_recv;

  (* Check if recv works with recvfrom *)
  let buf = Bytes.create 65536 in
  Printf.printf "\nTrying direct recvfrom on receiver socket...\n";
  let receiver_socket = Udp_transport.get_socket receiver_udp in
  match Unix.recvfrom receiver_socket buf 0 65536 [] with
  | len, Unix.ADDR_INET (addr, port) ->
    Printf.printf "Got %d bytes from %s:%d\n" len (Unix.string_of_inet_addr addr) port
  | _, _ ->
    Printf.printf "Got packet from non-inet address\n"
  | exception Unix.Unix_error (Unix.EAGAIN, _, _) ->
    Printf.printf "No data available (EAGAIN)\n"
  | exception e ->
    Printf.printf "Error: %s\n" (Printexc.to_string e)
