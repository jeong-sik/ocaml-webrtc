(** Trace SACK sends and failures *)
open Webrtc

let () =
  Printf.printf "=== SACK Send Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:51000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:51001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:51001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:51000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in
  let msgs = ref 0 in
  let last_send_err = ref 0 in
  let last_recv_err = ref 0 in

  Printf.printf "Tracking UDP errors on both sender and receiver...\n\n%!";

  for step = 1 to 40000 do
    if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
      match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
      | Ok _ -> incr msgs
      | Error _ -> ()
    end;

    Sctp_full_transport.tick receiver;
    Sctp_full_transport.tick sender;

    (* Check for UDP errors *)
    let s_udp = Udp_transport.get_stats sender_udp in
    let r_udp = Udp_transport.get_stats receiver_udp in

    (* Report if send_errors change *)
    if s_udp.send_errors <> !last_send_err || r_udp.send_errors <> !last_recv_err then begin
      Printf.printf "step %d: sender_send_err=%d receiver_send_err=%d (SACK fails!)\n%!"
        step s_udp.send_errors r_udp.send_errors;
      last_send_err := s_udp.send_errors;
      last_recv_err := r_udp.send_errors
    end;

    (* Detect collapse *)
    if Sctp_full_transport.get_cwnd sender < 2000 &&
       Sctp_full_transport.get_flight_size sender > 100000 then begin
      Printf.printf "\n*** COLLAPSE at step %d ***\n" step;
      Printf.printf "Sender UDP: sent=%d send_errors=%d recv_errors=%d\n"
        s_udp.packets_sent s_udp.send_errors s_udp.recv_errors;
      Printf.printf "Receiver UDP: sent=%d send_errors=%d recv_errors=%d\n"
        r_udp.packets_sent r_udp.send_errors r_udp.recv_errors;
      Printf.printf "Note: receiver 'sent' = SACK packets sent\n";
      exit 0
    end;

    if step mod 10000 = 0 then begin
      Printf.printf "[checkpoint step %d: msgs=%d sender_err=%d receiver_err=%d]\n%!"
        step !msgs s_udp.send_errors r_udp.send_errors
    end
  done;

  Printf.printf "Test completed without collapse\n"
