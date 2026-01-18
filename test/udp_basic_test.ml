(** Basic UDP test to verify packet delivery on localhost *)
open Webrtc

let () =
  Printf.printf "=== Basic UDP Test ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:48000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:48001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:48001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:48000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  Printf.printf "Sender local: %s:%d\n"
    (Udp_transport.local_endpoint sender_udp).host
    (Udp_transport.local_endpoint sender_udp).port;
  Printf.printf "Receiver local: %s:%d\n\n"
    (Udp_transport.local_endpoint receiver_udp).host
    (Udp_transport.local_endpoint receiver_udp).port;

  let data = Bytes.make 1024 'X' in

  (* Send one message *)
  Printf.printf "=== Phase 1: Single send/recv ===\n";
  match Sctp_full_transport.send_data sender ~stream_id:0 ~data with
  | Error e -> Printf.printf "Send failed: %s\n" e
  | Ok _ ->
    let s_udp = Udp_transport.get_stats sender_udp in
    Printf.printf "After send: sender packets_sent=%d\n" s_udp.packets_sent;

    (* Now tick receiver to pick up the packet *)
    Sctp_full_transport.tick receiver;
    let r_udp = Udp_transport.get_stats receiver_udp in
    Printf.printf "After recv tick: receiver packets_recv=%d\n\n" r_udp.packets_recv;

    (* Send 100 messages in a burst *)
    Printf.printf "=== Phase 2: Burst 100 messages ===\n";
    let s_before = Udp_transport.get_stats sender_udp in
    for _ = 1 to 100 do
      ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data)
    done;
    let s_after = Udp_transport.get_stats sender_udp in
    Printf.printf "Sent %d packets\n" (s_after.packets_sent - s_before.packets_sent);

    (* Tick receiver multiple times to drain *)
    let r_before = Udp_transport.get_stats receiver_udp in
    for _ = 1 to 10 do
      Sctp_full_transport.tick receiver
    done;
    let r_after = Udp_transport.get_stats receiver_udp in
    Printf.printf "Received %d packets\n\n" (r_after.packets_recv - r_before.packets_recv);

    (* Tick sender to process SACKs and send more *)
    Printf.printf "=== Phase 3: Full exchange (1000 ticks) ===\n";
    let s0 = Udp_transport.get_stats sender_udp in
    let r0 = Udp_transport.get_stats receiver_udp in

    for _ = 1 to 1000 do
      (* Try to send more data if possible *)
      if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then
        ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
      Sctp_full_transport.tick receiver;
      Sctp_full_transport.tick sender
    done;

    let s1 = Udp_transport.get_stats sender_udp in
    let r1 = Udp_transport.get_stats receiver_udp in
    Printf.printf "Sender sent: %d packets\n" (s1.packets_sent - s0.packets_sent);
    Printf.printf "Receiver got: %d packets\n" (r1.packets_recv - r0.packets_recv);
    Printf.printf "Delta: %d packets lost\n\n" ((s1.packets_sent - s0.packets_sent) - (r1.packets_recv - r0.packets_recv));

    Printf.printf "=== Final Stats ===\n";
    Printf.printf "Total sender packets_sent: %d\n" s1.packets_sent;
    Printf.printf "Total receiver packets_recv: %d\n" r1.packets_recv;
    Printf.printf "cwnd: %d, flight: %d\n"
      (Sctp_full_transport.get_cwnd sender)
      (Sctp_full_transport.get_flight_size sender)
