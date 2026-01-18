(** Trace the ORIGIN of gap ranges - when do they first form? *)
open Webrtc

let () =
  Printf.printf "=== Gap Origin Trace ===\n\n%!";

  let sender = Sctp_full_transport.create ~host:"127.0.0.1" ~port:55000 () in
  let receiver = Sctp_full_transport.create ~host:"127.0.0.1" ~port:55001 () in
  Sctp_full_transport.connect sender ~host:"127.0.0.1" ~port:55001;
  Sctp_full_transport.connect receiver ~host:"127.0.0.1" ~port:55000;

  let sender_udp = Sctp_full_transport.get_udp_transport sender in
  let receiver_udp = Sctp_full_transport.get_udp_transport receiver in

  let data = Bytes.make 1024 'X' in

  Printf.printf "Starting - watching for gap formation...\n\n%!";

  let first_gap_step = ref None in
  let gap_count_history = ref [] in

  for step = 1 to 5000 do
    (* Before any action: check receiver's gap state *)
    let gap_count_before = Sctp_full_transport.get_gap_count receiver in
    let cum_tsn_before = Sctp_full_transport.get_cumulative_tsn receiver in

    (* send_data if allowed *)
    let sent =
      if Sctp_full_transport.get_flight_size sender < Sctp_full_transport.get_cwnd sender then begin
        ignore (Sctp_full_transport.send_data sender ~stream_id:0 ~data);
        true
      end else false
    in

    let s_after_send = (Udp_transport.get_stats sender_udp).packets_sent in

    (* receiver tick *)
    Sctp_full_transport.tick receiver;
    let gap_count_after_rtick = Sctp_full_transport.get_gap_count receiver in
    let cum_tsn_after_rtick = Sctp_full_transport.get_cumulative_tsn receiver in

    (* sender tick *)
    Sctp_full_transport.tick sender;
    let s_final = (Udp_transport.get_stats sender_udp).packets_sent in
    let tick_pkts = s_final - s_after_send in

    let gap_count_after = Sctp_full_transport.get_gap_count receiver in

    (* Detect gap formation *)
    if gap_count_after_rtick > 0 && !first_gap_step = None then begin
      first_gap_step := Some step;
      let gaps = Sctp_full_transport.get_gap_ranges receiver in
      Printf.printf "*** FIRST GAP at step %d ***\n%!" step;
      Printf.printf "  Gap ranges: [%s]\n%!"
        (String.concat "; " (List.map (fun (s, e) -> Printf.sprintf "%d-%d" s e) gaps));
      Printf.printf "  cum_tsn: %ld -> %ld\n%!" cum_tsn_before cum_tsn_after_rtick;
      Printf.printf "  sent_new: %b, tick_pkts: %d\n\n%!" sent tick_pkts
    end;

    (* Track gap count changes *)
    if gap_count_after > gap_count_before then
      gap_count_history := (step, gap_count_before, gap_count_after) :: !gap_count_history;

    (* Print every 500 steps or when gaps change *)
    if step mod 500 = 0 || gap_count_after <> gap_count_before then begin
      Printf.printf "step %d: gaps=%d cum_tsn=%ld sent=%b tick_pkts=%d\n%!"
        step gap_count_after cum_tsn_after_rtick sent tick_pkts
    end;

    (* Stop early if we found the gap and traced a bit more *)
    if !first_gap_step <> None && step > (Option.get !first_gap_step) + 50 then begin
      Printf.printf "\n\nStopping after 50 more steps\n";
      Printf.printf "Final: sent=%d recv=%d\n"
        (Udp_transport.get_stats sender_udp).packets_sent
        (Udp_transport.get_stats receiver_udp).packets_recv;
      exit 0
    end
  done;

  Printf.printf "\nNo gaps formed in 5000 steps!\n";
  Printf.printf "Final: sent=%d recv=%d\n"
    (Udp_transport.get_stats sender_udp).packets_sent
    (Udp_transport.get_stats receiver_udp).packets_recv
