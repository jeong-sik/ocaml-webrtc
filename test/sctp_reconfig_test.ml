(** SCTP Re-Config tests (RFC 6525) *)

open Webrtc

let passed = ref 0
let failed = ref 0

let test name f =
  Printf.printf "  %s... %!" name;
  try
    f ();
    incr passed;
    Printf.printf "PASS\n%!"
  with e ->
    incr failed;
    Printf.printf "FAIL (%s)\n%!" (Printexc.to_string e)

let assert_true msg b = if not b then failwith msg
let assert_eq_i32 msg a b = if a <> b then failwith msg

let find_send_packet outputs =
  let rec loop = function
    | [] -> None
    | Sctp_core.SendPacket p :: _ -> Some p
    | _ :: rest -> loop rest
  in
  loop outputs

let decode_data_stream_seq packet =
  match Sctp.decode_packet packet with
  | Error e -> failwith e
  | Ok pkt ->
    match pkt.Sctp.chunks with
    | [] -> failwith "missing chunk"
    | chunk :: _ ->
      let header = Bytes.create 4 in
      Bytes.set_uint8 header 0 chunk.chunk_type;
      Bytes.set_uint8 header 1 chunk.chunk_flags;
      Bytes.set_uint16_be header 2 (4 + Bytes.length chunk.chunk_value);
      let buf = Bytes.cat header chunk.chunk_value in
      match Sctp.decode_data_chunk buf with
      | Error e -> failwith e
      | Ok dc -> dc.Sctp.stream_seq

let build_reconfig_packet params =
  let chunk = Sctp_reconfig.to_raw_chunk params in
  Sctp.encode_packet {
    Sctp.header = {
      source_port = 5000;
      dest_port = 5000;
      verification_tag = 0l;
      checksum = 0l;
    };
    chunks = [chunk];
  }

let decode_reconfig_params packet =
  match Sctp.decode_packet packet with
  | Error e -> failwith e
  | Ok pkt ->
    let is_reconfig chunk =
      chunk.Sctp.chunk_type = Sctp.int_of_chunk_type Sctp.RE_CONFIG
    in
    match List.find_opt is_reconfig pkt.Sctp.chunks with
    | None -> failwith "missing RE-CONFIG chunk"
    | Some chunk ->
      match Sctp_reconfig.of_raw_chunk chunk with
      | Ok params -> params
      | Error e -> failwith e

let find_reconfig_request_seq params =
  let rec loop = function
    | [] -> failwith "missing reset request"
    | Sctp_reconfig.Outgoing_ssn_reset r :: _ -> r.request_seq
    | _ :: rest -> loop rest
  in
  loop params

let find_reconfig_response params =
  let rec loop = function
    | [] -> failwith "missing reconfig response"
    | Sctp_reconfig.Reconfig_response { response_seq; result } :: _ ->
      (response_seq, result)
    | _ :: rest -> loop rest
  in
  loop params

let () =
  Printf.printf "=== SCTP RE-CONFIG ===\n";

  test "encode/decode outgoing reset" (fun () ->
    let params = [
      Sctp_reconfig.Outgoing_ssn_reset {
        request_seq = 1l;
        response_seq = 2l;
        last_tsn = 100l;
        streams = [0; 1; 2];
      }
    ] in
    let encoded = Sctp_reconfig.encode_params params in
    assert_true "aligned length" (Bytes.length encoded mod 4 = 0);
    match Sctp_reconfig.decode_params encoded with
    | Error e -> failwith e
    | Ok [Sctp_reconfig.Outgoing_ssn_reset p] ->
      assert_eq_i32 "request_seq" 1l p.request_seq;
      assert_eq_i32 "response_seq" 2l p.response_seq;
      assert_eq_i32 "last_tsn" 100l p.last_tsn;
      assert_true "stream list" (p.streams = [0; 1; 2])
    | Ok _ -> failwith "Unexpected params"
  );

  test "encode/decode response" (fun () ->
    let params = [
      Sctp_reconfig.Reconfig_response { response_seq = 7l; result = 0l }
    ] in
    let encoded = Sctp_reconfig.encode_params params in
    match Sctp_reconfig.decode_params encoded with
    | Error e -> failwith e
    | Ok [Sctp_reconfig.Reconfig_response r] ->
      assert_eq_i32 "response_seq" 7l r.response_seq;
      assert_eq_i32 "result" 0l r.result
    | Ok _ -> failwith "Unexpected params"
  );

  test "raw_chunk roundtrip" (fun () ->
    let params = [
      Sctp_reconfig.Add_outgoing_streams { request_seq = 3l; new_streams = 2 };
      Sctp_reconfig.Add_incoming_streams { request_seq = 4l; new_streams = 1 };
    ] in
    let chunk = Sctp_reconfig.to_raw_chunk params in
    match Sctp_reconfig.of_raw_chunk chunk with
    | Error e -> failwith e
    | Ok _ -> ()
  );

  test "peer outgoing reset does not reset local outgoing seq" (fun () ->
    let core = Sctp_core.create () in
    ignore (Sctp_core.initiate_direct core);
    let out1 = Sctp_core.handle core (Sctp_core.UserSend { stream_id = 1; data = Bytes.of_string "a" }) in
    let out2 = Sctp_core.handle core (Sctp_core.UserSend { stream_id = 1; data = Bytes.of_string "b" }) in
    let seq1 = match find_send_packet out1 with
      | None -> failwith "missing packet"
      | Some p -> decode_data_stream_seq p
    in
    let seq2 = match find_send_packet out2 with
      | None -> failwith "missing packet"
      | Some p -> decode_data_stream_seq p
    in
    assert_true "seq increments" (seq1 = 0 && seq2 = 1);

    let reconfig = Sctp_reconfig.Outgoing_ssn_reset {
      request_seq = 10l;
      response_seq = 0l;
      last_tsn = 0l;
      streams = [1];
    } in
    let packet = build_reconfig_packet [reconfig] in
    let outputs = Sctp_core.handle core (Sctp_core.PacketReceived packet) in
    assert_true "responds to reconfig" (find_send_packet outputs <> None);

    let out3 = Sctp_core.handle core (Sctp_core.UserSend { stream_id = 1; data = Bytes.of_string "c" }) in
    let seq3 = match find_send_packet out3 with
      | None -> failwith "missing packet"
      | Some p -> decode_data_stream_seq p
    in
    assert_true "seq not reset" (seq3 = 2)
  );

  test "UserResetStreams resets after response" (fun () ->
    let core = Sctp_core.create () in
    ignore (Sctp_core.initiate_direct core);
    ignore (Sctp_core.handle core (Sctp_core.UserSend { stream_id = 1; data = Bytes.of_string "a" }));
    ignore (Sctp_core.handle core (Sctp_core.UserSend { stream_id = 1; data = Bytes.of_string "b" }));

    let reset_out = Sctp_core.handle core (Sctp_core.UserResetStreams { stream_ids = [1] }) in
    let reset_packet = match find_send_packet reset_out with
      | None -> failwith "missing reset packet"
      | Some p -> p
    in
    let request_seq =
      decode_reconfig_params reset_packet |> find_reconfig_request_seq
    in

    let out3 = Sctp_core.handle core (Sctp_core.UserSend { stream_id = 1; data = Bytes.of_string "c" }) in
    let seq3 = match find_send_packet out3 with
      | None -> failwith "missing packet"
      | Some p -> decode_data_stream_seq p
    in
    assert_true "seq unchanged before response" (seq3 = 2);

    let response = Sctp_reconfig.Reconfig_response {
      response_seq = request_seq;
      result = Sctp_reconfig.result_success;
    } in
    let response_packet = build_reconfig_packet [response] in
    ignore (Sctp_core.handle core (Sctp_core.PacketReceived response_packet));

    let out4 = Sctp_core.handle core (Sctp_core.UserSend { stream_id = 1; data = Bytes.of_string "d" }) in
    let seq4 = match find_send_packet out4 with
      | None -> failwith "missing packet"
      | Some p -> decode_data_stream_seq p
    in
    assert_true "seq reset after response" (seq4 = 0)
  );

  test "incoming reset waits for last_tsn" (fun () ->
    let core = Sctp_core.create ~initial_tsn:1l () in
    ignore (Sctp_core.initiate_direct core);

    let reconfig = Sctp_reconfig.Outgoing_ssn_reset {
      request_seq = 11l;
      response_seq = 0l;
      last_tsn = 10l;
      streams = [1];
    } in
    let packet = build_reconfig_packet [reconfig] in
    let outputs = Sctp_core.handle core (Sctp_core.PacketReceived packet) in
    let response_packet = match find_send_packet outputs with
      | None -> failwith "missing response packet"
      | Some p -> p
    in
    let (_seq, result) = decode_reconfig_params response_packet |> find_reconfig_response in
    assert_true "in progress" (result = Sctp_reconfig.result_in_progress)
  );

  Printf.printf "\nSCTP RE-CONFIG tests: %d passed, %d failed\n" !passed !failed;
  if !failed > 0 then exit 1
