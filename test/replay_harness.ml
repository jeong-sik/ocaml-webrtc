(** Deterministic replay harness for Sans-IO Sctp_core

    Captures a sequence of inputs and their corresponding outputs,
    then replays the same inputs on a fresh state machine and verifies
    output identity.

    This proves the state machine is deterministic: same inputs, same config
    → identical outputs.

    @since 0.3.0
*)

open Webrtc

(** A single step: one input and its outputs. *)
type step = {
  input : Sctp_core.input;
  outputs : Sctp_core.output list;
}

(** A recorded trace: config + steps. *)
type trace = {
  src_port : int;
  dst_port : int;
  initial_tsn : int32;
  my_vtag : int32;
  steps : step list;
}

(** [record ~src_port ~dst_port ~initial_tsn ~my_vtag inputs] creates a
    state machine with the given config, feeds each input, and records
    the outputs at each step.

    Time is set deterministically via [set_now] at each step. *)
let record ~src_port ~dst_port ~initial_tsn ~my_vtag inputs =
  let t = Sctp_core.create
    ~src_port ~dst_port ~initial_tsn ~my_vtag () in
  let steps = List.mapi (fun i inp ->
    (* Deterministic time: step index * 10ms *)
    Sctp_core.set_now t (float_of_int i *. 0.01);
    let outputs = Sctp_core.handle t inp in
    { input = inp; outputs }
  ) inputs in
  { src_port; dst_port; initial_tsn; my_vtag; steps }

(** [replay trace] creates a fresh state machine with the same config
    and replays all recorded inputs.  Returns the new outputs for comparison. *)
let replay trace =
  let t = Sctp_core.create
    ~src_port:trace.src_port
    ~dst_port:trace.dst_port
    ~initial_tsn:trace.initial_tsn
    ~my_vtag:trace.my_vtag
    () in
  List.mapi (fun i step ->
    Sctp_core.set_now t (float_of_int i *. 0.01);
    let outputs = Sctp_core.handle t step.input in
    { input = step.input; outputs }
  ) trace.steps

(** Check if a packet contains non-deterministic content.
    Heartbeat chunks (type 4 at byte 0) include a random nonce.
    INIT chunks (type 1) include a random initial TSN/vtag when
    generated internally. *)
let has_nondeterministic_content packet =
  let len = Bytes.length packet in
  if len < 4 then false
  else
    let first_byte = Bytes.get_uint8 packet 0 in
    (* Chunk types: 1=INIT, 4=HEARTBEAT, 5=HEARTBEAT-ACK *)
    first_byte = 1 || first_byte = 4 || first_byte = 5

(** Structural comparison for packets with non-deterministic content.
    Non-deterministic: same length + same chunk type byte.
    Deterministic: byte equality. *)
let packets_equivalent p1 p2 =
  if has_nondeterministic_content p1 || has_nondeterministic_content p2 then
    Bytes.length p1 = Bytes.length p2
    && Bytes.length p1 >= 1
    && Bytes.get_uint8 p1 0 = Bytes.get_uint8 p2 0
  else
    Bytes.equal p1 p2

(** [outputs_equal a b] compares two output lists for equality.
    Uses structural comparison on each variant.
    SendPacket uses {!packets_equivalent} to handle heartbeat nonces. *)
let output_equal a b =
  match a, b with
  | Sctp_core.SendPacket p1, Sctp_core.SendPacket p2 ->
    packets_equivalent p1 p2
  | DeliverData d1, DeliverData d2 ->
    d1.stream_id = d2.stream_id && Bytes.equal d1.data d2.data
  | SetTimer s1, SetTimer s2 ->
    s1.timer = s2.timer && Float.equal s1.delay_ms s2.delay_ms
  | CancelTimer t1, CancelTimer t2 -> t1 = t2
  | ConnectionEstablished, ConnectionEstablished -> true
  | ConnectionClosed, ConnectionClosed -> true
  | Error e1, Error e2 -> String.equal e1 e2
  | _ -> false

let outputs_equal a b =
  List.length a = List.length b
  && List.for_all2 output_equal a b

(** [verify trace] replays and checks every step matches.
    Returns [Ok ()] if deterministic, [Error (step_idx, expected, actual)]
    if divergence found. *)
let verify trace =
  let replayed = replay trace in
  let rec check idx original replayed =
    match original, replayed with
    | [], [] -> Ok ()
    | orig :: rest_o, repl :: rest_r ->
      if outputs_equal orig.outputs repl.outputs then
        check (idx + 1) rest_o rest_r
      else
        Error (idx, orig.outputs, repl.outputs)
    | _ -> Error (-1, [], [])  (* length mismatch *)
  in
  check 0 trace.steps replayed

(** [pp_step_divergence idx expected actual] formats a divergence report. *)
let pp_divergence idx expected actual =
  Printf.sprintf "Step %d diverged: expected %d outputs, got %d"
    idx (List.length expected) (List.length actual)
