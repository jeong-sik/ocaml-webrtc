(** Connection lifecycle harness *)

type phase =
  | Init
  | Ice_gathering
  | Dtls_handshake
  | Sctp_association
  | Data_channel
  | Established
[@@deriving show, eq]

type failure =
  { failed_phase : phase
  ; error : Oas_error.t
  ; cleaned_phases : phase list
  }
[@@deriving show, eq]

type cleanup = unit -> unit

type phase_entry =
  { phase : phase
  ; cleanup : cleanup
  }

type state =
  | Active of phase
  | Failed of failure

type t =
  { mutable state : state
  ; mutable completed : phase_entry list (* newest first *)
  }

let phase_index = function
  | Init -> 0
  | Ice_gathering -> 1
  | Dtls_handshake -> 2
  | Sctp_association -> 3
  | Data_channel -> 4
  | Established -> 5
;;

let create () = { state = Active Init; completed = [] }

let current_phase t =
  match t.state with
  | Active p -> p
  | Failed f -> f.failed_phase
;;

let advance t ~phase ~cleanup =
  match t.state with
  | Failed _ -> Error "cannot advance: lifecycle is in failed state"
  | Active current ->
    let cur_idx = phase_index current in
    let new_idx = phase_index phase in
    if new_idx <> cur_idx + 1
    then
      Error
        (Printf.sprintf
           "invalid transition: %s → %s (must be sequential)"
           (show_phase current)
           (show_phase phase))
    else (
      t.completed <- { phase; cleanup } :: t.completed;
      t.state <- Active phase;
      Ok ())
;;

let fail t ~error =
  let err = Oas_error.of_string error in
  let failed_phase = current_phase t in
  (* Run cleanups in reverse order (newest phase first = already in order) *)
  let cleaned_phases =
    List.map
      (fun entry ->
         (try entry.cleanup () with
          | _exn -> ());
         (* cleanup must not propagate exceptions *)
         entry.phase)
      t.completed
  in
  let failure = { failed_phase; error = err; cleaned_phases } in
  t.state <- Failed failure;
  t.completed <- [];
  failure
;;

let is_established t =
  match t.state with
  | Active Established -> true
  | _ -> false
;;

let is_failed t =
  match t.state with
  | Failed _ -> true
  | Active _ -> false
;;

let completed_phases t = List.rev_map (fun e -> e.phase) t.completed
