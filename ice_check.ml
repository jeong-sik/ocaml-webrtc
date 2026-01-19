(** RFC 8445 ICE Connectivity Checks - Sans-IO Implementation

    This module implements ICE connectivity checks using the Sans-IO pattern:
    - All I/O operations are represented as ADT values (input/output)
    - Pure functions handle state transitions
    - Side effects are handled by the caller

    Benefits:
    - Easy to test without mocking
    - Suitable for formal verification
    - Runtime-agnostic (works with Lwt, Eio, or blocking I/O)
*)

(** {1 Types} *)

(** Check state per RFC 8445 Section 6.1.2.6 *)
type check_state =
  | Frozen      (** Initial state, waiting to be scheduled *)
  | Waiting     (** Ready to perform check *)
  | In_progress (** Check request sent, waiting for response *)
  | Succeeded   (** Check completed successfully *)
  | Failed      (** Check failed after all retries *)
[@@deriving show, eq]

(** STUN attributes for connectivity checks *)
type stun_attrs = {
  username: string;           (** Combined username: remoteUfrag:localUfrag *)
  password: string;           (** Remote ICE password for HMAC *)
  use_candidate: bool;        (** Nomination flag (controlling agent) *)
  priority: int;              (** Candidate priority *)
  ice_controlling: int64 option;  (** Tie-breaker if controlling *)
  ice_controlled: int64 option;   (** Tie-breaker if controlled *)
}

(** Transaction state for retransmission *)
type transaction = {
  id: bytes;                  (** 96-bit transaction ID *)
  attempt: int;               (** Current attempt number (1-based) *)
  max_attempts: int;          (** Maximum attempts before failure *)
  rto_ms: int;                (** Current retransmission timeout *)
  max_rto_ms: int;            (** Maximum RTO cap for backoff *)
  sent_at: float;             (** Timestamp of last send *)
}

(** Check context - immutable per-check data *)
type check_context = {
  local_addr: string * int;   (** Local (address, port) *)
  remote_addr: string * int;  (** Remote (address, port) *)
  stun_attrs: stun_attrs;     (** STUN message attributes *)
  transaction: transaction;   (** Transaction state *)
}

(** Check machine state *)
type t = {
  state: check_state;
  context: check_context;
  nominated: bool;            (** Whether this check was nominated *)
  last_error: string option;  (** Error message if failed *)
}

(** {1 Sans-IO Input Events} *)

(** Events that can trigger state transitions *)
type input =
  | Start_check                     (** Initiate the check *)
  | Stun_response_received of {
      transaction_id: bytes;
      success: bool;
      mapped_addr: (string * int) option;  (** XOR-MAPPED-ADDRESS if success *)
      error_code: int option;              (** Error code if failure *)
    }
  | Timer_fired                     (** Retransmission timer expired *)
  | Cancel                          (** Cancel the check *)

(** {1 Sans-IO Output Commands} *)

(** Commands to be executed by the I/O layer *)
type output =
  | Send_stun_request of {
      dest: string * int;           (** Destination (address, port) *)
      transaction_id: bytes;
      username: string;
      password: string;
      use_candidate: bool;
      priority: int;
      ice_controlling: int64 option;
      ice_controlled: int64 option;
    }
  | Set_timer of {
      duration_ms: int;             (** Timer duration in milliseconds *)
    }
  | Cancel_timer                    (** Cancel any pending timer *)
  | Check_completed of {
      success: bool;
      nominated: bool;
      mapped_addr: (string * int) option;
      error: string option;
    }
  | No_op                           (** No action needed *)

(** {1 Configuration} *)

(** Timing configuration for connectivity checks *)
type config = {
  initial_rto_ms: int;  (** RFC 8445 Section 14.3: Initial RTO (default: 500) *)
  max_rto_ms: int;      (** Maximum RTO after exponential backoff (default: 3000) *)
  max_attempts: int;    (** Maximum retransmission attempts (default: 7) *)
}

(** Default configuration per RFC 8445 recommendations *)
let default_config = {
  initial_rto_ms = 500;
  max_rto_ms = 3000;
  max_attempts = 7;
}

(** {1 Creation} *)

(** Generate random transaction ID (96 bits) *)
let generate_transaction_id () =
  let id = Bytes.create 12 in
  for i = 0 to 11 do
    Bytes.set id i (Char.chr (Random.int 256))
  done;
  id

(** Create a new connectivity check *)
let create
    ~local_addr
    ~remote_addr
    ~local_ufrag
    ~local_pwd:_
    ~remote_ufrag
    ~remote_pwd
    ~priority
    ~is_controlling
    ~tie_breaker
    ~use_candidate
    ?(config = default_config)
    () =
  let username = remote_ufrag ^ ":" ^ local_ufrag in
  let stun_attrs = {
    username;
    password = remote_pwd;
    use_candidate;
    priority;
    ice_controlling = if is_controlling then Some tie_breaker else None;
    ice_controlled = if not is_controlling then Some tie_breaker else None;
  } in
  let transaction = {
    id = generate_transaction_id ();
    attempt = 0;
    max_attempts = config.max_attempts;
    rto_ms = config.initial_rto_ms;
    max_rto_ms = config.max_rto_ms;
    sent_at = 0.0;
  } in
  let context = {
    local_addr;
    remote_addr;
    stun_attrs;
    transaction;
  } in
  {
    state = Frozen;
    context;
    nominated = false;
    last_error = None;
  }

(** {1 State Transitions (Pure Functions)} *)

(** Calculate next RTO with exponential backoff *)
let next_rto ~max_rto_ms current_rto =
  min (current_rto * 2) max_rto_ms

(** Handle state transition and produce output *)
let step (check : t) (input : input) (now : float) : t * output =
  match check.state, input with

  (* Frozen -> Waiting: Start the check *)
  | Frozen, Start_check ->
    let check = { check with state = Waiting } in
    let output = No_op in
    (check, output)

  (* Waiting -> In_progress: Send first request *)
  | Waiting, Start_check ->
    let transaction = {
      check.context.transaction with
      attempt = 1;
      sent_at = now;
    } in
    let context = { check.context with transaction } in
    let check = { check with state = In_progress; context } in
    let attrs = check.context.stun_attrs in
    let output = Send_stun_request {
      dest = check.context.remote_addr;
      transaction_id = transaction.id;
      username = attrs.username;
      password = attrs.password;
      use_candidate = attrs.use_candidate;
      priority = attrs.priority;
      ice_controlling = attrs.ice_controlling;
      ice_controlled = attrs.ice_controlled;
    } in
    (check, output)

  (* In_progress: Receive success response *)
  | In_progress, Stun_response_received { transaction_id; success = true; mapped_addr; _ } ->
    if Bytes.equal transaction_id check.context.transaction.id then
      let check = {
        check with
        state = Succeeded;
        nominated = check.context.stun_attrs.use_candidate;
      } in
      let output = Check_completed {
        success = true;
        nominated = check.nominated;
        mapped_addr;
        error = None;
      } in
      (check, output)
    else
      (* Wrong transaction ID, ignore *)
      (check, No_op)

  (* In_progress: Receive error response *)
  | In_progress, Stun_response_received { transaction_id; success = false; error_code; _ } ->
    if Bytes.equal transaction_id check.context.transaction.id then
      let error_msg = match error_code with
        | Some 487 -> "Role conflict"
        | Some 400 -> "Bad request"
        | Some 401 -> "Unauthorized"
        | Some code -> Printf.sprintf "STUN error %d" code
        | None -> "Unknown error"
      in
      let check = {
        check with
        state = Failed;
        last_error = Some error_msg;
      } in
      let output = Check_completed {
        success = false;
        nominated = false;
        mapped_addr = None;
        error = Some error_msg;
      } in
      (check, output)
    else
      (check, No_op)

  (* In_progress: Timer fired, maybe retransmit *)
  | In_progress, Timer_fired ->
    let tx = check.context.transaction in
    if tx.attempt >= tx.max_attempts then
      (* Max attempts reached, fail *)
      let check = {
        check with
        state = Failed;
        last_error = Some "Timeout after max retries";
      } in
      let output = Check_completed {
        success = false;
        nominated = false;
        mapped_addr = None;
        error = Some "Timeout";
      } in
      (check, output)
    else
      (* Retransmit with exponential backoff *)
      let new_rto = next_rto ~max_rto_ms:tx.max_rto_ms tx.rto_ms in
      let transaction = {
        tx with
        attempt = tx.attempt + 1;
        rto_ms = new_rto;
        sent_at = now;
      } in
      let context = { check.context with transaction } in
      let check = { check with context } in
      let attrs = check.context.stun_attrs in
      let output = Send_stun_request {
        dest = check.context.remote_addr;
        transaction_id = transaction.id;
        username = attrs.username;
        password = attrs.password;
        use_candidate = attrs.use_candidate;
        priority = attrs.priority;
        ice_controlling = attrs.ice_controlling;
        ice_controlled = attrs.ice_controlled;
      } in
      (check, output)

  (* Any state: Cancel *)
  | _, Cancel ->
    let check = {
      check with
      state = Failed;
      last_error = Some "Cancelled";
    } in
    (check, Cancel_timer)

  (* Terminal states or invalid transitions *)
  | Succeeded, _ | Failed, _ ->
    (check, No_op)

  | _, _ ->
    (check, No_op)

(** {1 Queries} *)

(** Get current state *)
let get_state check = check.state

(** Check if in terminal state *)
let is_terminal check =
  match check.state with
  | Succeeded | Failed -> true
  | _ -> false

(** Get nominated status *)
let is_nominated check = check.nominated

(** Get last error *)
let get_error check = check.last_error

(** Get transaction ID *)
let get_transaction_id check = check.context.transaction.id

(** Get current RTO *)
let get_rto check = check.context.transaction.rto_ms

(** {1 Check List Management} *)

(** Check list for managing multiple connectivity checks *)
type check_list = {
  checks: (int * t) list;     (** (pair_id, check) pairs *)
  next_id: int;
}

(** Create empty check list *)
let create_check_list () = {
  checks = [];
  next_id = 0;
}

(** Add check to list *)
let add_check list check =
  let id = list.next_id in
  let checks = (id, check) :: list.checks in
  ({ checks; next_id = id + 1 }, id)

(** Get check by ID *)
let get_check list id =
  List.assoc_opt id list.checks

(** Update check in list *)
let update_check list id check =
  let checks = List.map (fun (i, c) ->
    if i = id then (i, check) else (i, c)
  ) list.checks in
  { list with checks }

(** Get next waiting check (for scheduling) *)
let get_next_waiting list =
  List.find_opt (fun (_, check) ->
    check.state = Waiting
  ) list.checks

(** Get all succeeded checks *)
let get_succeeded list =
  List.filter_map (fun (id, check) ->
    if check.state = Succeeded then Some (id, check) else None
  ) list.checks

(** Check if any check succeeded *)
let has_succeeded list =
  List.exists (fun (_, check) -> check.state = Succeeded) list.checks

(** Check if all checks finished *)
let all_finished list =
  List.for_all (fun (_, check) -> is_terminal check) list.checks
