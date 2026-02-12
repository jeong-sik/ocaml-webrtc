(** Fiber-aware sleep compatibility.

    When an Eio clock is registered via {!set_clock}, {!sleep} suspends only
    the current fiber.  Otherwise it falls back to [Unix.sleepf]. *)

let global_clock : float Eio.Time.clock_ty Eio.Resource.t option ref = ref None

let set_clock clock = global_clock := Some clock

let sleep seconds =
  match !global_clock with
  | Some clock -> Eio.Time.sleep clock seconds
  | None -> Unix.sleepf seconds
