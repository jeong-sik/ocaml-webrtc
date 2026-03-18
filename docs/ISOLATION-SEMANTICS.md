# OAS Isolation Semantics

How connections, state, and resources are isolated in the OAS stack.

## Connection Independence

Each `Sctp_core.t` instance is fully independent:

- No shared mutable state between instances
- No global singletons (each has own TSN counter, vtag, timers)
- One instance = one SCTP association

This means N connections = N independent state machines with zero cross-contamination.

## Sans-IO Isolation

`Sctp_core` is Sans-IO: it performs zero I/O operations.

| What it does | What it does not do |
|---|---|
| Accept inputs, produce outputs | Read/write sockets |
| Track timers (symbolic) | Sleep or block |
| Manage congestion state | Allocate OS resources |

The I/O layer (`Sctp_eio`) translates outputs to actual operations. This separation means `Sctp_core` can be tested without any OS interaction.

## Eio Switch Relationship

Each WebRTC connection lives inside an `Eio.Switch.run` scope:

```
Switch.run (fun sw ->
  (* ICE, DTLS, SCTP resources scoped to this switch *)
  (* Switch cancellation cleans up all fibers *)
)
```

The `Lifecycle` module (introduced in Sprint 3) provides phase-ordered cleanup within a switch, ensuring resources are released newest-first even on partial failures.

## Threading Model

OAS uses Eio fibers (cooperative multitasking on OCaml 5 effects):

- **No preemptive threads**: No data races possible within a fiber
- **No locks needed**: State machine operations are fiber-local
- **Yield points**: Only at explicit Eio operations (socket read/write, sleep)

Cross-fiber communication uses Eio primitives:
- `Eio.Stream` for packet queues
- `Eio.Promise` for one-shot signals

## Shared State Boundaries

| Component | Shared? | Scope |
|-----------|---------|-------|
| `Sctp_core.t` | No | Per-connection |
| `Buffer_pool.t` | Optional | Per-transport or global |
| `Webrtc_crypto` RNG | Process-global | `mirage-crypto-rng` entropy pool |
| Timer scheduling | Per-switch | Eio `Clock` |

The only process-global shared resource is the cryptographic RNG, which is thread-safe by design (`mirage-crypto-rng` uses domain-local state on OCaml 5).

## Error Isolation

Errors in one connection do not affect others:

1. `Sctp_core.handle` returns `Error of string` — never raises
2. `Oas_error.classify` categorizes for local recovery decisions
3. `Lifecycle.fail` cleans up only the affected connection's resources

Exception propagation is contained by `Switch.run` — a failing connection's switch cancellation does not reach other switches.

## Determinism Guarantee

`Sctp_core` is deterministic given:
- Same `config` (src_port, dst_port, initial_tsn, my_vtag)
- Same input sequence
- Same timestamps (`set_now`)

Exception: Heartbeat chunks contain a random nonce from `Webrtc_crypto.random_int32()`. The `Replay_harness` handles this via structural comparison.
