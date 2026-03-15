# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.2] - 2026-03-16

### Added
- `Webrtc_constants` module — centralized RFC constants with section comments

### Changed
- Migrate `String.sub` prefix checks to `String.starts_with` in ice.ml, ice_eio.ml, sdp.ml
- Extract duplicate `default_session` in sdp.ml — 5 copies to 1 shared value
- Replace hardcoded port/buffer/address values with `Webrtc_constants`

### Fixed
- **SCTP bundle data loss** — flushed bundles from `Sctp_bundling.add_chunk` now emitted instead of discarded
- **UDP sendto partial send** — `ice_eio.ml` detects and warns on short writes
- **Unix error context** — `discover_local_ip` logs `Unix.Unix_error` details instead of silent `None`

## [0.2.1] - 2026-03-09

### Security

- Replace all stdlib `Random` (non-cryptographic PRNG) with `mirage-crypto-rng` CSPRNG
  across SCTP, ICE, STUN, SDP, and TURN modules (#31, #32).
- Fix `Int32.abs Int32.min_int` edge case in SDP session ID generation -- use
  `Int32.logand` to mask sign bit instead (#32).
- Add rejection sampling in ICE credential generation to eliminate modulo bias (#31).

### Changed

- Centralize `ensure_rng_initialized` into `Webrtc_crypto` module (was incorrectly
  placed in `Dtls_eio`) (#30, #31).
- Add `random_bytes_raw`, `random_int32`, `random_nonzero_int32` helpers to
  `Webrtc_crypto` with `.mli` interface (#31).
- Rename `Webrtc_common.random_bytes` to `random_fill_insecure` with warning
  docstring for non-security buffer fill usage (#31).
- Widen exception handling in `ensure_rng_initialized` from `Failure _` only
  to `Failure _ | Sys_error _` (#31).

## [0.2.0] - 2026-03-08

### Changed

- Quality sweep: exception narrowing, `.mli` interfaces for public modules (#29).
- Use `Log.warn` for SCTP errors, hoist `now()` from loops (#28).
- Migrate `Time_compat.now` and log SCTP send failures (#27).
- Upgrade `time_compat.ml` to canonical Variant C (#26).
- Extract `send_sctp_packets` helper with error logging (#25).

## [0.1.3] - 2026-03-07

### Changed

- Fix ocamlformat drift in `time_compat.ml` (#23).
- Initial test infrastructure with bisect_ppx (#22).

## [0.1.2] - 2026-03-06

### Added

- Initial pure OCaml WebRTC implementation: DTLS, SCTP, ICE, STUN, TURN, SDP, SRTP.
