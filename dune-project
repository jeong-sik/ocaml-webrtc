(lang dune 3.13)
(name ocaml-webrtc)
(version 0.6.0)

(generate_opam_files true)

(package
 (name ocaml-webrtc)
 (synopsis "Pure OCaml WebRTC implementation")
 (description "Complete WebRTC stack: DTLS, SCTP, ICE, STUN, TURN")
 (depends
  (ocaml (>= 5.1))
  (dune (>= 3.13))
  (eio (>= 1.0))
  (mirage-crypto (>= 1.0.0))
  (mirage-crypto-rng (>= 1.0.0))
  (x509 (>= 1.0.0))
  (tls (>= 2.0.0))
  (ptime (>= 1.2.0))
  (cstruct (>= 6.0.0))
  (digestif (>= 1.1.0))
  (logs (>= 0.7.0))
  (fmt (>= 0.9.0))))
