(** DTLS Protocol Types — Shared type definitions for DTLS 1.2

    Extracted from dtls.ml to break the God Object pattern.
    All DTLS sub-modules (dtls_codec, dtls_retransmit, etc.) depend on these types.

    @author Second Brain
    @since ocaml-webrtc 0.2.2
*)

type _ Stdlib.Effect.t +=
  | Send : bytes -> int Effect.t
  | Recv : int -> bytes Effect.t
  | Now : float Effect.t
  | Random : int -> bytes Effect.t
  | SetTimer : int -> unit Effect.t
  | CancelTimer : unit Effect.t

type content_type =
  | ChangeCipherSpec
  | Alert
  | Handshake
  | ApplicationData

type handshake_type =
  | HelloRequest
  | ClientHello
  | ServerHello
  | HelloVerifyRequest
  | Certificate
  | ServerKeyExchange
  | CertificateRequest
  | ServerHelloDone
  | CertificateVerify
  | ClientKeyExchange
  | Finished

type alert_level =
  | Warning
  | Fatal

type alert_description =
  | CloseNotify
  | UnexpectedMessage
  | BadRecordMac
  | DecryptionFailed
  | RecordOverflow
  | DecompressionFailure
  | HandshakeFailure
  | BadCertificate
  | UnsupportedCertificate
  | CertificateRevoked
  | CertificateExpired
  | CertificateUnknown
  | IllegalParameter
  | UnknownCA
  | AccessDenied
  | DecodeError
  | DecryptError
  | ProtocolVersion
  | InsufficientSecurity
  | InternalError
  | UserCanceled
  | NoRenegotiation

type state =
  | Initial
  | HelloSent
  | HelloVerifyReceived
  | ServerHelloReceived
  | CertificateReceived
  | KeyExchangeDone
  | ChangeCipherSpecSent
  | Established
  | Closed
  | Error of string
  | HelloVerifySent
  | ClientHelloReceived
  | ServerFlightSent
  | ClientKeyExchangeReceived

type cipher_suite =
  | TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
  | TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
  | TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
  | TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384

type srtp_profile = Srtp.profile

type config =
  { is_client : bool
  ; certificate : string option
  ; private_key : string option
  ; verify_peer : bool
  ; cipher_suites : cipher_suite list
  ; srtp_profiles : Srtp.profile list
  ; mtu : int
  ; retransmit_timeout_ms : int
  ; max_retransmits : int
  }

type crypto_state =
  { mutable client_write_key : bytes option
  ; mutable server_write_key : bytes option
  ; mutable client_write_iv : bytes option
  ; mutable server_write_iv : bytes option
  ; mutable read_seq_num : int64
  ; mutable write_seq_num : int64
  }

type handshake_state =
  { mutable client_random : bytes option
  ; mutable server_random : bytes option
  ; mutable premaster_secret : bytes option
  ; mutable master_secret : bytes option
  ; mutable handshake_messages : bytes list
  ; mutable cookie : bytes option
  ; mutable message_seq : int
  ; mutable next_receive_seq : int
  ; mutable pending_fragments : (int * bytes) list
  ; mutable ecdhe_keypair : Ecdhe.keypair option
  ; mutable server_public_key : Cstruct.t option
  ; mutable selected_curve : Ecdhe.named_curve option
  }

type retransmit_state =
  { mutable last_flight : bytes list
  ; mutable retransmit_count : int
  ; mutable current_timeout_ms : int
  ; mutable flight_sent_at : float
  ; mutable timer_active : bool
  }

type t =
  { config : config
  ; mutable state : state
  ; mutable negotiated_cipher : cipher_suite option
  ; mutable negotiated_srtp_profile : Srtp.profile option
  ; mutable peer_certificate : string option
  ; mutable epoch : int
  ; crypto : crypto_state
  ; handshake : handshake_state
  ; retransmit : retransmit_state
  }

type io_ops =
  { send : bytes -> int
  ; recv : int -> bytes
  ; now : unit -> float
  ; random : int -> bytes
  ; set_timer : int -> unit
  ; cancel_timer : unit -> unit
  }
