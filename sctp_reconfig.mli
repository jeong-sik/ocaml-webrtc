(** RFC 6525 - SCTP Re-configuration chunk helpers *)

type reconfig_param =
  | Outgoing_ssn_reset of {
      request_seq : int32;
      response_seq : int32;
      last_tsn : int32;
      streams : int list;
    }
  | Incoming_ssn_reset of {
      request_seq : int32;
      response_seq : int32;
      last_tsn : int32;
      streams : int list;
    }
  | Reconfig_response of {
      response_seq : int32;
      result : int32;
    }
  | Add_outgoing_streams of {
      request_seq : int32;
      new_streams : int;
    }
  | Add_incoming_streams of {
      request_seq : int32;
      new_streams : int;
    }
  | Unknown of int * bytes

type t = reconfig_param list

val encode_params : reconfig_param list -> bytes
val decode_params : bytes -> (reconfig_param list, string) result
val to_raw_chunk : reconfig_param list -> Sctp.raw_chunk
val of_raw_chunk : Sctp.raw_chunk -> (reconfig_param list, string) result
