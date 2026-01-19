(** RFC 4566 SDP - Session Description Protocol

    Pure OCaml implementation for WebRTC SDP parsing/generation.

    @author Second Brain
    @since ocaml-webrtc 0.1.0
*)

(** {1 Types} *)

type net_type = IN
type addr_type = IP4 | IP6

type media_type =
  | Audio
  | Video
  | Application
  | Text
  | Message

type protocol =
  | UDP
  | RTP_AVP
  | RTP_SAVP
  | RTP_SAVPF
  | UDP_TLS_RTP_SAVPF
  | DTLS_SCTP
  | UDP_DTLS_SCTP

type connection = {
  net_type : net_type;
  addr_type : addr_type;
  address : string;
  ttl : int option;
  num_addresses : int option;
}

type origin = {
  username : string;
  sess_id : string;
  sess_version : int64;
  net_type : net_type;
  addr_type : addr_type;
  unicast_address : string;
}

type bandwidth = {
  bwtype : string;
  bandwidth : int;
}

type timing = {
  start_time : int64;
  stop_time : int64;
}

type ice_candidate = {
  foundation : string;
  component_id : int;
  transport : string;
  priority : int64;
  address : string;
  port : int;
  cand_type : string;
  rel_addr : string option;
  rel_port : int option;
  extensions : (string * string) list;
}

type fingerprint = {
  hash_func : string;
  fingerprint : string;
}

type rtpmap = {
  payload_type : int;
  encoding_name : string;
  clock_rate : int;
  encoding_params : string option;
}

type fmtp = {
  format : int;
  parameters : string;
}

type sctpmap = {
  port : int;
  protocol : string;
  streams : int option;
}

type media = {
  media_type : media_type;
  port : int;
  num_ports : int option;
  protocol : protocol;
  formats : string list;
  connection : connection option;
  bandwidths : bandwidth list;
  rtpmaps : rtpmap list;
  fmtps : fmtp list;
  ice_ufrag : string option;
  ice_pwd : string option;
  ice_options : string list;
  ice_candidates : ice_candidate list;
  fingerprint : fingerprint option;
  setup : string option;
  mid : string option;
  sctpmap : sctpmap option;
  max_message_size : int option;
  direction : string option;
  other_attrs : (string * string option) list;
}

type session = {
  version : int;
  origin : origin;
  session_name : string;
  session_info : string option;
  uri : string option;
  emails : string list;
  phones : string list;
  connection : connection option;
  bandwidths : bandwidth list;
  timings : timing list;
  ice_lite : bool;
  ice_ufrag : string option;
  ice_pwd : string option;
  ice_options : string list;
  fingerprint : fingerprint option;
  groups : (string * string list) list;
  msid_semantic : (string * string list) option;
  media : media list;
  other_attrs : (string * string option) list;
}

(** {1 Parsing Helpers} *)

let string_of_media_type = function
  | Audio -> "audio"
  | Video -> "video"
  | Application -> "application"
  | Text -> "text"
  | Message -> "message"

let media_type_of_string = function
  | "audio" -> Some Audio
  | "video" -> Some Video
  | "application" -> Some Application
  | "text" -> Some Text
  | "message" -> Some Message
  | _ -> None

let string_of_protocol = function
  | UDP -> "UDP"
  | RTP_AVP -> "RTP/AVP"
  | RTP_SAVP -> "RTP/SAVP"
  | RTP_SAVPF -> "RTP/SAVPF"
  | UDP_TLS_RTP_SAVPF -> "UDP/TLS/RTP/SAVPF"
  | DTLS_SCTP -> "DTLS/SCTP"
  | UDP_DTLS_SCTP -> "UDP/DTLS/SCTP"

let protocol_of_string = function
  | "UDP" -> Some UDP
  | "RTP/AVP" -> Some RTP_AVP
  | "RTP/SAVP" -> Some RTP_SAVP
  | "RTP/SAVPF" -> Some RTP_SAVPF
  | "UDP/TLS/RTP/SAVPF" -> Some UDP_TLS_RTP_SAVPF
  | "DTLS/SCTP" -> Some DTLS_SCTP
  | "UDP/DTLS/SCTP" -> Some UDP_DTLS_SCTP
  | _ -> None

let string_of_addr_type = function
  | IP4 -> "IP4"
  | IP6 -> "IP6"

let addr_type_of_string = function
  | "IP4" -> Some IP4
  | "IP6" -> Some IP6
  | _ -> None

let split_on_char c s =
  String.split_on_char c s

let trim = String.trim

(** {1 Parse Origin (o=)} *)

let parse_origin line =
  (* o=<username> <sess-id> <sess-version> <nettype> <addrtype> <unicast-address> *)
  match split_on_char ' ' line with
  | [username; sess_id; version; _nettype; addrtype; addr] ->
    (match addr_type_of_string addrtype, Int64.of_string_opt version with
    | Some at, Some v -> Ok {
        username;
        sess_id;
        sess_version = v;
        net_type = IN;
        addr_type = at;
        unicast_address = addr;
      }
    | _ -> Error "Invalid origin line")
  | _ -> Error "Invalid origin format"

(** {1 Parse Connection (c=)} *)

let parse_connection line =
  (* c=<nettype> <addrtype> <connection-address> *)
  match split_on_char ' ' line with
  | [_nettype; addrtype; addr] ->
    (match addr_type_of_string addrtype with
    | Some at -> Ok {
        net_type = IN;
        addr_type = at;
        address = addr;
        ttl = None;
        num_addresses = None;
      }
    | None -> Error "Invalid address type")
  | _ -> Error "Invalid connection format"

(** {1 Parse Media (m=)} *)

let parse_media_line line =
  (* m=<media> <port> <proto> <fmt> ... *)
  match split_on_char ' ' line with
  | media :: port_str :: proto :: formats ->
    (match media_type_of_string media,
           protocol_of_string proto,
           int_of_string_opt port_str with
    | Some mt, Some p, Some port -> Ok {
        media_type = mt;
        port;
        num_ports = None;
        protocol = p;
        formats;
        connection = None;
        bandwidths = [];
        rtpmaps = [];
        fmtps = [];
        ice_ufrag = None;
        ice_pwd = None;
        ice_options = [];
        ice_candidates = [];
        fingerprint = None;
        setup = None;
        mid = None;
        sctpmap = None;
        max_message_size = None;
        direction = None;
        other_attrs = [];
      }
    | _ -> Error "Invalid media line")
  | _ -> Error "Invalid media format"

(** {1 Parse ICE Candidate} *)

let parse_candidate line =
  (* a=candidate:<foundation> <component-id> <transport> <priority> <address> <port> typ <type> [extensions] *)
  let line = if String.length line > 10 && String.sub line 0 10 = "candidate:" then
    String.sub line 10 (String.length line - 10)
  else line in

  let parts = split_on_char ' ' line in
  match parts with
  | foundation :: comp :: transport :: priority :: addr :: port_str :: "typ" :: ctype :: rest ->
    (match int_of_string_opt comp,
           Int64.of_string_opt priority,
           int_of_string_opt port_str with
    | Some component_id, Some prio, Some port ->
      (* Parse extensions (raddr, rport, etc.) *)
      let rec parse_ext acc = function
        | [] -> acc
        | "raddr" :: v :: rest -> parse_ext (("raddr", v) :: acc) rest
        | "rport" :: v :: rest -> parse_ext (("rport", v) :: acc) rest
        | k :: v :: rest -> parse_ext ((k, v) :: acc) rest
        | _ :: rest -> parse_ext acc rest
      in
      let exts = parse_ext [] rest in
      let rel_addr = List.assoc_opt "raddr" exts in
      let rel_port = Option.bind (List.assoc_opt "rport" exts) int_of_string_opt in
      Ok {
        foundation;
        component_id;
        transport = String.uppercase_ascii transport;
        priority = prio;
        address = addr;
        port;
        cand_type = ctype;
        rel_addr;
        rel_port;
        extensions = List.filter (fun (k, _) -> k <> "raddr" && k <> "rport") exts;
      }
    | _ -> Error "Invalid candidate values")
  | _ -> Error "Invalid candidate format"

(** {1 Parse Fingerprint} *)

let parse_fingerprint line =
  (* a=fingerprint:<hash-func> <fingerprint> *)
  match split_on_char ' ' (trim line) with
  | [hash_func; fp] -> Ok { hash_func; fingerprint = fp }
  | hash_func :: fp_parts -> Ok { hash_func; fingerprint = String.concat " " fp_parts }
  | _ -> Error "Invalid fingerprint"

(** {1 Main Parser} *)

let parse sdp =
  let lines = String.split_on_char '\n' sdp |> List.map trim |> List.filter (fun l -> l <> "") in

  let default_session = {
    version = 0;
    origin = { username = "-"; sess_id = "0"; sess_version = 0L; net_type = IN; addr_type = IP4; unicast_address = "0.0.0.0" };
    session_name = "-";
    session_info = None;
    uri = None;
    emails = [];
    phones = [];
    connection = None;
    bandwidths = [];
    timings = [];
    ice_lite = false;
    ice_ufrag = None;
    ice_pwd = None;
    ice_options = [];
    fingerprint = None;
    groups = [];
    msid_semantic = None;
    media = [];
    other_attrs = [];
  } in

  let rec parse_lines session current_media = function
    | [] ->
      (* Finalize: add last media section *)
      let media = match current_media with
        | Some m -> session.media @ [m]
        | None -> session.media
      in
      Ok { session with media }

    | line :: rest when String.length line >= 2 ->
      let prefix = String.sub line 0 2 in
      let value = if String.length line > 2 then String.sub line 2 (String.length line - 2) else "" in

      (match prefix, current_media with
      (* Session-level *)
      | "v=", None ->
        parse_lines { session with version = int_of_string_opt value |> Option.value ~default:0 } None rest

      | "o=", None ->
        (match parse_origin value with
        | Ok o -> parse_lines { session with origin = o } None rest
        | Error _ -> parse_lines session None rest)

      | "s=", None ->
        parse_lines { session with session_name = value } None rest

      | "c=", None ->
        (match parse_connection value with
        | Ok c -> parse_lines { session with connection = Some c } None rest
        | Error _ -> parse_lines session None rest)

      | "t=", None ->
        (match split_on_char ' ' value with
        | [start; stop] ->
          let t = {
            start_time = Int64.of_string_opt start |> Option.value ~default:0L;
            stop_time = Int64.of_string_opt stop |> Option.value ~default:0L;
          } in
          parse_lines { session with timings = session.timings @ [t] } None rest
        | _ -> parse_lines session None rest)

      (* Media section starts *)
      | "m=", _ ->
        let new_session = match current_media with
          | Some m -> { session with media = session.media @ [m] }
          | None -> session
        in
        (match parse_media_line value with
        | Ok m -> parse_lines new_session (Some m) rest
        | Error _ -> parse_lines new_session None rest)

      (* Attributes *)
      | "a=", _ ->
        let (attr_name, attr_value) =
          match String.index_opt value ':' with
          | Some i -> (String.sub value 0 i, Some (String.sub value (i+1) (String.length value - i - 1)))
          | None -> (value, None)
        in
        (match current_media with
        | Some m ->
          let m' = match attr_name with
            | "ice-ufrag" -> { m with ice_ufrag = attr_value }
            | "ice-pwd" -> { m with ice_pwd = attr_value }
            | "fingerprint" ->
              (match attr_value with
              | Some v -> (match parse_fingerprint v with
                | Ok fp -> { m with fingerprint = Some fp }
                | Error _ -> m)
              | None -> m)
            | "setup" -> { m with setup = attr_value }
            | "mid" -> { m with mid = attr_value }
            | "candidate" ->
              (match attr_value with
              | Some v -> (match parse_candidate v with
                | Ok c -> { m with ice_candidates = m.ice_candidates @ [c] }
                | Error _ -> m)
              | None -> m)
            | "sctp-port" ->
              (match attr_value with
              | Some v -> { m with sctpmap = Some { port = int_of_string_opt v |> Option.value ~default:5000; protocol = "webrtc-datachannel"; streams = None } }
              | None -> m)
            | "max-message-size" ->
              { m with max_message_size = Option.bind attr_value int_of_string_opt }
            | "sendrecv" | "sendonly" | "recvonly" | "inactive" ->
              { m with direction = Some attr_name }
            | _ -> { m with other_attrs = m.other_attrs @ [(attr_name, attr_value)] }
          in
          parse_lines session (Some m') rest
        | None ->
          let session' = match attr_name with
            | "ice-lite" -> { session with ice_lite = true }
            | "ice-ufrag" -> { session with ice_ufrag = attr_value }
            | "ice-pwd" -> { session with ice_pwd = attr_value }
            | "fingerprint" ->
              (match attr_value with
              | Some v -> (match parse_fingerprint v with
                | Ok fp -> { session with fingerprint = Some fp }
                | Error _ -> session)
              | None -> session)
            | "group" ->
              (match attr_value with
              | Some v ->
                let parts = split_on_char ' ' v in
                (match parts with
                | semantics :: ids -> { session with groups = session.groups @ [(semantics, ids)] }
                | _ -> session)
              | None -> session)
            | _ -> { session with other_attrs = session.other_attrs @ [(attr_name, attr_value)] }
          in
          parse_lines session' None rest)

      | _ -> parse_lines session current_media rest)

    | _ :: rest -> parse_lines session current_media rest
  in

  parse_lines default_session None lines

let parse_media sdp =
  match parse ("m=" ^ sdp) with
  | Ok s -> (match s.media with
    | m :: _ -> Ok m
    | [] -> Error "Failed to parse media: no media section")
  | Error e -> Error ("Failed to parse media: " ^ e)

(** {1 Generation} *)

let rec to_string session =
  let buf = Buffer.create 1024 in
  let add s = Buffer.add_string buf s; Buffer.add_char buf '\n' in

  add (Printf.sprintf "v=%d" session.version);
  add (Printf.sprintf "o=%s %s %Ld IN %s %s"
    session.origin.username
    session.origin.sess_id
    session.origin.sess_version
    (string_of_addr_type session.origin.addr_type)
    session.origin.unicast_address);
  add (Printf.sprintf "s=%s" session.session_name);

  Option.iter (fun (c : connection) ->
    add (Printf.sprintf "c=IN %s %s" (string_of_addr_type c.addr_type) c.address)
  ) session.connection;

  List.iter (fun t ->
    add (Printf.sprintf "t=%Ld %Ld" t.start_time t.stop_time)
  ) session.timings;

  if session.ice_lite then add "a=ice-lite";
  Option.iter (fun v -> add (Printf.sprintf "a=ice-ufrag:%s" v)) session.ice_ufrag;
  Option.iter (fun v -> add (Printf.sprintf "a=ice-pwd:%s" v)) session.ice_pwd;
  Option.iter (fun fp -> add (Printf.sprintf "a=fingerprint:%s %s" fp.hash_func fp.fingerprint)) session.fingerprint;

  List.iter (fun (sem, ids) ->
    add (Printf.sprintf "a=group:%s %s" sem (String.concat " " ids))
  ) session.groups;

  List.iter (fun m ->
    add (Printf.sprintf "m=%s %d %s %s"
      (string_of_media_type m.media_type)
      m.port
      (string_of_protocol m.protocol)
      (String.concat " " m.formats));

    Option.iter (fun (c : connection) ->
      add (Printf.sprintf "c=IN %s %s" (string_of_addr_type c.addr_type) c.address)
    ) m.connection;

    Option.iter (fun v -> add (Printf.sprintf "a=ice-ufrag:%s" v)) m.ice_ufrag;
    Option.iter (fun v -> add (Printf.sprintf "a=ice-pwd:%s" v)) m.ice_pwd;
    Option.iter (fun fp -> add (Printf.sprintf "a=fingerprint:%s %s" fp.hash_func fp.fingerprint)) m.fingerprint;
    Option.iter (fun v -> add (Printf.sprintf "a=setup:%s" v)) m.setup;
    Option.iter (fun v -> add (Printf.sprintf "a=mid:%s" v)) m.mid;

    Option.iter (fun (sm : sctpmap) ->
      add (Printf.sprintf "a=sctp-port:%d" sm.port);
    ) m.sctpmap;

    Option.iter (fun v -> add (Printf.sprintf "a=max-message-size:%d" v)) m.max_message_size;
    Option.iter (fun v -> add (Printf.sprintf "a=%s" v)) m.direction;

    List.iter (fun c ->
      add (Printf.sprintf "a=%s" (candidate_to_string c))
    ) m.ice_candidates;
  ) session.media;

  Buffer.contents buf

and media_to_string m =
  to_string { version = 0; origin = { username = "-"; sess_id = "0"; sess_version = 0L; net_type = IN; addr_type = IP4; unicast_address = "0.0.0.0" }; session_name = "-"; session_info = None; uri = None; emails = []; phones = []; connection = None; bandwidths = []; timings = []; ice_lite = false; ice_ufrag = None; ice_pwd = None; ice_options = []; fingerprint = None; groups = []; msid_semantic = None; media = [m]; other_attrs = [] }

and candidate_to_string c =
  let base = Printf.sprintf "candidate:%s %d %s %Ld %s %d typ %s"
    c.foundation c.component_id (String.lowercase_ascii c.transport)
    c.priority c.address c.port c.cand_type in
  let with_rel = match c.rel_addr, c.rel_port with
    | Some ra, Some rp -> Printf.sprintf "%s raddr %s rport %d" base ra rp
    | _ -> base
  in
  List.fold_left (fun acc (k, v) -> Printf.sprintf "%s %s %s" acc k v) with_rel c.extensions

(** {1 Offer/Answer Helpers} *)

let create_datachannel_offer ~ice_ufrag ~ice_pwd ~fingerprint ~sctp_port =
  {
    version = 0;
    origin = {
      username = "-";
      sess_id = string_of_int (Random.int 1000000000);
      sess_version = 1L;
      net_type = IN;
      addr_type = IP4;
      unicast_address = "127.0.0.1";
    };
    session_name = "-";
    session_info = None;
    uri = None;
    emails = [];
    phones = [];
    connection = Some { net_type = IN; addr_type = IP4; address = "0.0.0.0"; ttl = None; num_addresses = None };
    bandwidths = [];
    timings = [{ start_time = 0L; stop_time = 0L }];
    ice_lite = false;
    ice_ufrag = Some ice_ufrag;
    ice_pwd = Some ice_pwd;
    ice_options = [];
    fingerprint = Some fingerprint;
    groups = [("BUNDLE", ["0"])];
    msid_semantic = Some ("WMS", []);
    media = [{
      media_type = Application;
      port = 9;
      num_ports = None;
      protocol = UDP_DTLS_SCTP;
      formats = ["webrtc-datachannel"];
      connection = None;
      bandwidths = [];
      rtpmaps = [];
      fmtps = [];
      ice_ufrag = None;
      ice_pwd = None;
      ice_options = [];
      ice_candidates = [];
      fingerprint = None;
      setup = Some "actpass";
      mid = Some "0";
      sctpmap = Some { port = sctp_port; protocol = "webrtc-datachannel"; streams = Some 1024 };
      max_message_size = Some 262144;
      direction = None;
      other_attrs = [];
    }];
    other_attrs = [];
  }

let create_answer ~offer ~ice_ufrag ~ice_pwd ~fingerprint =
  { offer with
    origin = { offer.origin with sess_version = Int64.succ offer.origin.sess_version };
    ice_ufrag = Some ice_ufrag;
    ice_pwd = Some ice_pwd;
    fingerprint = Some fingerprint;
    media = List.map (fun m ->
      { m with
        setup = Some "active";  (* Answer is active if offer is actpass *)
        ice_candidates = [];    (* Will add our own candidates *)
      }
    ) offer.media;
  }

let add_candidate session candidate ~media_index =
  if media_index >= 0 && media_index < List.length session.media then
    let media = List.mapi (fun i m ->
      if i = media_index then
        { m with ice_candidates = m.ice_candidates @ [candidate] }
      else m
    ) session.media in
    { session with media }
  else session

let get_candidates session =
  List.concat_map (fun m -> m.ice_candidates) session.media

(** {1 Utilities} *)

let find_media_by_mid session mid =
  List.find_opt (fun m -> m.mid = Some mid) session.media

let find_media_by_type session mt =
  List.find_opt (fun m -> m.media_type = mt) session.media

let find_media_by_index session index =
  if index < 0 then None else List.nth_opt session.media index

let resolve_ice_credentials (session : session) (media : media) =
  match media.ice_ufrag, media.ice_pwd with
  | Some ufrag, Some pwd -> Some (ufrag, pwd)
  | _ ->
    (match session.ice_ufrag, session.ice_pwd with
    | Some ufrag, Some pwd -> Some (ufrag, pwd)
    | _ -> None)

let resolve_ice_options (session : session) (media : media) =
  let add acc opt = if List.mem opt acc then acc else acc @ [opt] in
  let acc = List.fold_left add [] session.ice_options in
  List.fold_left add acc media.ice_options

let resolve_fingerprint (session : session) (media : media) =
  match media.fingerprint with
  | Some fp -> Some fp
  | None -> session.fingerprint

let resolve_sctp_port media =
  match media.sctpmap with
  | Some sm -> Some sm.port
  | None -> None

let has_datachannel session =
  List.exists (fun m ->
    m.media_type = Application &&
    (m.protocol = DTLS_SCTP || m.protocol = UDP_DTLS_SCTP)
  ) session.media

let pp_session fmt session =
  Format.fprintf fmt "%s" (to_string session)

let pp_media fmt media =
  Format.fprintf fmt "%s" (media_to_string media)
