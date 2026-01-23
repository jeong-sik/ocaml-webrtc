(** Simple logging module using Printf *)

let error fmt = Printf.ksprintf (fun s -> Printf.eprintf "[ERROR] %s\n%!" s) fmt
let warn fmt = Printf.ksprintf (fun s -> Printf.eprintf "[WARN] %s\n%!" s) fmt
let info fmt = Printf.ksprintf (fun s -> Printf.printf "[INFO] %s\n%!" s) fmt
let debug fmt = Printf.ksprintf (fun s -> Printf.printf "[DEBUG] %s\n%!" s) fmt
