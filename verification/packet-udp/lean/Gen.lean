import Ip
import Lean

open Lean

/-- `lake exe gen <dir> <seed>`: writes `<dir>/<stem>.json` for every vector
file of every module. The same seed always gives the same files. -/
def main (args : List String) : IO UInt32 := do
  match args with
  | [dir, seed] =>
    let some seed := seed.toNat? | IO.eprintln "seed must be a number"; return 1
    let files :=
      Ip.Checksum.vectors seed ++ Ip.Header.vectors seed ++ Ip.Udp.vectors seed ++
      Ip.Reassembly.vectors seed ++ Ip.Ext6.vectors seed ++ Ip.Icmp.vectors seed
    IO.FS.createDirAll dir
    for (stem, cases) in files do
      IO.FS.writeFile (System.FilePath.mk dir / s!"{stem}.json") cases.compress
    return 0
  | _ => IO.eprintln "usage: gen <dir> <seed>"; return 1
