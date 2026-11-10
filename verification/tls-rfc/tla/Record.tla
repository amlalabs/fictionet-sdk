------------------------------ MODULE Record ------------------------------
(* The TLS record layer as RFC 8446 sections 5, 6 and 4.6.3 (and RFC 5246  *)
(* section 6.2 for TLS 1.2) set it out, over one connection, both ways.    *)
(*                                                                         *)
(* Two sides, "C" (client) and "S" (server). Each sends records on its own *)
(* in-order stream (TCP) and reads the other's. A record carries its       *)
(* content type, the epoch of the keys it was protected under (0: not      *)
(* protected), its sequence number under those keys, whether it is         *)
(* authentic (AEAD abstracted: a record decrypts if and only if it is      *)
(* authentic, under the reader's current keys and at the reader's next     *)
(* sequence number), the length class of its wire length and of its        *)
(* plaintext, and the epoch its message moves to (`ne`, -1 for none): the  *)
(* handshake messages after which the keys change (the first flight,       *)
(* EndOfEarlyData, Finished in TLS 1.3, ChangeCipherSpec in TLS 1.2) and   *)
(* KeyUpdate. Epochs: 0 none, 1 early data (client only), 2 handshake      *)
(* keys, 3 application keys, 4 and up after key updates. TLS 1.2 goes      *)
(* from 0 to 3 at ChangeCipherSpec.                                        *)
(*                                                                         *)
(* The handshake itself is a fixed script of records per side (Script);   *)
(* its messages' meaning is out of scope. An attacker on the wire may     *)
(* inject forged records or replay earlier ones. With Misbehave, the       *)
(* client may also send authentic records the RFCs forbid (oversize,       *)
(* empty handshake or alert, data after close_notify), so that the         *)
(* reader's checks are exercised. Early data is either absent, accepted   *)
(* or rejected (the reader then skips records it cannot deprotect, up to   *)
(* an allowance, RFC 8446 section 4.2.10).                                 *)
(*                                                                         *)
(* Length classes, by wire length: Z 0, S 1..2^14-1, F 2^14, O1            *)
(* 2^14+1..2^14+256, O2 2^14+257..2^14+2047, O3 2^14+2048, O4 more. A      *)
(* plaintext is Z, S, F, or O (more than 2^14). Limits: an unprotected     *)
(* record at most F; a TLS 1.3 protected one at most O1; a TLS 1.2         *)
(* protected one at most O3; any plaintext at most F.                      *)
(*                                                                         *)
(* The RFC rules are written as actions; the properties below restate     *)
(* what the RFCs require of the result, over history variables (sent,     *)
(* acc, got, due, fails). The flags are RFC rules; a control config drops  *)
(* one and names the property that must then fail. RecordCode refines     *)
(* this module with the server replaced by the vendored rustls code.       *)
(*                                                                         *)
(* Bounds: MaxAppC and MaxAppS application records, MaxKU key update      *)
(* requests per side, MaxForge attacker injections, MaxBad misbehaving     *)
(* records, MaxHs further handshake records (0 in the model configs; the   *)
(* trace check sets it for the real flights). One of each is enough to put *)
(* every kind of record at every point of the other stream: the streams    *)
(* interleave freely. A side that is over has no read keys (re = rs = -1). *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
  V,          \* "1.2" or "1.3"
  Early,      \* "none", "accept" or "reject": early data from the client
  Allowance,  \* records the server may skip while early data is rejected
  Frag,       \* the client's Finished comes in two records
  Compat,     \* TLS 1.3 compatibility ChangeCipherSpec records (RFC 8446 D.4)
  Wide,       \* TLS 1.2 protected records up to 2^14+2048 (block ciphers)
  AppPls,     \* plaintext length classes of application data writers use
  MaxAppC, MaxAppS, MaxKU, MaxForge, MaxBad,
  MaxHs,      \* further handshake records a side may send in its handshake
  Misbehave,  \* the client may send records the RFCs forbid
  \* RFC rules; TRUE is the RFC.
  ReplyFirst,       \* 4.6.3: a KeyUpdate in reply goes before the next application data
  CheckSeq,         \* 5.3: the nonce is the reader's next sequence number
  IgnoreAfterClose, \* 6.1: data after a received close_notify is ignored
  QuietAfterClose,  \* 6.1: nothing is sent after close_notify
  CheckSize         \* 5.1, 5.2; RFC 5246 6.2: record_overflow past the limits

ASSUME V \in {"1.2", "1.3"} /\ Early \in {"none", "accept", "reject"}
ASSUME V = "1.2" => Early = "none" /\ ~Compat
ASSUME MaxAppC \in Nat /\ MaxAppS \in Nat /\ MaxKU \in Nat /\ MaxForge \in Nat /\ MaxBad \in Nat
ASSUME MaxHs \in Nat

Sides == {"C", "S"}
Peer(x) == IF x = "C" THEN "S" ELSE "C"
MaxApp(x) == IF x = "C" THEN MaxAppC ELSE MaxAppS

Ord == [Z |-> 0, S |-> 1, F |-> 2, O1 |-> 3, O2 |-> 4, O3 |-> 5, O4 |-> 6]
MaxLen(prot) == IF ~prot THEN 2 ELSE IF V = "1.3" THEN 3 ELSE 5

VARIABLES
  wire,   \* [Sides -> Seq(record)]: what x sent (or was injected as x's), not yet read by Peer(x)
  st,     \* [Sides -> side state], below
  forged, \* attacker injections used
  bad,    \* misbehaving records used
  sent,   \* history: the records x sent, in order
  acc,    \* history: [r, prot, ke, ks] the records x accepted, with its read keys and sequence number
  got,    \* history: the ids of the application data x delivered
  due,    \* history: positions in sent[x] after which x owes a KeyUpdate
  fails   \* history: [x, r, prot, al, why, quiet] each reader's failure

vars == <<wire, st, forged, bad, sent, acc, got, due, fails>>

(* A side: write epoch and sequence number, read epoch and sequence       *)
(* number, script position, the peer's Finished received, a handshake     *)
(* message being joined, skipping undeprotectable records and what is     *)
(* left to skip, a KeyUpdate owed, close_notify sent and received, over   *)
(* (failed, or sent or received a fatal alert: no read keys then), CCS    *)
(* for compatibility sent,                                                 *)
(* application records, key update requests and further handshake       *)
(* records written.                                                       *)
St0 == [we |-> 0, ws |-> 0, re |-> 0, rs |-> 0, sp |-> 1, finR |-> FALSE,
        more |-> FALSE, trial |-> FALSE, allow |-> Allowance, pend |-> FALSE,
        closeS |-> FALSE, closeR |-> FALSE, dead |-> FALSE, cc |-> FALSE,
        appW |-> 0, kuW |-> 0, hsX |-> 0]

-----------------------------------------------------------------------------
(* The handshake script *)

Step(t, k, ne) == [t |-> t, k |-> k, ne |-> ne]

Script(x) ==
  IF V = "1.2"
  THEN <<Step("hs", "hs", -1), Step("ccs", "ccs", 3), Step("hs", "fin", -1)>>
  ELSE LET first == Step("hs", "hs", IF x = "C" /\ Early # "none" THEN 1 ELSE 2)
           mid == IF x = "C" /\ Early = "accept" THEN <<Step("hs", "eoed", 2)>>
                  ELSE IF x = "C" /\ Early = "reject" THEN <<Step("none", "switch", 2)>>
                  ELSE <<>>
           fin == IF x = "C" /\ Frag THEN <<Step("hs", "frag", -1), Step("hs", "fin", 3)>>
                  ELSE <<Step("hs", "fin", 3)>>
       IN <<first>> \o mid \o fin

ScriptDone(s, x) == s.sp > Len(Script(x))

-----------------------------------------------------------------------------
(* Writing *)

\* The wire lengths an honest writer gives a plaintext of class pl.
HonestLens(pl, prot) ==
  IF ~prot THEN {pl}
  ELSE IF pl = "F" THEN (IF V = "1.2" /\ Wide THEN {"O1", "O3"} ELSE {"O1"})
  ELSE {"S"}

\* -2 for ne: the next epoch (a KeyUpdate).
NE(s, ne) == IF ne = -2 THEN s.we + 1 ELSE ne

Mk(s, t, k, pl, len, ne, id) ==
  [t |-> t, k |-> k, e |-> s.we, n |-> IF s.we > 0 THEN s.ws ELSE 0, a |-> TRUE,
   len |-> len, pl |-> pl, ne |-> NE(s, ne), id |-> id]

\* The writer after sending r: new keys after a key-changing message
\* (sequence numbers start at 0, 5.3), else the next sequence number.
After(s, r) ==
  IF r.ne >= 0 THEN [s EXCEPT !.we = r.ne, !.ws = 0]
  ELSE IF r.e > 0 THEN [s EXCEPT !.ws = @ + 1]
  ELSE s

KURec(s) == Mk(s, "hs", "ku", "S", "S", -2, 0)

\* Sending one record, after the KeyUpdate owed if p: the records and the
\* writer after them.
Emission(s, p, t, k, pl, len, ne, id) ==
  LET s1 == IF p THEN [After(s, KURec(s)) EXCEPT !.pend = FALSE] ELSE s
      r == Mk(s1, t, k, pl, len, ne, id)
      pre == IF p THEN <<KURec(s)>> ELSE <<>>
  IN [recs |-> pre \o <<r>>, st |-> After(s1, r)]

\* Whether the owed KeyUpdate may go first, or must.
Prefixes(s, isApp) ==
  IF ~s.pend THEN {FALSE}
  ELSE IF isApp /\ ReplyFirst THEN {TRUE} ELSE {TRUE, FALSE}

Writing(x) == ~st[x].dead /\ ~st[x].closeS

Put(x, em, upd) ==
  /\ wire' = [wire EXCEPT ![x] = @ \o em.recs]
  /\ sent' = [sent EXCEPT ![x] = @ \o em.recs]
  /\ st' = [st EXCEPT ![x] = upd]

CanApp(s, x) == ScriptDone(s, x) \/ (x = "C" /\ Early # "none" /\ s.we = 1)

SendScript(x) ==
  /\ Writing(x) /\ ~ScriptDone(st[x], x)
  /\ LET step == Script(x)[st[x].sp] IN
     IF step.t = "none"
     THEN /\ st' = [st EXCEPT ![x].we = step.ne, ![x].ws = 0, ![x].sp = @ + 1]
          /\ UNCHANGED <<wire, sent>>
     ELSE LET em == Emission(st[x], FALSE, step.t, step.k, "S", "S", step.ne, 0)
          IN Put(x, em, [em.st EXCEPT !.sp = @ + 1])
  /\ UNCHANGED <<forged, bad, acc, got, due, fails>>

\* A further handshake record within the handshake: unprotected before the
\* first key change, or under the TLS 1.3 handshake keys (a flight that
\* takes more than one record).
SendHs(x) ==
  /\ Writing(x) /\ st[x].sp > 1 /\ ~ScriptDone(st[x], x) /\ st[x].hsX < MaxHs
  /\ st[x].we = 0 \/ (V = "1.3" /\ st[x].we = 2)
  /\ LET em == Emission(st[x], FALSE, "hs", "hs", "S", "S", -1, 0)
     IN Put(x, em, [em.st EXCEPT !.hsX = @ + 1])
  /\ UNCHANGED <<forged, bad, acc, got, due, fails>>

SendApp(x) ==
  /\ Writing(x) /\ CanApp(st[x], x) /\ st[x].appW < MaxApp(x)
  /\ \E pl \in AppPls, p \in Prefixes(st[x], TRUE):
       \E len \in HonestLens(pl, st[x].we > 0):
         LET em == Emission(st[x], p, "app", "data", pl, len, -1, st[x].appW + 1)
         IN Put(x, em, [em.st EXCEPT !.appW = @ + 1])
  /\ UNCHANGED <<forged, bad, acc, got, due, fails>>

\* A KeyUpdate in reply (update_not_requested), or a request.
SendKU(x) ==
  /\ V = "1.3" /\ Writing(x) /\ ScriptDone(st[x], x)
  /\ \/ /\ st[x].pend
        /\ LET em == Emission(st[x], FALSE, "hs", "ku", "S", "S", -2, 0)
           IN Put(x, em, [em.st EXCEPT !.pend = FALSE])
     \/ /\ st[x].kuW < MaxKU
        /\ \E p \in Prefixes(st[x], FALSE):
             LET em == Emission(st[x], p, "hs", "kureq", "S", "S", -2, 0)
             IN Put(x, em, [em.st EXCEPT !.kuW = @ + 1])
  /\ UNCHANGED <<forged, bad, acc, got, due, fails>>

SendClose(x) ==
  /\ Writing(x) /\ ScriptDone(st[x], x)
  /\ \E p \in Prefixes(st[x], FALSE):
       LET em == Emission(st[x], p, "alert", "close", "S", "S", -1, 0)
       IN Put(x, em, [em.st EXCEPT !.closeS = TRUE])
  /\ UNCHANGED <<forged, bad, acc, got, due, fails>>

\* An unprotected change_cipher_spec during the TLS 1.3 handshake.
SendCompat(x) ==
  /\ V = "1.3" /\ Compat /\ Writing(x) /\ ~st[x].cc
  /\ st[x].sp > 1 /\ ~ScriptDone(st[x], x)
  /\ LET r == [t |-> "ccs", k |-> "ccs", e |-> 0, n |-> 0, a |-> TRUE, len |-> "S",
               pl |-> "S", ne |-> -1, id |-> 0]
     IN Put(x, [recs |-> <<r>>], [st[x] EXCEPT !.cc = TRUE])
  /\ UNCHANGED <<forged, bad, acc, got, due, fails>>

\* A side fails on its own (out of memory, say): it sends and reads nothing more.
Abort(x) ==
  /\ ~st[x].dead
  /\ st' = [st EXCEPT ![x].dead = TRUE, ![x].re = -1, ![x].rs = -1, ![x].trial = FALSE]
  /\ UNCHANGED <<wire, forged, bad, sent, acc, got, due, fails>>

\* Authentic records the RFCs forbid, from a misbehaving client.
BadRecs(s) ==
  IF s.we = 0
  THEN {[t |-> "hs", k |-> "hs", pl |-> "O", len |-> l] : l \in {"O1", "O2", "O4"}}
       \cup {[t |-> "hs", k |-> "hs", pl |-> "Z", len |-> "Z"]}
       \cup (IF Compat THEN {[t |-> "ccs", k |-> "ccs", pl |-> "O", len |-> "O1"]} ELSE {})
  ELSE IF s.we >= 3
  THEN {[t |-> "app", k |-> "data", pl |-> "O", len |-> IF V = "1.3" THEN "O1" ELSE "O3"],
        [t |-> "app", k |-> "data", pl |-> "S", len |-> IF V = "1.3" THEN "O2" ELSE "O4"],
        [t |-> "alert", k |-> "fatal", pl |-> "Z", len |-> "S"]}
  ELSE {}

SendBad ==
  /\ Misbehave /\ bad < MaxBad /\ ~st["C"].dead
  /\ \/ /\ ~st["C"].closeS
        /\ \E b \in BadRecs(st["C"]):
             LET r == Mk(st["C"], b.t, b.k, b.pl, b.len, -1, 0)
             IN Put("C", [recs |-> <<r>>], After(st["C"], r))
     \/ /\ st["C"].closeS    \* data after its own close_notify
        /\ LET r == Mk(st["C"], "app", "data", "S", "S", -1, st["C"].appW + 1)
           IN Put("C", [recs |-> <<r>>], [After(st["C"], r) EXCEPT !.appW = @ + 1])
  /\ bad' = bad + 1
  /\ UNCHANGED <<forged, acc, got, due, fails>>

\* The attacker injects a forged record or replays a protected one.
Forge(x) ==
  /\ forged < MaxForge
  /\ \/ \E len \in {"S", IF V = "1.3" THEN "O2" ELSE "O4"}:
          wire' = [wire EXCEPT ![x] = Append(@, [t |-> "app", k |-> "data", e |-> 0,
                     n |-> 0, a |-> FALSE, len |-> len, pl |-> "S", ne |-> -1, id |-> 0])]
     \/ \E i \in DOMAIN sent[x]:
          /\ sent[x][i].e > 0
          /\ wire' = [wire EXCEPT ![x] = Append(@, sent[x][i])]
  /\ forged' = forged + 1
  /\ UNCHANGED <<st, bad, sent, acc, got, due, fails>>

-----------------------------------------------------------------------------
(* Reading *)

\* Whether the reader treats r as protected: once it has keys, every
\* record but change_cipher_spec, which is never protected.
IsProt(s, r) == s.re > 0 /\ r.t # "ccs"

Decrypts(s, r) == r.a /\ r.e = s.re /\ (r.n = s.rs \/ ~CheckSeq)

AppOK(s) == s.finR \/ (Early = "accept" /\ s.re = 1)
CcsOK(s) == IF V = "1.2" THEN s.re = 0 ELSE ~s.finR

FailV(why) == [o |-> "fail", why |-> why]

\* What the RFCs make of r arriving at a reader in state s.
Verdict(s, r) ==
  LET prot == IsProt(s, r) IN
  CASE s.closeR /\ IgnoreAfterClose -> [o |-> "ignore", why |-> "closed"]
    [] CheckSize /\ Ord[r.len] > MaxLen(prot) -> FailV("size")
    [] prot /\ ~Decrypts(s, r) /\ s.trial /\ s.allow > 0 -> [o |-> "skip", why |-> "trial"]
    [] prot /\ ~Decrypts(s, r) /\ s.trial -> FailV("allowance")
    [] prot /\ ~Decrypts(s, r) -> FailV("mac")
    [] CheckSize /\ r.pl = "O" -> FailV("size")
    [] r.pl = "Z" /\ r.t # "app" -> FailV("empty")
    [] s.more /\ r.t # "hs" -> FailV("interleave")
    [] r.t = "app" /\ ~AppOK(s) -> FailV("unexpected")
    [] r.t = "ccs" /\ ~CcsOK(s) -> FailV("unexpected")
    [] r.k \in {"ku", "kureq"} /\ ~s.finR -> FailV("unexpected")
    [] OTHER -> [o |-> "accept", why |-> "legal"]

\* The alert the RFCs name for a failure, where they name one.
Mandated(why) == why \in {"size", "mac"}
MandatedAlert(why) == IF why = "size" THEN "record_overflow" ELSE "bad_record_mac"

\* The alerts a reader may send: the one named, or where none is named any
\* the RFCs list for a rejected record.
AlertsFor(why) ==
  IF Mandated(why) THEN {MandatedAlert(why)}
  ELSE {"unexpected_message", "decode_error", "record_overflow", "bad_record_mac",
        "illegal_parameter"}

\* The epoch the reader moves to after r, and whether it skips records then.
RecvEpoch(r) == IF r.ne = 1 /\ Early = "reject" THEN 2 ELSE r.ne
TrialAfter(r) == r.ne = 1 /\ Early = "reject"

\* The reader after accepting r.
AfterAccept(s, r) ==
  LET prot == IsProt(s, r)
      s1 == IF prot THEN [s EXCEPT !.rs = @ + 1, !.trial = FALSE] ELSE s
      s2 == IF r.ne >= 0
            THEN [s1 EXCEPT !.re = RecvEpoch(r), !.rs = 0, !.trial = TrialAfter(r)]
            ELSE s1
      s3 == IF r.t = "hs" THEN [s2 EXCEPT !.more = (r.k = "frag"),
                                          !.finR = @ \/ r.k = "fin"] ELSE s2
  IN CASE r.t = "alert" /\ r.k = "close" -> [s3 EXCEPT !.closeR = TRUE]
       [] r.t = "alert" -> [s3 EXCEPT !.dead = TRUE, !.re = -1, !.rs = -1, !.trial = FALSE]
       [] r.k = "kureq" -> [s3 EXCEPT !.pend = TRUE]
       [] OTHER -> s3

AccEntry(s, r) == [r |-> r, prot |-> IsProt(s, r), ke |-> s.re, ks |-> s.rs]

Receive(x) ==
  LET y == Peer(x) IN
  /\ ~st[x].dead /\ wire[y] # <<>>
  /\ LET r == Head(wire[y])
         s == st[x]
         v == Verdict(s, r)
         rest == [wire EXCEPT ![y] = Tail(@)]
     IN CASE v.o = "ignore" ->
               /\ wire' = rest
               /\ UNCHANGED <<st, sent, acc, got, due, fails>>
          [] v.o = "skip" ->
               /\ wire' = rest
               /\ st' = [st EXCEPT ![x].allow = @ - 1]
               /\ UNCHANGED <<sent, acc, got, due, fails>>
          [] v.o = "accept" ->
               /\ wire' = rest
               /\ st' = [st EXCEPT ![x] = AfterAccept(s, r)]
               /\ acc' = [acc EXCEPT ![x] = Append(@, AccEntry(s, r))]
               /\ got' = IF r.t = "app" /\ r.pl # "Z"
                         THEN [got EXCEPT ![x] = Append(@, r.id)] ELSE got
               /\ due' = IF r.k = "kureq" /\ ~s.pend
                         THEN [due EXCEPT ![x] = @ \cup {Len(sent[x])}] ELSE due
               /\ UNCHANGED <<sent, fails>>
          [] v.o = "fail" ->
               LET quiet == s.closeS /\ QuietAfterClose
                   fail(al) == [x |-> x, r |-> r, prot |-> IsProt(s, r), al |-> al,
                                why |-> v.why, quiet |-> quiet]
               IN /\ \/ /\ quiet \/ ~Mandated(v.why)
                        /\ wire' = rest
                        /\ st' = [st EXCEPT ![x] = [s EXCEPT !.dead = TRUE, !.re = -1, !.rs = -1, !.trial = FALSE]]
                        /\ fails' = Append(fails, fail("none"))
                        /\ UNCHANGED sent
                     \/ /\ ~quiet
                        /\ \E p \in Prefixes(s, FALSE), al \in AlertsFor(v.why):
                             LET em == Emission(s, p, "alert", "fatal", "S", "S", -1, 0)
                             IN /\ wire' = [rest EXCEPT ![x] = @ \o em.recs]
                                /\ sent' = [sent EXCEPT ![x] = @ \o em.recs]
                                /\ st' = [st EXCEPT ![x] = [em.st EXCEPT !.dead = TRUE,
                                                                         !.re = -1, !.rs = -1, !.trial = FALSE]]
                                /\ fails' = Append(fails, fail(al))
                  /\ UNCHANGED <<acc, got, due>>
  /\ UNCHANGED <<forged, bad>>

-----------------------------------------------------------------------------

Init ==
  /\ wire = [x \in Sides |-> <<>>]
  /\ st = [x \in Sides |-> St0]
  /\ forged = 0 /\ bad = 0
  /\ sent = [x \in Sides |-> <<>>]
  /\ acc = [x \in Sides |-> <<>>]
  /\ got = [x \in Sides |-> <<>>]
  /\ due = [x \in Sides |-> {}]
  /\ fails = <<>>

Next ==
  \E x \in Sides:
    \/ SendScript(x) \/ SendApp(x) \/ SendKU(x) \/ SendClose(x) \/ SendCompat(x)
    \/ SendHs(x)
    \/ Abort(x) \/ Forge(x) \/ Receive(x)
    \/ (x = "C" /\ SendBad)

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* Properties *)

\* x is held to the RFC as a writer: the server always, the client unless
\* it misbehaves on purpose.
Honest(x) == x = "S" \/ ~Misbehave

\* The positions of the protected entries of a sequence of records.
ProtPos(seq, isProt(_)) == {i \in DOMAIN seq : isProt(seq[i])}
NextProt(seq, isProt(_), i) ==
  {j \in ProtPos(seq, isProt) : j > i /\ \A k \in i + 1 .. j - 1 : ~isProt(seq[k])}

IsP(r) == r.e > 0
IsPA(a) == a.prot

\* 5.2, 5.3: plaintext reaches the reader only from records that were
\* authentic and deprotected under its current read keys at its next
\* sequence number, in order, each once.
AuthBeforeDeliver ==
  \A x \in Sides :
    /\ \A i \in DOMAIN acc[x] :
         acc[x][i].prot => /\ acc[x][i].r.a
                           /\ acc[x][i].r.e = acc[x][i].ke
                           /\ acc[x][i].r.n = acc[x][i].ks
    /\ \A i \in ProtPos(acc[x], IsPA) :
         /\ (\A k \in 1 .. i - 1 : ~acc[x][k].prot) => acc[x][i].ks = 0
         /\ \A j \in NextProt(acc[x], IsPA, i) :
              IF acc[x][j].ke = acc[x][i].ke
              THEN acc[x][j].ks = acc[x][i].ks + 1
              ELSE acc[x][j].ke > acc[x][i].ke /\ acc[x][j].ks = 0
    /\ \A i \in DOMAIN got[x] : got[x][i] >= 1
    /\ \A i, j \in DOMAIN got[x] : i < j => got[x][i] < got[x][j]

\* 5.3: no keys and sequence number protect two records.
NonceUnique ==
  \A x \in Sides : \A i, j \in DOMAIN sent[x] :
    i # j /\ sent[x][i].e > 0 /\ sent[x][j].e > 0
      => <<sent[x][i].e, sent[x][i].n>> # <<sent[x][j].e, sent[x][j].n>>

\* 5.3: under each keys, the records sent carry 0, 1, 2, ... with no hole.
NoGap ==
  \A x \in Sides : \A i \in ProtPos(sent[x], IsP) :
    /\ (\A k \in 1 .. i - 1 : sent[x][k].e # sent[x][i].e) => sent[x][i].n = 0
    /\ \A j \in NextProt(sent[x], IsP, i) :
         sent[x][j].e = sent[x][i].e => sent[x][j].n = sent[x][i].n + 1

\* 4.6.3, 5.1: every record after a key-changing message is under the new
\* keys and every one before it under the old; the reader switches keys
\* right after it; a reply to update_requested precedes the next
\* application data.
KUOrder ==
  \A x \in Sides :
    /\ \A i \in ProtPos(sent[x], IsP) : \A j \in NextProt(sent[x], IsP, i) :
         IF sent[x][i].ne >= 0 THEN sent[x][j].e = sent[x][i].ne
         ELSE \/ sent[x][j].e = sent[x][i].e
              \/ x = "C" /\ Early = "reject" /\ sent[x][i].e = 1 /\ sent[x][j].e = 2
    /\ \A i \in DOMAIN sent[x] : \A j \in DOMAIN sent[x] :
         j > i /\ sent[x][i].e = 0 /\ sent[x][i].ne > 0 /\ sent[x][j].t # "ccs"
           => sent[x][j].e > 0
    /\ \A i \in DOMAIN acc[x] : \A j \in NextProt(acc[x], IsPA, i) :
         acc[x][i].r.ne >= 0 => acc[x][j].ke = RecvEpoch(acc[x][i].r)

KUReplyFirst ==
  \A x \in Sides : \A p \in due[x] : \A i \in p + 1 .. Len(sent[x]) :
    sent[x][i].t = "app" => \E j \in p + 1 .. i - 1 : sent[x][j].k = "ku"

\* 6.1, 6: nothing is sent after close_notify or a fatal alert; nothing
\* received after close_notify is accepted; a fatal alert received ends
\* the connection.
NoSendAfterClose ==
  \A x \in Sides : Honest(x) =>
    \A i, j \in DOMAIN sent[x] : i < j => sent[x][i].t # "alert"

IgnoreAfterCloseProp ==
  \A x \in Sides : \A i, j \in DOMAIN acc[x] :
    i < j => ~(acc[x][i].r.t = "alert" /\ acc[x][i].r.k = "close")

FatalEnds ==
  \A x \in Sides : \A i \in DOMAIN acc[x] :
    acc[x][i].r.t = "alert" /\ acc[x][i].r.k = "fatal"
      => i = Len(acc[x]) /\ st[x].dead

\* 5.1, 5.2, RFC 5246 6.2: nothing past the length limits, and no empty
\* fragment but application data, is accepted.
AccLegal ==
  \A x \in Sides : \A i \in DOMAIN acc[x] :
    LET a == acc[x][i] IN
    /\ Ord[a.r.len] <= MaxLen(a.prot)
    /\ a.r.pl # "O"
    /\ a.r.pl = "Z" => a.r.t = "app"

\* Where the RFCs name the alert (record_overflow, bad_record_mac), the
\* reader sends that one, unless it already sent close_notify.
RightAlert ==
  \A i \in DOMAIN fails :
    Mandated(fails[i].why) /\ ~fails[i].quiet => fails[i].al = MandatedAlert(fails[i].why)

\* A reader fails only on a record the RFCs reject.
NoFalseReject == \A i \in DOMAIN fails : fails[i].why # "legal"

\* Writers held to the RFC send nothing it forbids.
HonestWriter ==
  \A x \in Sides : Honest(x) => \A i \in DOMAIN sent[x] :
    LET r == sent[x][i] IN
    /\ Ord[r.len] <= MaxLen(r.e > 0) /\ r.pl # "O"
    /\ r.pl = "Z" => r.t = "app"

=============================================================================
