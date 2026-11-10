----------------------------- MODULE Handshake -----------------------------
(* The TLS server handshake as RFC 8446 (TLS 1.3) and RFC 5246 with       *)
(* RFC 7627 (TLS 1.2) describe it, from the server's side: the records it *)
(* receives, the messages it queues to send, and the keys each record is  *)
(* protected under. Crypto is abstract: a record names the epoch it was   *)
(* protected under ("none" for plaintext), and a Finished or a            *)
(* CertificateVerify is "ok" or "bad".                                    *)
(*                                                                        *)
(* Epochs: "none", "early" (client_early_traffic_secret), "hs" (the       *)
(* handshake traffic secrets), "app0", "app1", ... (application traffic   *)
(* secret N, one more after each KeyUpdate in that direction), and "ccs"  *)
(* (TLS 1.2: the keys the ChangeCipherSpec turns on). `rd` is the epoch   *)
(* the server reads under, `wr` the one it writes under.                  *)
(*                                                                        *)
(* What the RFCs say, as the only transitions there are:                  *)
(*   RFC 8446 2 (Figures 1-4): full handshake, HelloRetryRequest, PSK     *)
(*     resumption, 0-RTT; 4.1.4: at most one HelloRetryRequest (the hrr   *)
(*     phase takes no ClientHello that would need another), and the       *)
(*     second ClientHello may not offer early data.                       *)
(*   4.2.10: early data only with a PSK and only on the first ClientHello.*)
(*     Accepted: read under "early" until EndOfEarlyData, then "hs".      *)
(*     Rejected: skip records that fail to deprotect under "hs" (trial    *)
(*     decryption) until one deprotects, at most Skip records. After a   *)
(*     HelloRetryRequest: skip records whose outer type is                *)
(*     application_data until the second ClientHello, at most Skip.       *)
(*   4.3.2, 4.4: optional client authentication, only in a full           *)
(*     handshake: Certificate, CertificateVerify only for a non-empty     *)
(*     Certificate, Finished.                                             *)
(*   4.4.4 and 2.1 (0.5-RTT): the server may send application data after *)
(*     its Finished; application data from the client is taken only      *)
(*     under accepted early keys or after the client Finished.            *)
(*   4.6.1 NewSessionTicket after the client Finished. 4.6.3 KeyUpdate:   *)
(*     each one moves its sender's write epoch and the receiver's read    *)
(*     epoch; update_requested makes the receiver owe a KeyUpdate of its  *)
(*     own (update_not_requested) before its next application data.       *)
(*   5.1: ClientHello, EndOfEarlyData, Finished and KeyUpdate end their   *)
(*     record; a record that goes on after one (`co`) aborts.             *)
(*   5, D.4: a plaintext change_cipher_spec is dropped after the first    *)
(*     ClientHello and before the client Finished; the server's own       *)
(*     compatibility CCS goes right after its first handshake message.    *)
(*   6: an alert ends the connection; close_notify after the client       *)
(*     Finished ends only the client's side.                              *)
(*   RFC 5246 7.3, 7.4: full handshake with optional client certificate   *)
(*     (CertificateVerify only for a non-empty one), abbreviated          *)
(*     handshake with the server's ChangeCipherSpec and Finished first,   *)
(*     ChangeCipherSpec before each Finished, no application data before  *)
(*     both Finished. RFC 7627 5.3: no abbreviated handshake when the     *)
(*     session used extended master secret and the hello does not, or    *)
(*     the other way round. RFC 5746 / 5246 7.2.2: a renegotiating        *)
(*     ClientHello may be refused with a no_renegotiation warning.        *)
(*                                                                        *)
(* The server may abort at any point (Dead): it then queues a fatal alert *)
(* or nothing and takes no more records. Every record the RFC requires    *)
(* the server to refuse has no other transition than that. After an      *)
(* abort the state is canonical (Canon), so that a model of the code     *)
(* need not say what its dead connection still holds.                     *)
(*                                                                        *)
(* Bounds: MaxRecv records received, MaxSend application data and ticket  *)
(* messages queued outside a flight, MaxKU KeyUpdates each way. Records   *)
(* are one unit long, so Skip and MaxEarly count records.                 *)
EXTENDS Integers, Sequences

CONSTANTS
  Versions,   \* subset of {"13", "12"} the client may offer (one per hello)
  MaxEarly,   \* max_early_data_size, in records
  Skip,       \* how many records a server skips of rejected early data
  MaxRecv,    \* records the server receives in one behavior
  MaxSend,    \* application data and NewSessionTicket messages queued alone
  MaxKU,      \* KeyUpdates each way
  CoMsgs      \* messages a client record may carry with more after them

ASSUME Versions \subseteq {"13", "12"} /\ Versions # {}
ASSUME MaxEarly \in Nat /\ Skip \in Nat /\ MaxRecv \in Nat /\ MaxSend \in Nat
ASSUME MaxKU \in 0..3

VARIABLE h

AppE == <<"app0", "app1", "app2", "app3", "app4">>
App(n) == AppE[n + 1]

\* What a ClientHello offers: the version, a key share for the group the
\* server picks (sh), early data (ed), a PSK the server can use with a
\* valid binder (pk); in TLS 1.2 extended master secret (em) and a session
\* to resume (ss: none, or one that used EMS or did not).
NoCH == [v |-> "", sh |-> FALSE, ed |-> FALSE, pk |-> FALSE, em |-> FALSE, ss |-> "none"]
CH13 == {[v |-> "13", sh |-> a, ed |-> b, pk |-> c, em |-> FALSE, ss |-> "none"] :
          a \in BOOLEAN, b \in BOOLEAN, c \in BOOLEAN}
CH12 == {[v |-> "12", sh |-> FALSE, ed |-> FALSE, pk |-> FALSE, em |-> a, ss |-> b] :
          a \in BOOLEAN, b \in {"none", "ems", "noems"}}
CHs == {c \in CH13 \cup CH12 : c.v \in Versions}

Epochs == {"none"}
          \cup (IF "13" \in Versions THEN {"early", "hs"} \cup {App(n) : n \in 0..MaxKU} ELSE {})
          \cup (IF "12" \in Versions THEN {"ccs"} ELSE {})
CMsgs == (IF "13" \in Versions THEN {"AD", "EOED", "Cert", "CV", "Fin", "KU", "CCS", "Alert"} ELSE {})
         \cup (IF "12" \in Versions THEN {"AD", "Cert", "CKE", "CV", "CCS", "Fin", "Alert"} ELSE {})
XOf(m) == CASE m = "Cert" -> {"empty", "full"}
          [] m \in {"CV", "Fin"} -> {"ok", "bad"}
          [] m = "KU" -> {"req", "noreq"}
          [] m = "Alert" -> {"fatal", "close"}
          [] OTHER -> {""}
CoOf(m) == IF m \in CoMsgs THEN BOOLEAN ELSE {FALSE}

\* A record from the client: its message, the epoch it is protected under,
\* the message's kind, whether the record goes on after it, the hello.
Rec(m, e, x, co) == [m |-> m, e |-> e, x |-> x, co |-> co, ch |-> NoCH]
Records ==
  {[m |-> "CH", e |-> e, x |-> "", co |-> co, ch |-> c] :
     c \in CHs, e \in {"none"} \cup (IF "12" \in Versions THEN {"ccs"} ELSE {}), co \in CoOf("CH")}
  \cup UNION {{Rec(m, e, x, co) : e \in Epochs, x \in XOf(m), co \in CoOf(m)} : m \in CMsgs}

\* Messages that must end their record (RFC 8446 5.1; the TLS 1.2
\* Finished likewise ends the handshake's records).
KeyChange == {"CH", "EOED", "Fin", "KU"}

\* What the server queues: message, epoch, kind.
QX(m, e, x) == [m |-> m, e |-> e, x |-> x]
Q(m, e) == QX(m, e, "")

\* The last event: a record received (all of it, so that a refinement
\* check ties a step to the very record), a message queued or sent, an
\* abort.
Ev(d, m, e, x, co, ch) == [d |-> d, m |-> m, e |-> e, x |-> x, co |-> co, ch |-> ch]
NoEv == Ev("none", "", "", "", FALSE, NoCH)
EvR(r) == Ev("recv", r.m, r.e, r.x, r.co, r.ch)
EvQ(q) == Ev("queue", q.m, q.e, q.x, FALSE, NoCH)
EvSend(q) == Ev("send", q.m, q.e, q.x, FALSE, NoCH)

Init ==
  h = [ ver |-> "?",       \* "?" until a ClientHello is answered
        ph |-> "start",
        rd |-> "none", rdN |-> 0, wr |-> "none", wrN |-> 0,
        mode |-> "none",   \* early data: none, accepted, trial, skipHrr
        skip |-> 0,        \* early records still to accept or skip
        finS |-> FALSE,    \* the server's Finished is queued
        finC |-> FALSE,    \* the client's Finished is verified
        kuOwed |-> FALSE,  \* a KeyUpdate is owed before application data
        pclosed |-> FALSE, \* close_notify received after the handshake
        certFull |-> FALSE,\* TLS 1.2: the client sent a certificate
        nRecv |-> 0, nSend |-> 0,
        outq |-> <<>>,     \* queued, not yet on the wire
        ev |-> NoEv ]      \* the last event

-----------------------------------------------------------------------------
(* Aborting *)

Canon(g, q) ==
  [g EXCEPT !.ph = "closed", !.ver = "?", !.rd = "none", !.rdN = 0, !.wr = "none",
            !.wrN = 0, !.mode = "none", !.skip = 0, !.finS = FALSE, !.finC = FALSE,
            !.kuOwed = FALSE, !.pclosed = FALSE, !.certFull = FALSE, !.outq = @ \o q]

\* A fatal alert under the write epoch, or nothing; a KeyUpdate owed may
\* go first.
AlertOpts(g) ==
  {<<>>, <<QX("Alert", g.wr, "fatal")>>}
  \cup (IF g.kuOwed /\ g.wrN < MaxKU
          THEN {<<QX("KU", g.wr, "noreq"), QX("Alert", App(g.wrN + 1), "fatal")>>}
          ELSE {})

Dead(g) == {Canon(g, q) : q \in AlertOpts(g)}

-----------------------------------------------------------------------------
(* Answering a ClientHello *)

Flight13(k, p, q) ==
  <<Q("SH", "none")>> \o (IF k THEN <<Q("CCS", "none")>> ELSE <<>>)
  \o <<Q("EE", "hs")>> \o (IF q THEN <<Q("CR", "hs")>> ELSE <<>>)
  \o (IF p THEN <<>> ELSE <<Q("Cert", "hs"), Q("CV", "hs")>>)
  \o <<Q("Fin", "hs")>>

\* Early data: accepted only with the PSK chosen, on the first hello.
EarlyModes(c, p, first) ==
  IF ~c.ed THEN {"none"} ELSE IF p /\ first THEN {"accepted", "trial"} ELSE {"trial"}

\* ServerHello and the rest of the server's flight. `first`: no
\* HelloRetryRequest went before, so the compatibility CCS may follow.
SH13At(g, k, p, q, m) ==
  [g EXCEPT !.ver = "13", !.outq = @ \o Flight13(k, p, q),
            !.wr = App(0), !.wrN = 0, !.finS = TRUE,
            !.rd = IF m = "accepted" THEN "early" ELSE "hs",
            !.ph = IF m = "accepted" THEN "early" ELSE IF q THEN "cert" ELSE "fin",
            !.mode = m,
            !.skip = CASE m = "accepted" -> MaxEarly [] m = "trial" -> Skip [] OTHER -> 0]

\* p: the PSK is chosen; q: a CertificateRequest (never with a PSK);
\* k: the compatibility CCS; m: what becomes of early data.
SH13(g, c, first) ==
  UNION { UNION { { SH13At(g, k, p, q, m) :
                      k \in (IF first THEN BOOLEAN ELSE {FALSE}),
                      m \in EarlyModes(c, p, first) } :
                  q \in (IF p THEN {FALSE} ELSE BOOLEAN) } :
          p \in (IF c.pk THEN BOOLEAN ELSE {FALSE}) }

HRR(g, c) ==
  { [g EXCEPT !.ver = "13", !.ph = "hrr",
              !.outq = @ \o <<Q("HRR", "none")>> \o (IF k THEN <<Q("CCS", "none")>> ELSE <<>>),
              !.mode = IF c.ed THEN "skipHrr" ELSE "none",
              !.skip = IF c.ed THEN Skip ELSE 0] : k \in BOOLEAN }

CanResume(c) ==
  /\ c.ss # "none"
  /\ ~(c.ss = "ems" /\ ~c.em)     \* RFC 7627 5.3: abort the abbreviated handshake
  /\ ~(c.ss = "noems" /\ c.em)    \* RFC 7627 5.3: must not resume

Full12(g) ==
  { [g EXCEPT !.ver = "12", !.ph = IF q THEN "c12cert" ELSE "cke",
              !.outq = @ \o <<Q("SH", "none"), Q("Cert", "none"), Q("SKE", "none")>>
                         \o (IF q THEN <<Q("CR", "none")>> ELSE <<>>) \o <<Q("SHD", "none")>>] :
      q \in BOOLEAN }

Resume12(g) ==
  { [g EXCEPT !.ver = "12", !.ph = "ccs12", !.wr = "ccs", !.finS = TRUE,
              !.outq = @ \o <<Q("SH", "none")>> \o (IF t THEN <<Q("NST", "none")>> ELSE <<>>)
                         \o <<Q("CCS", "none"), Q("Fin", "ccs")>>] : t \in BOOLEAN }

First(g, c) ==
  IF c.v = "13"
    THEN HRR(g, c) \cup (IF c.sh THEN SH13(g, c, TRUE) ELSE {})
    ELSE Full12(g) \cup (IF CanResume(c) THEN Resume12(g) ELSE {})

\* The client's Finished: tickets may follow it in TLS 1.3; in a full
\* TLS 1.2 handshake the server's ChangeCipherSpec and Finished follow.
NSTs(n, e) == [j \in 1..n |-> Q("NST", e)]
Fin13(g) ==
  { [g EXCEPT !.ph = "open", !.finC = TRUE, !.rd = App(0), !.rdN = 0,
              !.outq = @ \o NSTs(t, g.wr)] : t \in 0..2 }

Fin12(g) ==
  IF g.finS THEN {[g EXCEPT !.ph = "open", !.finC = TRUE]}
  ELSE { [g EXCEPT !.ph = "open", !.finC = TRUE, !.finS = TRUE, !.wr = "ccs",
                   !.outq = @ \o (IF t THEN <<Q("NST", "none")>> ELSE <<>>)
                              \o <<Q("CCS", "none"), Q("Fin", "ccs")>>] : t \in BOOLEAN }

-----------------------------------------------------------------------------
(* Receiving a record *)

EndTrial(g) == IF g.mode = "trial" THEN [g EXCEPT !.mode = "none", !.skip = 0] ELSE g

\* A record under the read epoch, not running on past a key change.
Main(g, r) ==
  CASE g.ph = "start" /\ r.m = "CH" -> First(g, r.ch)
    [] g.ph = "hrr" /\ r.m = "CH" /\ r.ch.v = "13" /\ r.ch.sh /\ ~r.ch.ed -> SH13(g, r.ch, FALSE)
    [] g.ph = "early" /\ r.m = "AD" /\ g.skip >= 1 -> {[g EXCEPT !.skip = @ - 1]}
    [] g.ph = "early" /\ r.m = "EOED" ->
         {[g EXCEPT !.rd = "hs", !.ph = "fin", !.mode = "none", !.skip = 0]}
    [] g.ph = "cert" /\ r.m = "Cert" -> {[g EXCEPT !.ph = IF r.x = "full" THEN "cv" ELSE "fin"]}
    [] g.ph = "cv" /\ r.m = "CV" /\ r.x = "ok" -> {[g EXCEPT !.ph = "fin"]}
    [] g.ph = "fin" /\ r.m = "Fin" /\ r.x = "ok" -> Fin13(g)
    [] g.ph = "open" /\ g.ver = "13" /\ r.m = "AD" -> {g}
    [] g.ph = "open" /\ g.ver = "13" /\ r.m = "KU" /\ g.rdN < MaxKU ->
         {[g EXCEPT !.rd = App(g.rdN + 1), !.rdN = @ + 1, !.kuOwed = @ \/ r.x = "req"]}
    [] g.ph = "c12cert" /\ r.m = "Cert" -> {[g EXCEPT !.ph = "cke", !.certFull = (r.x = "full")]}
    [] g.ph = "cke" /\ r.m = "CKE" ->
         {[g EXCEPT !.ph = IF g.certFull THEN "cv12" ELSE "ccs12", !.certFull = FALSE]}
    [] g.ph = "cv12" /\ r.m = "CV" /\ r.x = "ok" -> {[g EXCEPT !.ph = "ccs12"]}
    [] g.ph = "ccs12" /\ r.m = "CCS" -> {[g EXCEPT !.rd = "ccs", !.ph = "fin12"]}
    [] g.ph = "fin12" /\ r.m = "Fin" /\ r.x = "ok" -> Fin12(g)
    [] g.ph = "open" /\ g.ver = "12" /\ r.m = "AD" -> {g}
    [] g.ph = "open" /\ g.ver = "12" /\ r.m = "CH" ->
         {[g EXCEPT !.outq = @ \o <<QX("Alert", g.wr, "noreneg")>>]}
    [] OTHER -> {}

Handle(g, r) ==
  IF r.m = "CCS" /\ r.e = "none" /\ g.ver = "13" /\ ~g.finC THEN {g}
  ELSE IF r.m = "Alert"
    THEN IF r.x = "close" /\ g.finC /\ r.e = g.rd THEN {[g EXCEPT !.pclosed = TRUE]} ELSE {}
  \* A refused TLS 1.2 renegotiation changes no keys, so it may share its record.
  ELSE IF r.e # g.rd \/ (r.co /\ r.m \in KeyChange /\ ~(g.ver = "12" /\ g.ph = "open")) THEN {}
  ELSE Main(IF r.m = "CCS" THEN g ELSE EndTrial(g), r)

\* Skipping: a record that fails to deprotect under the handshake keys
\* while early data is rejected; a record of outer type application_data
\* after a HelloRetryRequest.
OuterAD(r) == r.e # "none" \/ r.m = "AD"
Skips(g, r) ==
  /\ g.skip >= 1
  /\ \/ g.mode = "trial" /\ r.e # g.rd /\ ~(r.m = "CCS" /\ r.e = "none")
     \/ g.mode = "skipHrr" /\ g.ph = "hrr" /\ OuterAD(r)

Recv(r) ==
  /\ h.ph # "closed" /\ ~h.pclosed /\ h.nRecv < MaxRecv
  /\ LET g == [h EXCEPT !.nRecv = @ + 1, !.ev = EvR(r)] IN
       \/ Skips(g, r) /\ h' = [g EXCEPT !.skip = @ - 1]
       \/ h' \in Handle(g, r)
       \/ h' \in Dead(g)

-----------------------------------------------------------------------------
(* The server's own steps *)

QueueAlone(q) ==
  h' = [h EXCEPT !.outq = @ \o <<q>>, !.nSend = @ + 1, !.ev = EvQ(q)]

\* Application data: after the server's Finished in TLS 1.3 (0.5-RTT
\* included), after both Finished in TLS 1.2, never while a KeyUpdate is owed.
SendAD ==
  /\ h.ph # "closed" /\ h.finS /\ (h.ver = "13" \/ h.finC) /\ ~h.kuOwed /\ h.nSend < MaxSend
  /\ QueueAlone(Q("AD", h.wr))

SendNST ==
  /\ h.ph = "open" /\ h.ver = "13" /\ h.nSend < MaxSend
  /\ QueueAlone(Q("NST", h.wr))

SendKU(x) ==
  /\ h.ph # "closed" /\ h.ver = "13" /\ h.finS /\ h.wrN < MaxKU
  /\ h' = [h EXCEPT !.outq = @ \o <<QX("KU", h.wr, x)>>, !.wr = App(h.wrN + 1), !.wrN = @ + 1,
                    !.kuOwed = IF x = "noreq" THEN FALSE ELSE @, !.ev = EvQ(QX("KU", h.wr, x))]

Abort ==
  /\ h.ph # "closed"
  /\ h' \in Dead([h EXCEPT !.ev = Ev("abort", "", "", "", FALSE, NoCH)])

\* The head of the queue goes on the wire.
Emit ==
  /\ h.outq # <<>>
  /\ h' = [h EXCEPT !.outq = Tail(@), !.ev = EvSend(Head(h.outq))]

Next ==
  \/ \E r \in Records : Recv(r)
  \/ SendAD \/ SendNST \/ SendKU("req") \/ SendKU("noreq")
  \/ Abort \/ Emit

Spec == Init /\ [][Next]_h

\* The same steps with the record a Recv takes read off the event it
\* leaves (every Recv sets ev to EvR(r)), so that checking a refinement
\* does not try every record. Equivalent to Next.
NextByEvent ==
  \/ \E r \in Records : h'.ev = EvR(r) /\ Recv(r)
  \/ SendAD \/ SendNST \/ SendKU("req") \/ SendKU("noreq")
  \/ Abort \/ Emit

SpecByEvent == Init /\ [][NextByEvent]_h

-----------------------------------------------------------------------------
(* Checks of the spec itself *)

Phases == {"start", "hrr", "early", "cert", "cv", "fin", "open",
           "c12cert", "cke", "cv12", "ccs12", "fin12", "closed"}

TypeOK ==
  /\ h.ver \in {"?", "13", "12"}
  /\ h.ph \in Phases
  /\ h.rd \in Epochs /\ h.wr \in Epochs
  /\ h.mode \in {"none", "accepted", "trial", "skipHrr"}
  /\ h.skip \in 0..(IF MaxEarly > Skip THEN MaxEarly ELSE Skip)
  /\ h.nRecv \in 0..MaxRecv /\ h.nSend \in 0..MaxSend

\* Application data is read only under accepted early keys or after the
\* client Finished; early data only without a HelloRetryRequest before.
DataAfterFinished ==
  (h.ev.d = "recv" /\ h.ev.m = "AD" /\ h.ph \notin {"closed", "hrr"} /\ h.mode # "trial")
    => (h.finC \/ (h.ph = "early" /\ h.ev.e = "early"))
=============================================================================
