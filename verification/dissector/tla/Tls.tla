-------------------------------- MODULE Tls --------------------------------
(* The passive TLS 1.3 reader (src/stdlib/dissect/tls.rs) opening the     *)
(* records of both directions with the keys of the key log, and the       *)
(* decrypted stream it hands the protocol inside.                         *)
(*                                                                        *)
(* A record is opened by the AEAD of one direction's key at one sequence  *)
(* number: here it opens exactly when the record was sealed by that       *)
(* direction's sender under that key and number (`open_with`, rustls's    *)
(* `MessageDecrypter`; a forged record never opens, so the only records   *)
(* that can open are the senders'). Each direction's sender seals, in     *)
(* order: for the client, early data under a key the key log does not     *)
(* have (when Early); its handshake record under the handshake key from   *)
(* number 0; then under application key 0 from number 0 a data record and *)
(* a KeyUpdate, and so on for K KeyUpdates, each starting the next key at *)
(* number 0; then a last data record. Data records carry the decrypted    *)
(* stream; the early data is its start. With Refused, the sender, which   *)
(* may be the agent, also seals records an endpoint refuses: application  *)
(* data under the handshake key after its handshake record, and a record  *)
(* of a content type other than handshake, alert or application data      *)
(* (heartbeat, say) after the first data record under application key 0;  *)
(* a protected change_cipher_spec, rustls's decrypter refuses itself, so  *)
(* it does not open (`into_tls13_unpadded_message`). On the wire the      *)
(* attacker may add records: a copy of one sent before, or one of the     *)
(* other direction. The capture may end with a record cut short.          *)
(*                                                                        *)
(* Source lines, at the commit in README.md:                              *)
(*   DirKeys::new, update, open        tls.rs 214-258                     *)
(*   Tls::record (23: open, KeyUpdate  tls.rs 365-512                     *)
(*     under the application key,                                         *)
(*     unopened, application data                                         *)
(*     only under an application key)                                     *)
(*   Tls::inner_data                   tls.rs 517-532                     *)
(*   Tls::handshake (KeyUpdate)        tls.rs 616                         *)
(*   TlsSession::end, lost             tls.rs 102-140                     *)
(*                                                                        *)
(* Left out: the hellos and the key log lookup (`find_keys`: the keys are *)
(* known from the start), record framing (the Kani harnesses over         *)
(* `TlsRecords`), handshake messages cut across records, and what the     *)
(* decrypted bytes say.                                                   *)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS Early,          \* the client sends early data
          K,              \* KeyUpdates each direction sends
          MaxInjected,    \* records the attacker adds
          CheckSeq,       \* a record opens only at its own number (the AEAD nonce)
          KeepSeq,        \* a record that does not open leaves the number as it was
          AppAtZero,      \* during the handshake, the application key is tried at 0
          UpdateOwn,      \* a KeyUpdate moves its own direction's key
          ResetSeq,       \* the next key starts at number 0
          MarkUnopened,   \* a record not opened marks the decrypted stream missing bytes
          WholeEnd,       \* the decrypted stream ends cleanly only after whole, opened records
          Refused,        \* the senders also seal records an endpoint refuses
          AppDataOnly     \* only application data under an application key reaches the decrypted stream

Dirs == {1, 2}            \* 1 is the client
Other(d) == 3 - d
\* Keys are numbered: application keys from 0, one for each KeyUpdate;
\* the handshake key and the early data key after them.
HandshakeKey == K + 1
EarlyKey == K + 2

(* What direction d's sender seals, in order: records of `kinds` under    *)
(* key e, numbered from 0, key by key.                                    *)
Under(e, kinds) == [j \in 1..Len(kinds) |-> [ep |-> e, seq |-> j - 1, kind |-> kinds[j]]]
HsKinds == IF Refused THEN <<"hs", "data">> ELSE <<"hs">>
AppKinds(e) == (IF Refused /\ e = 0 THEN <<"data", "other">> ELSE <<"data">>)
               \o (IF e < K THEN <<"update">> ELSE <<>>)
RECURSIVE AppFrom(_)
AppFrom(e) == IF e > K THEN <<>> ELSE Under(e, AppKinds(e)) \o AppFrom(e + 1)
Sealed == Under(HandshakeKey, HsKinds) \o AppFrom(0)
G(d) == (IF d = 1 /\ Early THEN <<[ep |-> EarlyKey, seq |-> 0, kind |-> "data"]>> ELSE <<>>)
        \o Sealed
(* Application data as an endpoint takes it: under any key but the        *)
(* handshake key.                                                         *)
Data(d) == {g \in DOMAIN G(d) : G(d)[g].kind = "data" /\ G(d)[g].ep # HandshakeKey}

VARIABLES sent,      \* sent[d]: genuine records of d on the wire so far
          injected,  \* records the attacker added
          hsKey,     \* hsKey[d]: DirKeys::handshake is still Some
          ep,        \* ep[d]: the application key in use (KeyUpdates applied)
          seq,       \* seq[d]: DirKeys::seq
          opened,    \* opened[d]: the records opened, as [from, g]
          unopened,  \* unopened[d]: Tls::unopened
          inner,     \* inner[d]: what the decrypted stream got: genuine data index, or 0 for "missing"
          ended,     \* ended[d]: the records ended, "" while open
          cut,       \* cut[d]: they ended inside a record
          innerEnd   \* innerEnd[d]: how the decrypted stream was ended
vars == <<sent, injected, hsKey, ep, seq, opened, unopened, inner, ended, cut, innerEnd>>

Init == /\ sent = [d \in Dirs |-> 0] /\ injected = 0
        /\ hsKey = [d \in Dirs |-> TRUE] /\ ep = [d \in Dirs |-> 0] /\ seq = [d \in Dirs |-> 0]
        /\ opened = [d \in Dirs |-> <<>>] /\ unopened = [d \in Dirs |-> FALSE]
        /\ inner = [d \in Dirs |-> <<>>] /\ ended = [d \in Dirs |-> ""]
        /\ cut = [d \in Dirs |-> FALSE] /\ innerEnd = [d \in Dirs |-> ""]

(* open_with: the record opens under direction d's key `e` at `n`. *)
Opens(r, d, e, n) == /\ r.from = d /\ G(r.from)[r.g].ep = e
                     /\ (CheckSeq => G(r.from)[r.g].seq = n)

(* Direction d reads record r, which arrived in order on its wire.        *)
(* DirKeys::open, then what Tls::record does with what it opened.         *)
Read(d, r) ==
  LET hs == hsKey[d] /\ Opens(r, d, HandshakeKey, seq[d])
      app0 == hsKey[d] /\ ~hs /\ AppAtZero /\ Opens(r, d, ep[d], 0)
      app == ~hsKey[d] /\ Opens(r, d, ep[d], seq[d])
      ok == hs \/ app0 \/ app
      kind == G(r.from)[r.g].kind
      underApp == app0 \/ app
      update == ok /\ kind = "update" /\ underApp
      u == IF UpdateOwn THEN d ELSE Other(d)
      n1 == IF hs \/ app THEN seq[d] + 1 ELSE IF app0 THEN 1 ELSE IF KeepSeq THEN seq[d] ELSE seq[d] + 1
  IN /\ hsKey' = [hsKey EXCEPT ![d] = hsKey[d] /\ ~app0]
     /\ seq' = IF update
               THEN [seq EXCEPT ![d] = n1, ![u] = IF ResetSeq THEN 0 ELSE IF u = d THEN n1 ELSE seq[u]]
               ELSE [seq EXCEPT ![d] = n1]
     /\ ep' = IF update THEN [ep EXCEPT ![u] = ep[u] + 1] ELSE ep
     /\ opened' = IF ok THEN [opened EXCEPT ![d] = Append(opened[d], r)] ELSE opened
     /\ IF ok /\ IF AppDataOnly THEN kind = "data" /\ underApp ELSE kind \in {"data", "other"}
        THEN \* Tls::inner_data: told of missing bytes first, if a record did not open.
             /\ inner' = [inner EXCEPT ![d] = (IF unopened[d] THEN Append(inner[d], 0) ELSE inner[d])
                                               \o <<r.g>>]
             /\ unopened' = [unopened EXCEPT ![d] = FALSE]
        ELSE /\ inner' = inner
             /\ unopened' = IF ok THEN unopened ELSE [unopened EXCEPT ![d] = unopened[d] \/ MarkUnopened]

Open(d) == ended[d] = ""

(* The next genuine record of d arrives. *)
Send(d) ==
  /\ Open(d) /\ sent[d] < Len(G(d))
  /\ sent' = [sent EXCEPT ![d] = sent[d] + 1]
  /\ Read(d, [from |-> d, g |-> sent[d] + 1])
  /\ UNCHANGED <<injected, ended, cut, innerEnd>>

(* The attacker adds a copy of a record sent before, of either direction. *)
Inject(d) ==
  /\ Open(d) /\ injected < MaxInjected
  /\ \E f \in Dirs : \E g \in 1..sent[f] :
       /\ injected' = injected + 1
       /\ Read(d, [from |-> f, g |-> g])
  /\ UNCHANGED <<sent, ended, cut, innerEnd>>

(* A FIN. If it falls inside the next genuine record, that record is cut  *)
(* short: the record reader is left waiting. TlsSession::end then ends    *)
(* the decrypted stream: cleanly only after whole records that all opened. *)
Fin(d) ==
  /\ Open(d)
  /\ \E c \in BOOLEAN :
       /\ c => sent[d] < Len(G(d))
       /\ ended' = [ended EXCEPT ![d] = "fin"] /\ cut' = [cut EXCEPT ![d] = c]
       /\ innerEnd' = [innerEnd EXCEPT ![d] =
                         IF ~WholeEnd \/ (~c /\ ~unopened[d]) THEN "fin" ELSE "truncated"]
  /\ UNCHANGED <<sent, injected, hsKey, ep, seq, opened, unopened, inner>>

Next == \E d \in Dirs : Send(d) \/ Inject(d) \/ Fin(d)
Spec == Init /\ [][Next]_vars

---------------------------------------------------------------------------
Range(s) == {s[j] : j \in DOMAIN s}

(* Each direction opens only its own sender's records, each once and in   *)
(* the order sealed: never a copy, never the other direction's.           *)
OpenedInOrder ==
  \A d \in Dirs :
    /\ \A j \in DOMAIN opened[d] : opened[d][j].from = d
    /\ \A i, j \in DOMAIN opened[d] : i < j => opened[d][i].g < opened[d][j].g

(* The decrypted stream never gets bytes past bytes it did not get        *)
(* without being told they are missing.                                   *)
NoSilentHole ==
  \A d \in Dirs : \A p \in DOMAIN inner[d] :
    inner[d][p] # 0 =>
      \A c \in Data(d) :
        (c < inner[d][p] /\ c \notin Range(SubSeq(inner[d], 1, p - 1))) =>
          \E q \in 1..p - 1 : inner[d][q] = 0 /\ \A x \in q + 1..p - 1 : inner[d][x] = 0 \/ inner[d][x] > c

(* Data record c is missing from d's decrypted stream, and the stream   *)
(* was told: a mark comes after every byte before c, and only bytes past  *)
(* c follow it.                                                           *)
MarkedMissing(d, c) ==
  \E q \in DOMAIN inner[d] :
    inner[d][q] = 0 /\ \A x \in q + 1..Len(inner[d]) : inner[d][x] = 0 \/ inner[d][x] > c

(* The decrypted stream ends cleanly only when it got every byte its      *)
(* sender sent since the last bytes it was told are missing.              *)
InnerEndClean ==
  \A d \in Dirs :
    innerEnd[d] = "fin" =>
      /\ ~cut[d]
      /\ \A c \in Data(d) : c <= sent[d] => c \in Range(inner[d]) \/ MarkedMissing(d, c)

(* With every key in the key log, each direction opens every record its   *)
(* sender sent whole, through every KeyUpdate of its own: the keys stay   *)
(* in step with the senders.                                              *)
KeysInStep ==
  \A d \in Dirs :
    (ended[d] # "" /\ ~(d = 1 /\ Early)) =>
      {opened[d][j].g : j \in DOMAIN opened[d]} = 1..sent[d]

(* The decrypted stream gets only what an endpoint takes as application   *)
(* data: no record an endpoint refuses, however it opened.                *)
InnerOnlyAppData ==
  \A d \in Dirs : \A p \in DOMAIN inner[d] : inner[d][p] # 0 => inner[d][p] \in Data(d)
=============================================================================
