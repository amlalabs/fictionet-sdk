------------------------- MODULE VersionNegotiation -------------------------
(* QUIC version negotiation between one client and one server, with an
   attacker on the path: RFC 9368's compatible and incompatible
   negotiation over versions 1 and 2 of RFC 9369 and a draft compatible
   with neither.

   Named to the code (quinn-proto, tree at the commit that adds this model):
   - ClientStart: Endpoint::connect and Negotiation::client
     (connection/negotiation.rs), which offers the preferred versions its
     first flight converts to.
   - ServerRecvInitial: Endpoint::handle_buffer (Version Negotiation for an
     unsupported version), Endpoint::accept and compatible_upgrade with
     version::select_compatible.
   - ClientRecvVN: Negotiation::react and Connection::restart_in_version.
   - ClientRecvInitial: Negotiation::admit (Current or Try) and
     Connection::adopt_tried_version; CRYPTO data in the current version
     settles it (read_crypto).
   - ClientRecvHandshake: Negotiation::admit (Handshake only in the current
     version), the transport parameter decoder's Chosen Version comparison
     and Negotiation::check_server with version::negotiation_was_genuine.
   - ServerRecvHandshake: the Handshake arm of process_decrypted_packet,
     which drops the retained original Initial keys.

   The attacker can, at any moment, deliver to the client a Version
   Negotiation packet listing any versions, and a server Initial in any
   version: Initial keys come from the connection ID, so the attacker can
   protect such packets. It can deliver to the server a client Initial with
   any offer. It cannot produce Handshake packets: those need the server's
   keys from the TLS handshake, which also authenticates the transcript,
   so a Handshake completes only when both sides saw the same client offer
   (TLS Finished). Honest messages stay in the network forever, so they
   can be delayed, reordered and replayed; never delivering one is a drop.

   Abstractions: cryptography is assumed; packet loss and retransmission
   are left to the network set; the ClientHello always fits the first
   packet; Retry, 0-RTT and session tickets are not modelled. *)
EXTENDS Integers, Sequences, FiniteSets

CONSTANTS
    V1, V2, D,          \* versions 1 and 2, and a draft compatible with neither
    ClientPrefs,        \* client preference lists to check
    ServerPrefs,        \* server preference lists to check
    IgnoreOriginal,     \* react ignores a list holding the Original Version
    ReactOnce,          \* react ignores Version Negotiation after reacting
    CheckGenuine,       \* check_server's downgrade check after reacting
    CheckOffered,       \* check_server: the Chosen Version was offered
    TryOffered,         \* admit tries only offered compatible versions
    ServerFromOffer,    \* select_compatible picks only what the client listed
    Transcript,         \* TLS authenticates the client's offer
    DropOther,          \* the server drops original keys on a Handshake
    JudgeAttempt        \* the downgrade check judges the attempted version,
                        \* not the negotiated one (the fix of c589fee32)

Versions == {V1, V2, D}
None == "none"

Compatible(a, b) == a = b \/ {a, b} = {V1, V2}

Range(s) == {s[i] : i \in 1..Len(s)}

\* The first entry of `s` satisfying `P`, or None
FirstOf(s, P(_)) ==
    IF \E i \in 1..Len(s): P(s[i])
    THEN s[CHOOSE i \in 1..Len(s): P(s[i]) /\ \A j \in 1..(i - 1): ~P(s[j])]
    ELSE None

\* What a client in `o` offers: its preferences its first flight converts to
Offered(pref, o) == {v \in Range(pref): Compatible(o, v)}

\* RFC 9368 section 2.3: the server's most preferred version that the
\* client offered and its first flight converts to
Select(spref, o, offer) ==
    LET pick == FirstOf(spref, LAMBDA v: Compatible(o, v)
                                          /\ (~ServerFromOffer \/ v \in offer))
    IN IF pick = None THEN o ELSE pick

\* The outcomes an honest network can give. Without Version Negotiation
\* the server answers the Original Version in its compatible choice. With
\* it, the client restarts in its most preferred version the server lists,
\* and the server answers that. An honest server sends Version Negotiation
\* only for a version it does not accept, but RFC 9368 lets the client
\* end up on the second path whenever it would have chosen that version
\* from the server's list (section 4): a client that started in a version
\* it prefers less may be moved to the one it prefers, never further.
Direct(pref, o, spref) == Select(spref, o, Offered(pref, o))
AfterVN(pref, spref) ==
    LET a == FirstOf(pref, LAMBDA v: v \in Range(spref))
    IN IF a = None THEN None ELSE Select(spref, a, Offered(pref, a))
Honest(pref, o, spref) ==
    IF o \in Range(spref) THEN Direct(pref, o, spref) ELSE AfterVN(pref, spref)

VARIABLES
    cpref, spref, orig0,   \* fixed per behaviour
    client,                \* the client's connection
    server,                \* the server's connection for each attempt
    net,                   \* honest messages ever sent
    otherAfterHandshake,   \* the server read an original Initial after a Handshake
    forged                 \* the attacker delivered something
vars == <<cpref, spref, orig0, client, server, net, otherAfterHandshake, forged>>

Idle == [state |-> "idle", orig |-> None, ver |-> None, other |-> {},
         offer |-> {}, chosen |-> None, handshake |-> FALSE]

FirstFlight(o) ==
    [attempt |-> 0, orig |-> o, offered |-> Offered(cpref, o), reacted |-> FALSE,
     ver |-> o, settled |-> FALSE, state |-> "start",
     initial |-> {o}, hs |-> {}, seen |-> {}]

Init ==
    /\ cpref \in ClientPrefs
    /\ spref \in ServerPrefs
    /\ orig0 \in Range(cpref)
    /\ client = FirstFlight(orig0)
    /\ server = [k \in 0..1 |-> Idle]
    /\ net = {}
    /\ otherAfterHandshake = FALSE
    /\ forged = FALSE

Send(m) == net' = net \cup {m}

ClientStart ==
    /\ client.state = "start"
    /\ client' = [client EXCEPT !.state = "wait"]
    /\ Send([t |-> "CInit", k |-> client.attempt, ver |-> client.orig,
             chosen |-> client.orig, offer |-> client.offered])
    /\ UNCHANGED <<cpref, spref, orig0, server, otherAfterHandshake, forged>>

(* The server gets a client Initial, honest or forged with any offer. *)
ServerRecvInitial(m) ==
    /\ m.t = "CInit"
    /\ LET s == server[m.k] IN
       IF s.state = "idle"
       THEN IF m.ver \notin Range(spref)
            THEN /\ Send([t |-> "VN", k |-> m.k, list |-> Range(spref)])
                 /\ UNCHANGED <<server, otherAfterHandshake>>
            ELSE LET n == Select(spref, m.ver, m.offer)
                 IN /\ server' = [server EXCEPT ![m.k] =
                          [state |-> "hs", orig |-> m.ver, ver |-> n,
                           other |-> IF n = m.ver THEN {} ELSE {m.ver},
                           offer |-> m.offer, chosen |-> m.chosen,
                           handshake |-> FALSE]]
                    /\ net' = net \cup
                          {[t |-> "SInit", k |-> m.k, ver |-> n],
                           [t |-> "SHS", k |-> m.k, ver |-> n,
                            chosen |-> n, avail |-> Range(spref),
                            seen |-> [chosen |-> m.chosen, offer |-> m.offer]]}
                    /\ UNCHANGED otherAfterHandshake
       ELSE \* A later Initial: current keys, or retained original keys.
            /\ m.ver \in {s.ver} \cup s.other
            /\ otherAfterHandshake' =
                  (otherAfterHandshake \/ (s.handshake /\ m.ver # s.ver))
            /\ UNCHANGED <<server, net>>
    /\ UNCHANGED <<cpref, spref, orig0, client>>

ForgedClientInitial ==
    \E k \in 0..1, v \in Versions, offer \in SUBSET Versions:
        /\ ServerRecvInitial([t |-> "CInit", k |-> k, ver |-> v, chosen |-> v,
                              offer |-> offer])
        /\ forged' = TRUE

(* Negotiation::react *)
ClientRecvVN(list) ==
    /\ client.state = "wait"
    /\ IF (IgnoreOriginal /\ client.orig \in list) \/ (ReactOnce /\ client.reacted)
          \/ client.settled
       THEN UNCHANGED client
       ELSE LET a == FirstOf(cpref, LAMBDA v: v \in list) IN
            IF a = None
            THEN client' = [client EXCEPT !.state = "failed"]
            ELSE client' = [FirstFlight(a) EXCEPT !.attempt = 1, !.reacted = TRUE]
    /\ UNCHANGED <<cpref, spref, orig0, server, net, otherAfterHandshake>>

(* Negotiation::admit for a server Initial, then adopt_tried_version *)
ClientRecvInitial(v, k) ==
    /\ client.state = "wait" /\ k = client.attempt
    /\ IF v = client.ver
       THEN client' = [client EXCEPT !.settled = TRUE,
                                     !.seen = @ \cup {v}]
       ELSE IF ~client.settled
               /\ (~TryOffered \/ (v \in client.offered /\ Compatible(client.orig, v)))
            THEN client' = [client EXCEPT !.ver = v, !.settled = TRUE,
                                          !.initial = {v}, !.seen = {v}]
            ELSE UNCHANGED client
    /\ UNCHANGED <<cpref, spref, orig0, server, net, otherAfterHandshake>>

(* A Handshake packet from the server: admitted only in the current
   version, which also is the key schedule the client derived its
   handshake keys with. The decoder compares the Chosen Version; then
   check_server. *)
ClientRecvHandshake(m) ==
    /\ m.t = "SHS" /\ client.state = "wait" /\ m.k = client.attempt
    /\ client.settled /\ m.ver = client.ver
    /\ ~Transcript \/ m.seen = [chosen |-> client.orig, offer |-> client.offered]
    /\ LET judged == IF JudgeAttempt THEN client.orig ELSE client.ver
           ok == /\ m.chosen = client.ver
                 /\ ~CheckOffered \/ m.chosen \in client.offered
                 /\ ~(CheckGenuine /\ client.reacted)
                    \/ (m.avail # {}
                        /\ FirstOf(cpref, LAMBDA v: v = client.ver \/ v \in m.avail)
                           = judged)
       IN IF ok
          THEN /\ client' = [client EXCEPT !.state = "done", !.hs = {client.ver},
                                           !.seen = @ \cup {m.ver}]
               /\ Send([t |-> "CHS", k |-> client.attempt, ver |-> client.ver])
          ELSE /\ client' = [client EXCEPT !.state = "failed"]
               /\ UNCHANGED net
    /\ UNCHANGED <<cpref, spref, orig0, server, otherAfterHandshake, forged>>

ServerRecvHandshake(m) ==
    /\ m.t = "CHS" /\ server[m.k].state = "hs" /\ m.ver = server[m.k].ver
    /\ server' = [server EXCEPT ![m.k].state = "done", ![m.k].handshake = TRUE,
                                ![m.k].other = IF DropOther THEN {} ELSE @]
    /\ UNCHANGED <<cpref, spref, orig0, client, net, otherAfterHandshake, forged>>

Next ==
    \/ ClientStart
    \/ \E m \in net: ServerRecvInitial(m) /\ UNCHANGED forged
    \/ \E m \in net: ClientRecvHandshake(m) \/ ServerRecvHandshake(m)
    \/ ForgedClientInitial
    \/ \E m \in net: m.t = "VN" /\ m.k = client.attempt /\ ClientRecvVN(m.list)
                     /\ UNCHANGED forged
    \/ \E list \in SUBSET Versions: ClientRecvVN(list) /\ forged' = TRUE
    \/ \E m \in net: m.t = "SInit" /\ ClientRecvInitial(m.ver, m.k) /\ UNCHANGED forged
    \/ \E v \in Versions, k \in 0..1: ClientRecvInitial(v, k) /\ forged' = TRUE

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
Done == client.state = "done"
Peer == server[client.attempt]

\* Both ends run the same version, and the server's Chosen Version is it.
Agreement == Done => Peer.state \in {"hs", "done"} /\ Peer.ver = client.ver

\* RFC 9368 section 4: the attacker cannot move the version to anything an
\* honest negotiation would not give.
NoDowngrade ==
    Done => client.ver \in {Honest(cpref, orig0, spref), AfterVN(cpref, spref)}

\* RFC 9368 section 2.3: the server picks only a version the client's
\* first flight offered and converts to, that it supports.
ServerChoosesOffered ==
    \A k \in 0..1: server[k].state # "idle" =>
        /\ server[k].ver \in Range(spref)
        /\ Compatible(server[k].orig, server[k].ver)
        /\ server[k].ver \in server[k].offer \cup {server[k].orig}

\* The client only ever runs a version it offered in this first flight.
ClientRunsOffered == client.ver \in client.offered \cup {client.orig}

\* No mixing: once settled the client holds and accepts only its version's
\* Initial keys and packets, and Handshake keys of that version alone.
ClientSingleVersion ==
    client.settled => client.initial = {client.ver} /\ client.seen \subseteq {client.ver}
                      /\ client.hs \subseteq {client.ver}

\* The server keeps the original Initial keys only until a Handshake in
\* the negotiated version, and never reads an original Initial after it.
ServerSingleVersion ==
    /\ ~otherAfterHandshake
    /\ \A k \in 0..1: server[k].handshake => server[k].other = {}

\* Without an attacker, a client gives up only when it shares no version
\* with the server.
NoFalseRefusal ==
    (client.state = "failed" /\ ~forged) => Honest(cpref, orig0, spref) = None

\* Every preference list over the three versions
Prefs == {s \in UNION {[1..n -> Versions]: n \in 1..3}:
              \A i, j \in 1..Len(s): i # j => s[i] # s[j]}

\* Reachability controls: each must be violated.
NoCompletion == ~Done
NoUpgrade == ~(Done /\ client.ver # client.orig)
NoRestartCompletion == ~(Done /\ client.reacted)
NoRestartUpgrade == ~(Done /\ client.reacted /\ client.ver # client.orig)
=============================================================================
