---------------------------- MODULE Transport ----------------------------
\* RFC 4253 transport ordering between the server as written and any
\* client the RFC allows, over two FIFO links.
\* Server source: src/stdlib/protocols/ssh/transport.rs `start` (version
\* and first KEXINIT), `handle` (receive dispatch, NEWKEYS install, strict
\* gate, IGNORE/DEBUG, application gate), `negotiate` (KEXINIT, strict
\* and ext-info-c on the first exchange only, the strict sequence-zero
\* check, skip_guess), `exchange_share` (ECDH_REPLY, NEWKEYS, strict
\* outgoing reset, EXT_INFO after the first NEWKEYS), `write_packet`
\* (refused unless established and idle), `rekey`, `Direction::advance`
\* (wrapping sequence); src/stdlib/services/ssh.rs `progress` (pending
\* packets are handled before the next poll, and only in the Established
\* state; a server rekey when `needs_rekey`; more than 128 pending
\* packets fail the connection).
\* Client: RFC 4253 sections 7, 7.1 (what a party may send between its
\* KEXINIT and its NEWKEYS; first_kex_packet_follows), 7.3 (NEWKEYS per
\* direction), 6.4 (sequence numbers count every packet, wrap at 2^32,
\* never reset); OpenSSH PROTOCOL "kex-strict" (first packet KEXINIT, no
\* other message during the initial exchange, sequence numbers reset at
\* every NEWKEYS); RFC 8308 section 2.4 (EXT_INFO right after the first
\* NEWKEYS, only to a client that sent ext-info-c).
\* Abstractions. A packet is its message kind, the sender's sequence
\* number and the key epoch it was sealed with; a sequence or epoch the
\* receiver does not expect is an authentication failure, which is what
\* the real AEAD reports. Sequence numbers count modulo M: M = 4 makes
\* every run wrap while the same rule is used at 2^32. "APP" stands for
\* every message from 5 up (service, authentication, connection); "IGNORE"
\* for 2..4. Algorithm choice, key derivation and signatures are left to
\* the vectors in ../lean and to the real-client tests.
EXTENDS Naturals, Sequences, FiniteSets
CONSTANTS Mutation, Strict, ExtInfo, Inject, M, MaxData, MaxInit, PendingCap

Pkt(t, s, k) == [t |-> t, seq |-> s, key |-> k, guess |-> FALSE, right |-> TRUE]
Next1(s) == (s + 1) % M

VARIABLES c2s, s2c,
          sVer, sExch, sEst, sStrict, sExt, sSkip, sInSeq, sOutSeq, sInKey,
          sOutKey, sFault, sPending, sApp, sInit,
          cGotVer, cStarted, cExch, cGotKex, cSent30, cGotReply, cSentNK,
          cGotNK, cOutEst, cInEst, cSrvKex, cPrev, cFirstNK, cInSeq, cOutSeq,
          cInKey, cOutKey, cApp, cInit, cIgnore, cGuess, injected, cViol, wrong
server == <<sVer, sExch, sEst, sStrict, sExt, sSkip, sInSeq, sOutSeq, sInKey,
            sOutKey, sFault, sPending, sApp, sInit>>
client == <<cGotVer, cStarted, cExch, cGotKex, cSent30, cGotReply, cSentNK,
            cGotNK, cOutEst, cInEst, cSrvKex, cPrev, cFirstNK, cInSeq, cOutSeq,
            cInKey, cOutKey, cApp, cInit, cIgnore, cGuess, injected, cViol, wrong>>
vars == <<c2s, s2c, server, client>>

\* Transport::start: identification, then the first KEXINIT (sequence 0).
Init == /\ c2s = <<Pkt("VER", 0, 0)>>
        /\ s2c = <<Pkt("VER", 0, 0), Pkt("KEXINIT", 0, 0)>>
        /\ sVer = FALSE /\ sExch = "Proposal" /\ sEst = FALSE
        /\ sStrict = FALSE /\ sExt = FALSE /\ sSkip = FALSE
        /\ sInSeq = 0 /\ sOutSeq = 1 /\ sInKey = 0 /\ sOutKey = 0
        /\ sFault = "none" /\ sPending = 0 /\ sApp = 0 /\ sInit = 0
        /\ cGotVer = FALSE /\ cStarted = FALSE /\ cExch = "Idle"
        /\ cGotKex = FALSE /\ cSent30 = FALSE /\ cGotReply = FALSE
        /\ cSentNK = FALSE /\ cGotNK = FALSE /\ cOutEst = FALSE
        /\ cInEst = FALSE /\ cSrvKex = FALSE /\ cPrev = "VER"
        /\ cFirstNK = FALSE /\ cInSeq = 0 /\ cOutSeq = 0 /\ cInKey = 0
        /\ cOutKey = 0 /\ cApp = 0 /\ cInit = 0 /\ cIgnore = 0
        /\ cGuess = 0 /\ injected = FALSE /\ wrong = FALSE /\ cViol = {}

---------------------------------------------------------------------------
\* Server.

Fail(why) == /\ sFault' = why
             /\ UNCHANGED <<sVer, sExch, sEst, sStrict, sExt, sSkip, sInSeq,
                            sOutSeq, sInKey, sOutKey, sPending, sApp, sInit, s2c>>

\* The strict reset after the server's own NEWKEYS (exchange_share).
OutReset(next) == IF (sStrict /\ Mutation # "keep") \/ Mutation = "reset"
                  THEN 0 ELSE next
InReset(next) == IF (sStrict /\ Mutation # "keep") \/ Mutation = "reset"
                 THEN 0 ELSE next

\* ECDH_INIT in the Share state: ECDH_REPLY, NEWKEYS, then EXT_INFO on
\* the first exchange to a client that asked for it, under the new key.
Reply(first, ext) ==
    LET after == OutReset((sOutSeq + 2) % M)
        sendExt == ext /\ (first \/ Mutation = "extrekey")
        head == <<Pkt("ECDH_REPLY", sOutSeq, sOutKey),
                  Pkt("NEWKEYS", Next1(sOutSeq), sOutKey)>>
    IN /\ s2c' = s2c \o head \o
                 (IF sendExt THEN <<Pkt("EXT_INFO", after, sOutKey + 1)>> ELSE <<>>)
       /\ sOutSeq' = IF sendExt THEN Next1(after) ELSE after
       /\ sOutKey' = sOutKey + 1

\* One packet through Transport::handle. Pending packets are handled first
\* (progress), so the server does not poll while one waits and it may.
ServerRecv ==
  /\ sFault = "none" /\ c2s # <<>>
  /\ ~(sEst /\ sExch = "Idle" /\ sPending > 0)
  /\ LET p == Head(c2s) IN
     /\ c2s' = Tail(c2s)
     /\ IF p.t = "VER" THEN
          /\ sVer' = TRUE
          /\ UNCHANGED <<sExch, sEst, sStrict, sExt, sSkip, sInSeq, sOutSeq,
                         sInKey, sOutKey, sFault, sPending, sApp, sInit, s2c>>
        ELSE IF ~sVer THEN Fail("state")
        ELSE IF p.key # sInKey THEN Fail("key")
        ELSE IF p.seq # sInSeq THEN Fail("seq")
        ELSE IF sSkip /\ Mutation # "noguess" THEN
          \* The wrongly guessed packet after a KEXINIT is ignored.
          /\ sSkip' = FALSE /\ sInSeq' = Next1(sInSeq)
          /\ UNCHANGED <<sVer, sExch, sEst, sStrict, sExt, sOutSeq, sInKey,
                         sOutKey, sFault, sPending, sApp, sInit, s2c>>
        ELSE IF p.t = "KEXINIT" THEN
          IF sExch \in {"Share", "NewKeys"} \/ (sExch = "Idle" /\ ~sEst)
          THEN Fail("state")
          ELSE LET strict == IF sEst THEN sStrict ELSE p.strict
               IN IF strict /\ ~sEst /\ p.seq # 0 /\ Mutation # "strictlax"
                  THEN Fail("state")
                  ELSE
                  /\ sStrict' = strict
                  /\ sExt' = IF sEst THEN sExt ELSE p.ext
                  /\ sSkip' = (p.guess /\ ~p.right)
                  /\ sExch' = "Share"
                  /\ sInSeq' = Next1(sInSeq)
                  \* A peer's KEXINIT while idle: our proposal goes first.
                  /\ IF sExch = "Idle"
                     THEN /\ s2c' = Append(s2c, Pkt("KEXINIT", sOutSeq, sOutKey))
                          /\ sOutSeq' = Next1(sOutSeq)
                     ELSE UNCHANGED <<s2c, sOutSeq>>
                  /\ UNCHANGED <<sVer, sEst, sInKey, sOutKey, sFault,
                                 sPending, sApp, sInit>>
        ELSE IF p.t = "ECDH_INIT" THEN
          IF sExch # "Share" THEN Fail("state")
          ELSE /\ Reply(~sEst, sExt)
               /\ sExch' = "NewKeys" /\ sInSeq' = Next1(sInSeq)
               /\ UNCHANGED <<sVer, sEst, sStrict, sExt, sSkip, sInKey,
                              sFault, sPending, sApp, sInit>>
        ELSE IF p.t = "NEWKEYS" THEN
          IF sExch # "NewKeys" THEN Fail("state")
          ELSE /\ sExch' = "Idle" /\ sEst' = TRUE /\ sInKey' = sInKey + 1
               /\ sInSeq' = InReset(Next1(sInSeq))
               /\ UNCHANGED <<sVer, sStrict, sExt, sSkip, sOutSeq, sOutKey,
                              sFault, sPending, sApp, sInit, s2c>>
        ELSE IF sStrict /\ ~sEst /\ Mutation # "strictlax" THEN Fail("state")
        ELSE IF p.t = "IGNORE" THEN
          /\ sInSeq' = Next1(sInSeq)
          /\ UNCHANGED <<sVer, sExch, sEst, sStrict, sExt, sSkip, sOutSeq,
                         sInKey, sOutKey, sFault, sPending, sApp, sInit, s2c>>
        ELSE \* APP
          IF ~sEst \/ sExch \in {"Share", "NewKeys"} THEN Fail("state")
          ELSE IF sPending >= PendingCap THEN Fail("pending")
          ELSE /\ sPending' = sPending + 1 /\ sInSeq' = Next1(sInSeq)
               /\ UNCHANGED <<sVer, sExch, sEst, sStrict, sExt, sSkip,
                              sOutSeq, sInKey, sOutKey, sFault, sApp, sInit, s2c>>
  /\ UNCHANGED client

\* write_packet: only when established and not in an exchange.
MayWrite == sEst /\ (sExch = "Idle" \/ (Mutation = "sendinkex" /\ sExch = "Proposal"))

\* A pending packet is handled (progress), with or without a reply. The
\* two are named apart so a trace says which (see the Rust replay).
Handle == /\ sFault = "none" /\ sEst /\ sExch = "Idle" /\ sPending > 0
          /\ sPending' = sPending - 1
          /\ UNCHANGED <<c2s, sVer, sExch, sEst, sStrict, sExt, sSkip, sInSeq,
                         sInKey, sOutKey, sFault, sApp, sInit, client>>
ServerHandleQuiet == Handle /\ UNCHANGED <<s2c, sOutSeq>>
ServerHandleReply == /\ Handle /\ s2c' = Append(s2c, Pkt("APP", sOutSeq, sOutKey))
                     /\ sOutSeq' = Next1(sOutSeq)
ServerHandle == ServerHandleQuiet \/ ServerHandleReply

\* Output the server's applications start (channel data, exit status).
ServerApp ==
  /\ sFault = "none" /\ MayWrite /\ sApp < MaxData
  /\ s2c' = Append(s2c, Pkt("APP", sOutSeq, sOutKey))
  /\ sOutSeq' = Next1(sOutSeq) /\ sApp' = sApp + 1
  /\ UNCHANGED <<c2s, sVer, sExch, sEst, sStrict, sExt, sSkip, sInSeq, sInKey,
                 sOutKey, sFault, sPending, sInit, client>>

\* Transport::rekey, called when needs_rekey.
ServerRekey ==
  /\ sFault = "none" /\ sEst /\ sExch = "Idle" /\ sInit < MaxInit
  /\ s2c' = Append(s2c, Pkt("KEXINIT", sOutSeq, sOutKey))
  /\ sOutSeq' = Next1(sOutSeq) /\ sExch' = "Proposal" /\ sInit' = sInit + 1
  /\ UNCHANGED <<c2s, sVer, sEst, sStrict, sExt, sSkip, sInSeq, sInKey,
                 sOutKey, sFault, sPending, sApp, client>>

---------------------------------------------------------------------------
\* Client: anything RFC 4253 and strict KEX allow it to send, and checks
\* of what the server sends.

Send(p) == /\ c2s' = Append(c2s, p) /\ cOutSeq' = Next1(cOutSeq)
KexPkt(g, r) == [t |-> "KEXINIT", seq |-> cOutSeq, key |-> cOutKey,
                 strict |-> Strict, ext |-> ExtInfo, guess |-> g, right |-> r]

\* A round ends once both NEWKEYS have passed.
EndRound(sentNK, gotNK) ==
  IF sentNK /\ gotNK
  THEN /\ cExch' = "Idle" /\ cGotKex' = FALSE /\ cSent30' = FALSE
       /\ cGotReply' = FALSE /\ cSentNK' = FALSE /\ cGotNK' = FALSE
  ELSE /\ cSentNK' = sentNK /\ cGotNK' = gotNK
       /\ UNCHANGED <<cExch, cGotKex, cSent30, cGotReply>>

ClientRecv ==
  /\ s2c # <<>>
  /\ LET p == Head(s2c)
         bad == (IF p.t # "VER" /\ p.seq # cInSeq THEN {"seq"} ELSE {}) \cup
                (IF p.t # "VER" /\ p.key # cInKey THEN {"key"} ELSE {})
     IN
     /\ s2c' = Tail(s2c)
     /\ cPrev' = IF p.t = "NEWKEYS" /\ ~cFirstNK THEN "FIRSTNK" ELSE p.t
     /\ IF p.t = "VER" THEN
          /\ cGotVer' = TRUE
          /\ UNCHANGED <<c2s, cStarted, cExch, cGotKex, cSent30, cGotReply,
                         cSentNK, cGotNK, cOutEst, cInEst, cSrvKex, cFirstNK,
                         cInSeq, cOutSeq, cInKey, cOutKey, cApp, cInit, cIgnore,
                         cGuess, injected, cViol, wrong>>
        ELSE IF p.t = "KEXINIT" THEN
          \* Section 7.1: a KEXINIT while idle is answered with ours.
          /\ cSrvKex' = TRUE /\ cGotKex' = TRUE /\ cInSeq' = Next1(cInSeq)
          /\ cViol' = cViol \cup bad \cup
                      (IF cGotKex THEN {"order"} ELSE {})
          /\ IF cExch = "Idle"
             THEN /\ Send(KexPkt(FALSE, TRUE)) /\ cExch' = "Sent"
                  /\ cStarted' = TRUE
             ELSE UNCHANGED <<c2s, cOutSeq, cExch, cStarted>>
          /\ UNCHANGED <<cGotVer, cSent30, cGotReply, cSentNK, cGotNK, cOutEst,
                         cInEst, cFirstNK, cInKey, cOutKey, cApp, cInit,
                         cIgnore, cGuess, injected, wrong>>
        ELSE IF p.t = "ECDH_REPLY" THEN
          /\ cGotReply' = TRUE /\ cInSeq' = Next1(cInSeq)
          /\ cViol' = cViol \cup bad \cup (IF cSent30 THEN {} ELSE {"order"})
          /\ UNCHANGED <<c2s, cGotVer, cStarted, cExch, cGotKex, cSent30,
                         cSentNK, cGotNK, cOutEst, cInEst, cSrvKex, cFirstNK,
                         cOutSeq, cInKey, cOutKey, cApp, cInit, cIgnore, cGuess,
                         injected, wrong>>
        ELSE IF p.t = "NEWKEYS" THEN
          /\ cInKey' = cInKey + 1 /\ cSrvKex' = FALSE /\ cInEst' = TRUE
          /\ cFirstNK' = TRUE
          /\ cInSeq' = IF Strict THEN 0 ELSE Next1(cInSeq)
          /\ cViol' = cViol \cup bad \cup (IF cGotReply THEN {} ELSE {"order"})
          /\ EndRound(cSentNK, TRUE)
          /\ UNCHANGED <<c2s, cGotVer, cStarted, cOutEst, cOutSeq, cOutKey,
                         cApp, cInit, cIgnore, cGuess, injected, wrong>>
        ELSE \* EXT_INFO or APP
          /\ cInSeq' = Next1(cInSeq)
          /\ cViol' = cViol \cup bad \cup
               (IF p.t = "EXT_INFO" /\ ~(ExtInfo /\ cPrev = "FIRSTNK")
                THEN {"extinfo"} ELSE {}) \cup
               (IF p.t = "APP" /\ (cSrvKex \/ ~cInEst) THEN {"kex"} ELSE {})
          /\ UNCHANGED <<c2s, cGotVer, cStarted, cExch, cGotKex, cSent30,
                         cGotReply, cSentNK, cGotNK, cOutEst, cInEst, cSrvKex,
                         cFirstNK, cOutSeq, cInKey, cOutKey, cApp, cInit,
                         cIgnore, cGuess, injected, wrong>>
  /\ UNCHANGED server

\* Start an exchange: the first KEXINIT, or a rekey once a round is over.
KexStart ==
  /\ cExch = "Idle" /\ cGotVer
  /\ IF cStarted THEN cOutEst /\ cInit < MaxInit ELSE TRUE
  /\ cExch' = "Sent" /\ cStarted' = TRUE
  /\ cInit' = IF cStarted THEN cInit + 1 ELSE cInit
  /\ UNCHANGED <<server, s2c, cGotVer, cGotKex, cGotReply, cSentNK, cGotNK,
                 cOutEst, cInEst, cSrvKex, cPrev, cFirstNK, cInSeq, cInKey,
                 cOutKey, cApp, cIgnore, injected, cViol>>
ClientKexInit == KexStart /\ Send(KexPkt(FALSE, TRUE))
                 /\ UNCHANGED <<cSent30, cGuess, wrong>>
\* first_kex_packet_follows: the guessed ECDH_INIT follows the KEXINIT at
\* once. A wrong guess is ignored and sent again (ClientEcdh) once the
\* server's KEXINIT is known.
Guess(r) == /\ KexStart /\ cGuess = 0 /\ cGuess' = 1 /\ wrong' = ~r
            /\ c2s' = c2s \o <<KexPkt(TRUE, r),
                                Pkt("ECDH_INIT", Next1(cOutSeq), cOutKey)>>
            /\ cOutSeq' = (cOutSeq + 2) % M
ClientGuessRight == Guess(TRUE) /\ cSent30' = TRUE
ClientGuessWrong == Guess(FALSE) /\ cSent30' = FALSE

ClientEcdh ==
  /\ cExch = "Sent" /\ cGotKex /\ ~cSent30
  /\ Send(Pkt("ECDH_INIT", cOutSeq, cOutKey)) /\ cSent30' = TRUE
  /\ UNCHANGED <<server, s2c, cGotVer, cStarted, cExch, cGotKex, cGotReply,
                 cSentNK, cGotNK, cOutEst, cInEst, cSrvKex, cPrev, cFirstNK,
                 cInSeq, cInKey, cOutKey, cApp, cInit, cIgnore, cGuess,
                 injected, cViol, wrong>>

\* Section 7.3: NEWKEYS after the reply; later packets use the new key.
ClientNewKeys ==
  /\ cGotReply /\ ~cSentNK
  /\ c2s' = Append(c2s, Pkt("NEWKEYS", cOutSeq, cOutKey))
  /\ cOutSeq' = IF Strict THEN 0 ELSE Next1(cOutSeq)
  /\ cOutKey' = cOutKey + 1 /\ cOutEst' = TRUE
  /\ EndRound(TRUE, cGotNK)
  /\ UNCHANGED <<server, s2c, cGotVer, cStarted, cInEst, cSrvKex, cPrev,
                 cFirstNK, cInSeq, cInKey, cApp, cInit, cIgnore, cGuess,
                 injected, cViol, wrong>>

\* Section 7.1: no application message between our KEXINIT and our NEWKEYS.
ClientApp ==
  /\ cOutEst /\ (cExch = "Idle" \/ cSentNK) /\ cApp < MaxData
  /\ Send(Pkt("APP", cOutSeq, cOutKey)) /\ cApp' = cApp + 1
  /\ UNCHANGED <<server, s2c, cGotVer, cStarted, cExch, cGotKex, cSent30,
                 cGotReply, cSentNK, cGotNK, cOutEst, cInEst, cSrvKex, cPrev,
                 cFirstNK, cInSeq, cInKey, cOutKey, cInit, cIgnore, cGuess,
                 injected, cViol, wrong>>

\* IGNORE/DEBUG are allowed at any time, except during a strict initial
\* exchange (and so never before the first KEXINIT under strict KEX).
ClientIgnore ==
  /\ cIgnore < 1 /\ (~Strict \/ cOutEst)
  /\ Send(Pkt("IGNORE", cOutSeq, cOutKey)) /\ cIgnore' = cIgnore + 1
  /\ UNCHANGED <<server, s2c, cGotVer, cStarted, cExch, cGotKex, cSent30,
                 cGotReply, cSentNK, cGotNK, cOutEst, cInEst, cSrvKex, cPrev,
                 cFirstNK, cInSeq, cInKey, cOutKey, cApp, cInit, cGuess,
                 injected, cViol, wrong>>

\* A client that breaks strict KEX: one IGNORE during the initial exchange.
ClientInject ==
  /\ Inject /\ ~injected /\ cStarted /\ ~cOutEst
  /\ Send(Pkt("IGNORE", cOutSeq, cOutKey)) /\ injected' = TRUE
  /\ UNCHANGED <<server, s2c, cGotVer, cStarted, cExch, cGotKex, cSent30,
                 cGotReply, cSentNK, cGotNK, cOutEst, cInEst, cSrvKex, cPrev,
                 cFirstNK, cInSeq, cInKey, cOutKey, cApp, cInit, cIgnore,
                 cGuess, cViol, wrong>>

Next == ServerRecv \/ ServerHandle \/ ServerApp \/ ServerRekey \/ ClientRecv
        \/ ClientKexInit \/ ClientGuessRight \/ ClientGuessWrong \/ ClientEcdh
        \/ ClientNewKeys \/ ClientApp
        \/ ClientIgnore \/ ClientInject
Spec == Init /\ [][Next]_vars /\ WF_vars(ServerRecv) /\ WF_vars(ServerHandle)
        /\ WF_vars(ClientRecv) /\ WF_vars(ClientEcdh) /\ WF_vars(ClientNewKeys)

---------------------------------------------------------------------------
\* Properties.
NoServerFault == sFault = "none"
\* Section 6.4 and strict KEX: each packet carries the number its receiver
\* expects, in both directions, across wraps and NEWKEYS.
SequenceAgreement == sFault # "seq" /\ "seq" \notin cViol
\* Section 7.3: each packet is opened with the key it was sealed with.
KeyAgreement == sFault # "key" /\ "key" \notin cViol
\* Section 7.1, server as sender: no application message between its
\* KEXINIT and its NEWKEYS.
NoApplicationInExchange == "kex" \notin cViol
\* Section 7 order of the server's exchange messages.
ExchangeOrder == "order" \notin cViol
\* RFC 8308 section 2.4.
ExtInfoPlacement == "extinfo" \notin cViol
\* Strict KEX: a message outside the exchange during the initial exchange
\* ends the connection before it is established.
StrictEnforced == ~(injected /\ sEst /\ sFault = "none")
\* Coverage, expected to be violated: a run that ends quiet after a rekey
\* started by each side, a wrongly or rightly guessed exchange, and all
\* application packets in both directions.
NoFullRun == ~(sEst /\ sInit = MaxInit /\ cInit = MaxInit /\ cGuess = 1
               /\ sApp = MaxData /\ cApp = MaxData /\ sPending = 0
               /\ sExch = "Idle" /\ cExch = "Idle" /\ s2c = <<>> /\ c2s = <<>>)
\* The same with a wrong guess and an IGNORE from the client.
NoWrongGuessRun == NoFullRun \/ ~wrong \/ cIgnore = 0
\* Every exchange the server is in ends.
ExchangeEnds == (sExch # "Idle") ~> (sExch = "Idle")
Established == <>sEst
=============================================================================
