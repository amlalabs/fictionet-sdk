----------------------------- MODULE ServerHs -----------------------------
(* The vendored rustls server handshake (rustls/, 0.23.46 with the budget *)
(* changes) as code, refining Handshake (the RFCs) under the mapping Map  *)
(* at the end. The connection is one record `s`; each operator names the  *)
(* Rust it stands for. Lines checked against comp/fv-tls at b3f4510d7.    *)
(*                                                                        *)
(* Receiving a record is one step: ConnectionCore::process_more_input     *)
(* (rustls/src/conn.rs:1122-1287: the Ok(None) skip of records that       *)
(* failed trial decryption, :1140-1148; plaintext CCS and early plaintext *)
(* alerts pass undecrypted, :1153-1173; a failed decryption skipped,       *)
(* :1206-1218, with RecordLayer::decrypt_incoming and                     *)
(* doing_trial_decryption, record_layer.rs:60-104, 234-245; the end of    *)
(* trial decryption at the first handshake message, conn.rs:1280-1284),   *)
(* then process_msg (conn.rs:1321-1365: the TLS 1.3 CCS drop :1327-1343,   *)
(* alerts), CommonState::process_main_protocol (common_state.rs:360-397:  *)
(* the TLS 1.2 no_renegotiation warning :369-379), then the state's       *)
(* handle:                                                                 *)
(*   hs.rs ExpectClientHello::handle :687-701, with_certified_key         *)
(*     :343-462 (reserve_flight :447-452), with_paid_flight :467-563;      *)
(*   server_conn.rs Acceptor::accept :903-930, Accepted::into_connection  *)
(*     :1097-1145 (IntoConnectionError::Unpaid :1118), EarlyDataState     *)
(*     :1197-1279;                                                         *)
(*   tls13.rs CompleteClientHelloHandling::handle_client_hello :136-499   *)
(*     (second hello with early data :189-197, second HelloRetryRequest   *)
(*     :220-225, early data decision :624-683, decrypters :426-446,       *)
(*     0.5-RTT :451-457), ExpectAndSkipRejectedEarlyData :852-878,        *)
(*     ExpectCertificate :1041-1123, ExpectCertificateVerify :1134-1179,  *)
(*     ExpectEarlyData :1192-1236, ExpectFinished :1326-1386,             *)
(*     ExpectTraffic and handle_key_update :1394-1444;                     *)
(*   tls12.rs handle_client_hello :64-232 (can_resume hs.rs:44-63, the    *)
(*     EMS check in start_resumption :243-248), ExpectCertificate         *)
(*     :435-497, ExpectClientKx :511-576, ExpectCertificateVerify         *)
(*     :603-658, ExpectCcs :683-721, ExpectFinished :820-895,              *)
(*     ExpectTraffic :904-923;                                             *)
(*   key_schedule.rs: set_handshake_decrypter :280-297, sign_client_finish *)
(*     :480-497 (the application read key goes in before the Finished is  *)
(*     compared), update_encrypter_and_notify :510-514,                   *)
(*     request_key_update_and_update_encrypter :516-528;                  *)
(*   common_state.rs: should_update_key :965-979,                          *)
(*     enqueue_key_update_notification :983-995 (the reply is encrypted   *)
(*     under the old key and waits), perhaps_write_key_update :695-701,   *)
(*     send_fatal_alert :821-834, reserve_flight :211-232.                 *)
(* The SDK retries an unpaid flight with the same config                 *)
(* (src/stdlib/services/tls/layer.rs TlsLayer::connect :305-325, retried *)
(* at :646-651). A refused flight may be refused again; MaxRefusals (2)   *)
(* in a row are explored, enough for a retry from a refused state.        *)
(*                                                                        *)
(* Abstractions: records carry one message, except that a record may run  *)
(* on past a key-change message (`co`); the hs_deframer's joining of      *)
(* fragments is otherwise left out. Every record is one unit long. Crypto *)
(* is the epoch label: a record decrypts iff it was protected under the   *)
(* active read epoch. The PSK the hello offers (pk) has a valid binder,   *)
(* a fresh age and the same suite and ALPN; the client offers            *)
(* psk_dhe_ke; certificate checks other than CertificateVerify pass;      *)
(* ALPN, SNI, compression and cipher suite checks pass. Plaintext the     *)
(* application writes during the handshake is left out: the SDK layer     *)
(* takes no writes until the handshake is done (verification/tls).        *)
(*                                                                        *)
(* Each flag is the code as it is when TRUE; a *_without_<flag>.cfg sets  *)
(* one to FALSE and names the one property TLC must then violate.         *)
EXTENDS Integers, Sequences

CONSTANTS
  Versions, MaxEarly, Skip, MaxRecv, MaxSend, MaxKU, CoMsgs,
  Auths,     \* client authentication configs: "none", "optional", "mandatory"
  EarlyCfgs, \* max_early_data_size > 0 (with stateful tickets), or not
  HalfCfgs,  \* send_half_rtt_data
  Tick13s,   \* send_tls13_tickets, 0 or 1
  Tick12s,   \* the TLS 1.2 ticketer is on and the client asks for a ticket
  Vias,      \* "acceptor" (Acceptor, as the SDK) or "new" (ServerConnection::new)
  ReserveBeforeKx,        \* reserve_flight runs before the suite and key exchange are set (hs.rs:447 before :506-507)
  TrialBound,             \* doing_trial_decryption takes from the allowance and stops at zero (record_layer.rs:234-245)
  HrrSkipBound,           \* ExpectAndSkipRejectedEarlyData skips only within skip_data_left (tls13.rs:866-869)
  RejectEarlyOnRetry,     \* a second ClientHello offering early data aborts (tls13.rs:189-197)
  AbortSecondHrr,         \* a second hello without a usable share aborts (tls13.rs:220-225)
  CheckFinished,          \* ExpectFinished compares verify_data and aborts on a mismatch (tls13.rs:1341-1349)
  CheckEmsOnResume,       \* start_resumption aborts when the session used EMS and the hello does not (tls12.rs:243-248)
  ReplyKU,                \* should_update_key answers update_requested (common_state.rs:970-973)
  CheckEoedAligned,       \* ExpectEarlyData checks EndOfEarlyData ends its record (tls13.rs:1217, added on comp/fv-tls)
  DropCcsOnlyInHandshake  \* process_msg drops a TLS 1.3 CCS only before the client Finished (conn.rs:1328-1330)

VARIABLE s

Spec0 == INSTANCE Handshake WITH h <- s   \* only for its constants and helpers
App(n) == Spec0!App(n)
NoCH == Spec0!NoCH
Records == Spec0!Records
Q(m, e) == Spec0!Q(m, e)
QX(m, e, x) == Spec0!QX(m, e, x)
EvR(r) == Spec0!EvR(r)
EvQ(q) == Spec0!EvQ(q)
NoEv == Spec0!NoEv
KeyChange == Spec0!KeyChange

\* A key epoch of the record layer: "none" (not active), "early", "hs",
\* "app" with its generation, "ccs".
Ep(k, n) == IF k = "app" THEN App(n) ELSE k
HsMsgs == {"CH", "EOED", "Cert", "CV", "Fin", "KU", "CKE"}

\* Refusals of one flight in a row the model explores.
MaxRefusals == 2

Configs ==
  [auth : Auths, early : EarlyCfgs, half : HalfCfgs, t13 : Tick13s, t12 : Tick12s, via : Vias]

\* The fields of the connection the hello's handling may change.
ConnFields == <<"cs", "kx", "suite", "dec", "decN", "trial", "enc", "encN", "outq",
                "mayRecv", "maySend", "sentFatal", "ed", "edLeft", "prev", "skipLeft">>
Snap(t) == [f \in {ConnFields[j] : j \in 1..Len(ConnFields)} |-> t[f]]

Init ==
  \E cfg \in Configs :
    s = [ cfg |-> cfg,
          cph |-> IF cfg.via = "acceptor" THEN "acceptor" ELSE "conn",
          cs |-> "ExpectClientHello",   \* the State the connection is in
          held |-> NoCH,                \* Accepted::message
          nv |-> "none",                \* negotiated_version
          kx |-> "none", suite |-> FALSE,
          dec |-> "none", decN |-> 0, trial |-> -1, hasDec |-> FALSE,
          enc |-> "none", encN |-> 0,
          qku |-> FALSE, kuN |-> 0,     \* queued_key_update_message, its epoch
          mayRecv |-> FALSE, maySend |-> FALSE, sentFatal |-> FALSE, pcl |-> FALSE,
          ccsLeft |-> 2, renegLeft |-> 1,  \* TemperCounters
          skipLeft |-> 0,               \* ExpectAndSkipRejectedEarlyData::skip_data_left
          ed |-> "new", edLeft |-> 0,   \* EarlyDataState
          prev |-> FALSE, prevPsk |-> FALSE,  \* previous_hello
          certFull |-> FALSE, resuming |-> FALSE,
          nRecv |-> 0, nSend |-> 0, outq |-> <<>>, ev |-> NoEv,
          \* history, for the properties
          finOK |-> FALSE, hrrs |-> 0, trialSkips |-> 0, hrrSkips |-> 0,
          badData |-> FALSE, earlyAfterHrr |-> FALSE, badEms |-> FALSE,
          owed |-> FALSE, badKU |-> FALSE, lateCcs |-> FALSE, unaligned |-> FALSE,
          snap |-> Snap([cs |-> "", kx |-> "", suite |-> FALSE, dec |-> "", decN |-> 0,
                         trial |-> 0, enc |-> "", encN |-> 0, outq |-> <<>>, mayRecv |-> FALSE,
                         maySend |-> FALSE, sentFatal |-> FALSE, ed |-> "", edLeft |-> 0,
                         prev |-> FALSE, skipLeft |-> 0]),
          refused |-> 0, unpaidChanged |-> FALSE, want |-> <<>>, retryDiffers |-> FALSE ]

-----------------------------------------------------------------------------
(* Ending *)

\* CommonState::send_fatal_alert: queued once, under the write key, after
\* a KeyUpdate waiting to go first (perhaps_write_key_update).
Fatal(t) ==
  [t EXCEPT !.cph = "dead", !.sentFatal = TRUE, !.qku = FALSE,
            !.outq = IF t.sentFatal THEN @
                     ELSE @ \o (IF t.qku THEN <<QX("KU", App(t.kuN), "noreq")>> ELSE <<>>)
                            \o <<QX("Alert", Ep(t.enc, t.encN), "fatal")>>]

\* An error returned without an alert (BudgetExhausted, a received alert,
\* the temper counters).
Silent(t) == [t EXCEPT !.cph = "dead"]

-----------------------------------------------------------------------------
(* Answering a ClientHello: tls13.rs handle_client_hello *)

Respond13(t, c) ==
  IF t.prev /\ c.ed /\ RejectEarlyOnRetry THEN Fatal(t)
  ELSE IF t.prev /\ t.prevPsk /\ ~c.pk THEN Fatal(t)            \* :201-206
  ELSE IF ~c.sh
    THEN IF t.prev /\ AbortSecondHrr THEN Fatal(t)
         ELSE [t EXCEPT \* emit_hello_retry_request and emit_fake_ccs, :227-260
                 !.outq = @ \o <<Q("HRR", "none"), Q("CCS", "none")>>,
                 !.cs = IF c.ed THEN "SkipEarly" ELSE "ExpectClientHello",
                 !.prev = TRUE, !.prevPsk = c.pk,
                 !.skipLeft = IF c.ed THEN Skip ELSE 0,
                 !.hrrs = @ + 1]
  ELSE
    LET psk == c.pk
        accept == c.ed /\ psk /\ t.cfg.early /\ t.ed # "rejected"   \* :666-674
        auth == ~psk /\ t.cfg.auth # "none"
        flight == <<Q("SH", "none")>>
                  \o (IF t.prev THEN <<>> ELSE <<Q("CCS", "none")>>)    \* :375-377
                  \o <<Q("EE", "hs")>> \o (IF auth THEN <<Q("CR", "hs")>> ELSE <<>>)
                  \o (IF psk THEN <<>> ELSE <<Q("Cert", "hs"), Q("CV", "hs")>>)
                  \o <<Q("Fin", "hs")>>
    IN [t EXCEPT
          !.kx = "done", !.outq = @ \o flight,
          !.enc = "app", !.encN = 0,                 \* into_traffic_with_client_finished_pending
          !.dec = IF accept THEN "early" ELSE "hs", !.decN = 0,
          !.trial = IF c.ed /\ ~accept THEN Skip ELSE -1,
          !.ed = IF accept THEN "accepted" ELSE "rejected",
          !.edLeft = IF accept THEN MaxEarly ELSE 0,
          !.maySend = ~auth /\ t.cfg.half,
          !.cs = IF auth THEN "ExpectCertificate"
                 ELSE IF accept THEN "ExpectEarlyData" ELSE "ExpectFinished",
          !.earlyAfterHrr = @ \/ (accept /\ t.prev)]

Respond12(t, c) ==
  LET resumable == c.ss # "none"
                   /\ ((c.ss = "ems") = c.em \/ (c.ss = "ems" /\ ~c.em))   \* can_resume
      auth == t.cfg.auth # "none"
  IN IF resumable
       THEN IF c.ss = "ems" /\ ~c.em /\ CheckEmsOnResume THEN Fatal(t)
            ELSE [t EXCEPT \* start_resumption
                    !.outq = @ \o <<Q("SH", "none")>>
                               \o (IF t.cfg.t12 THEN <<Q("NST", "none")>> ELSE <<>>)
                               \o <<Q("CCS", "none"), Q("Fin", "ccs")>>,
                    !.enc = "ccs", !.cs = "T12Ccs", !.resuming = TRUE,
                    !.badEms = @ \/ (c.ss = "ems") # c.em]
       ELSE [t EXCEPT
               !.outq = @ \o <<Q("SH", "none"), Q("Cert", "none"), Q("SKE", "none")>>
                          \o (IF auth THEN <<Q("CR", "none")>> ELSE <<>>)
                          \o <<Q("SHD", "none")>>,
               !.cs = IF auth THEN "T12Certificate" ELSE "T12ClientKx"]

\* with_paid_flight: the suite and key exchange are set (:506-507), then
\* the version's handling.
Paid(t, c) ==
  LET u == [t EXCEPT !.kx = "start", !.suite = TRUE] IN
  IF c.v = "13" THEN Respond13(u, c) ELSE Respond12(u, c)

\* with_certified_key: the version (tls12_enabled is false after a
\* HelloRetryRequest, :354-357) is set, the certificate resolved, then the
\* flight reserved. Gives the set of {refused, result} outcomes.
Certified(t, c) ==
  LET okv == c.v \in Versions /\ ~(c.v = "12" /\ t.prev)
      u == [t EXCEPT !.nv = c.v]
      early == IF ReserveBeforeKx THEN u ELSE [u EXCEPT !.kx = "start", !.suite = TRUE]
  IN IF ~okv THEN {[refused |-> FALSE, t |-> Fatal(t)]}
     ELSE {[refused |-> TRUE, t |-> early], [refused |-> FALSE, t |-> Paid(u, c)]}

-----------------------------------------------------------------------------
(* The states' handle *)

AD(t) == [t EXCEPT !.badData = @ \/ ~t.finOK]

Handle(t, m, r) ==
  CASE t.cs = "ExpectClientHello" /\ m = "CH" ->
         IF r.co THEN {Fatal(t)}                                     \* check_aligned_handshake, hs.rs:737
         ELSE {IF o.refused THEN Silent(o.t) ELSE o.t : o \in Certified(t, r.ch)}   \* BudgetExhausted, hs.rs:699-700
    [] t.cs = "SkipEarly" /\ m = "AD" /\ (t.skipLeft >= 1 \/ ~HrrSkipBound) ->
         {[t EXCEPT !.skipLeft = IF @ > 0 THEN @ - 1 ELSE 0, !.hrrSkips = @ + 1]}
    [] t.cs = "SkipEarly" /\ m = "CH" ->
         IF r.co THEN {Fatal(t)}
         ELSE {IF o.refused THEN Silent(o.t) ELSE o.t : o \in Certified(t, r.ch)}
    [] t.cs = "ExpectEarlyData" /\ m = "AD" ->
         {IF t.edLeft >= 1 THEN [t EXCEPT !.edLeft = @ - 1] ELSE Fatal(t)}
    [] t.cs = "ExpectEarlyData" /\ m = "EOED" ->
         IF r.co /\ CheckEoedAligned THEN {Fatal(t)}               \* check_aligned_handshake, tls13.rs:1217
         ELSE {[t EXCEPT !.dec = "hs", !.cs = "ExpectFinished", !.unaligned = @ \/ r.co]}
    [] t.cs = "ExpectCertificate" /\ m = "Cert" ->
         {IF r.x = "empty"
            THEN IF t.cfg.auth = "mandatory" THEN Fatal(t) ELSE [t EXCEPT !.cs = "ExpectFinished"]
            ELSE [t EXCEPT !.cs = "ExpectCertificateVerify"]}
    [] t.cs = "ExpectCertificateVerify" /\ m = "CV" ->
         {IF r.x = "ok" THEN [t EXCEPT !.cs = "ExpectFinished"] ELSE Fatal(t)}
    [] t.cs = "ExpectFinished" /\ m = "Fin" ->
         LET u == [t EXCEPT !.dec = "app", !.decN = 0] IN          \* sign_client_finish
         {IF r.x = "bad" /\ CheckFinished THEN Fatal(u)
          ELSE IF r.co THEN Fatal(u)                                 \* check_aligned_handshake, :1354
          ELSE [u EXCEPT !.outq = @ \o Spec0!NSTs(t.cfg.t13, App(0)),
                         !.mayRecv = TRUE, !.maySend = TRUE, !.cs = "ExpectTraffic",
                         !.finOK = (r.x = "ok")]}
    [] t.cs = "ExpectTraffic" /\ m = "AD" -> {AD(t)}
    [] t.cs = "ExpectTraffic" /\ m = "KU" ->
         IF r.co THEN {Fatal(t)}                                     \* :1408
         ELSE LET answer == r.x = "req" /\ ~t.qku /\ ReplyKU IN
              {[t EXCEPT !.qku = @ \/ answer, !.kuN = IF answer THEN t.encN ELSE @,
                         !.encN = IF answer THEN @ + 1 ELSE @,
                         !.decN = @ + 1, !.owed = @ \/ r.x = "req"]}
    [] t.cs = "T12Certificate" /\ m = "Cert" ->
         {IF r.x = "empty" /\ t.cfg.auth = "mandatory" THEN Fatal(t)
          ELSE [t EXCEPT !.cs = "T12ClientKx", !.certFull = (r.x = "full")]}
    [] t.cs = "T12ClientKx" /\ m = "CKE" ->
         {[t EXCEPT !.kx = "done", !.certFull = FALSE,
                    !.cs = IF t.certFull THEN "T12CertificateVerify" ELSE "T12Ccs"]}
    [] t.cs = "T12CertificateVerify" /\ m = "CV" ->
         {IF r.x = "ok" THEN [t EXCEPT !.cs = "T12Ccs"] ELSE Fatal(t)}
    [] t.cs = "T12Ccs" /\ m = "CCS" -> {[t EXCEPT !.dec = "ccs", !.cs = "T12Finished"]}
    [] t.cs = "T12Finished" /\ m = "Fin" ->
         {IF r.co \/ r.x = "bad" THEN Fatal(t)
          ELSE [t EXCEPT !.outq = IF t.resuming THEN @
                                  ELSE @ \o (IF t.cfg.t12 THEN <<Q("NST", "none")>> ELSE <<>>)
                                         \o <<Q("CCS", "none"), Q("Fin", "ccs")>>,
                         !.enc = "ccs", !.mayRecv = TRUE, !.maySend = TRUE,
                         !.cs = "T12Traffic", !.finOK = TRUE]}
    [] t.cs = "T12Traffic" /\ m = "AD" -> {AD(t)}
    [] OTHER -> {Fatal(t)}       \* inappropriate_message: unexpected_message

\* process_msg and process_main_protocol.
Msg(t, m, r) ==
  IF m = "CCS" /\ t.nv = "13" /\ (~t.mayRecv \/ ~DropCcsOnlyInHandshake)
    THEN {IF t.ccsLeft >= 1 THEN [t EXCEPT !.ccsLeft = @ - 1, !.lateCcs = @ \/ t.mayRecv]
          ELSE Silent(t)}
  ELSE IF m = "Alert"
    THEN {IF r.x = "close" /\ t.mayRecv THEN [t EXCEPT !.pcl = TRUE] ELSE Silent(t)}
  ELSE IF t.mayRecv /\ t.nv # "13" /\ m = "CH"
    THEN {IF t.renegLeft >= 1
            THEN [t EXCEPT !.renegLeft = @ - 1,
                           !.outq = @ \o <<QX("Alert", Ep(t.enc, t.encN), "noreneg")>>]
            ELSE Silent(t)}
  ELSE Handle(t, m, r)

\* process_more_input: what the record is once read, and whether it is
\* skipped.
Process(t, r) ==
  LET plain == (r.m = "CCS" /\ r.e = "none")
               \/ (r.m = "Alert" /\ r.e = "none" /\ t.nv = "13" /\ ~t.hasDec)
  IN
  IF plain THEN Msg(t, r.m, r)
  ELSE IF t.dec # "none"
    THEN IF r.e = Ep(t.dec, t.decN)
           THEN IF r.m = "CCS" THEN {Fatal(t)}     \* a protected CCS, inbound.rs:77-79
                ELSE Msg([t EXCEPT !.hasDec = TRUE,
                                   !.trial = IF r.m \in HsMsgs THEN -1 ELSE @], r.m, r)
         ELSE IF t.trial >= 1 \/ (t.trial = 0 /\ ~TrialBound)
           THEN {[t EXCEPT !.trial = IF @ > 0 THEN @ - 1 ELSE 0, !.trialSkips = @ + 1]}
         ELSE {Fatal(t)}                           \* bad_record_mac
  \* No read key: a protected TLS 1.3 record reads as application data, a
  \* protected TLS 1.2 record as its type with a body that does not parse.
  ELSE IF r.e = "none" THEN Msg(t, r.m, r)
  ELSE IF r.e = "ccs" THEN {Fatal(t)}              \* decode_error
  ELSE Msg(t, "AD", r)

-----------------------------------------------------------------------------
(* Steps *)

\* The client's environment: KeyUpdates within the epochs there are.
Sendable(t, r) ==
  /\ ~(r.m = "KU" /\ (t.decN >= MaxKU \/ t.encN >= MaxKU))

\* Acceptor::accept: the first record is the ClientHello (or the
\* connection fails); process_client_hello's checks run here.
AcceptorRecv ==
  /\ s.cph = "acceptor" /\ s.nRecv < MaxRecv
  /\ \E r \in Records :
       /\ Sendable(s, r)
       /\ IF r.m = "CH" /\ r.e = "none" /\ ~r.co
            THEN s' = [s EXCEPT !.cph = "accepted", !.held = r.ch]
          ELSE LET u == [s EXCEPT !.nRecv = @ + 1, !.ev = EvR(r)] IN
               s' = IF r.m = "CH" /\ r.e = "none"
                      THEN [u EXCEPT !.cph = "dead", !.outq = @ \o <<QX("Alert", "none", "fatal")>>]
                      ELSE Silent(u)

\* Accepted::into_connection, first or again (the SDK's retry).
IntoConnection ==
  /\ s.cph = "accepted"
  /\ LET r == [m |-> "CH", e |-> "none", x |-> "", co |-> FALSE, ch |-> s.held]
         base == [s EXCEPT !.cs = "ExpectClientHello"]
         firstTry == s.refused = 0
     IN \E o \in Certified(base, s.held) :
          \* The budget may refuse again and again; two refusals in a row
          \* show a retry starting from a refused state, which is enough.
          /\ (o.refused => s.refused < MaxRefusals)
          /\ IF o.refused
              THEN s' = [o.t EXCEPT
                           !.refused = @ + 1,
                           !.snap = IF firstTry THEN Snap(s) ELSE @,
                           !.unpaidChanged = @ \/ Snap(o.t) # (IF firstTry THEN Snap(s) ELSE s.snap),
                           !.want = IF firstTry
                                      THEN <<Snap(CHOOSE p \in {q.t : q \in {q2 \in Certified(base, s.held) : ~q2.refused}} : TRUE)>>
                                      ELSE @]
            ELSE s' = [o.t EXCEPT !.cph = IF o.t.cph = "dead" THEN "dead" ELSE "conn",
                                  !.nRecv = @ + 1, !.ev = EvR(r),
                                  !.retryDiffers = @ \/ (s.refused > 0 /\ s.want # <<Snap(o.t)>>)]

ConnRecv ==
  /\ s.cph = "conn" /\ ~s.pcl /\ s.nRecv < MaxRecv
  /\ \E r \in Records :
       /\ Sendable(s, r)
       /\ \E t \in Process([s EXCEPT !.nRecv = @ + 1, !.ev = EvR(r)], r) : s' = t

\* The application writes: a record under the write key, once the
\* KeyUpdate waiting has gone (perhaps_write_key_update runs first).
WriteAD ==
  /\ s.cph = "conn" /\ s.maySend /\ ~s.qku /\ s.nSend < MaxSend
  /\ s' = [s EXCEPT !.outq = @ \o <<Q("AD", Ep(s.enc, s.encN))>>, !.nSend = @ + 1,
                    !.ev = EvQ(Q("AD", Ep(s.enc, s.encN))), !.badKU = @ \/ s.owed]

\* perhaps_write_key_update, as the first part of any later output.
FlushKU ==
  /\ s.cph = "conn" /\ s.qku
  /\ s' = [s EXCEPT !.outq = @ \o <<QX("KU", App(s.kuN), "noreq")>>, !.qku = FALSE,
                    !.owed = FALSE, !.ev = EvQ(QX("KU", App(s.kuN), "noreq"))]

\* refresh_traffic_keys: request_key_update_and_update_encrypter.
Refresh ==
  /\ s.cph = "conn" /\ s.cs = "ExpectTraffic" /\ ~s.qku /\ s.encN < MaxKU
  /\ s' = [s EXCEPT !.outq = @ \o <<QX("KU", App(s.encN), "req")>>, !.encN = @ + 1,
                    !.ev = EvQ(QX("KU", App(s.encN), "req"))]

Emit ==
  /\ s.outq # <<>>
  /\ s' = [s EXCEPT !.outq = Tail(@), !.ev = Spec0!EvSend(Head(s.outq))]

Next == AcceptorRecv \/ IntoConnection \/ ConnRecv \/ WriteAD \/ FlushKU \/ Refresh \/ Emit

Spec == Init /\ [][Next]_s

-----------------------------------------------------------------------------
(* The refinement mapping onto Handshake *)

Dead == s.cph = "dead"

MapPh ==
  CASE Dead -> "closed"
    [] s.cph \in {"acceptor", "accepted"} -> "start"
    [] s.cs = "ExpectClientHello" -> IF s.prev THEN "hrr" ELSE "start"
    [] s.cs = "SkipEarly" -> "hrr"
    [] s.cs = "ExpectEarlyData" -> "early"
    [] s.cs = "ExpectCertificate" -> "cert"
    [] s.cs = "ExpectCertificateVerify" -> "cv"
    [] s.cs = "ExpectFinished" -> "fin"
    [] s.cs \in {"ExpectTraffic", "T12Traffic"} -> "open"
    [] s.cs = "T12Certificate" -> "c12cert"
    [] s.cs = "T12ClientKx" -> "cke"
    [] s.cs = "T12CertificateVerify" -> "cv12"
    [] s.cs = "T12Ccs" -> "ccs12"
    [] s.cs = "T12Finished" -> "fin12"

MapMode ==
  CASE Dead -> <<"none", 0>>
    [] s.cph = "conn" /\ s.cs = "SkipEarly" -> <<"skipHrr", s.skipLeft>>
    [] s.cph = "conn" /\ s.cs = "ExpectEarlyData" -> <<"accepted", s.edLeft>>
    [] s.trial >= 0 -> <<"trial", s.trial>>
    [] OTHER -> <<"none", 0>>

Map ==
  [ ver |-> IF Dead \/ s.cph # "conn" \/ s.nv = "none" THEN "?" ELSE s.nv,
    ph |-> MapPh,
    rd |-> IF Dead THEN "none" ELSE Ep(s.dec, s.decN),
    rdN |-> IF Dead \/ s.dec # "app" THEN 0 ELSE s.decN,
    wr |-> IF Dead THEN "none" ELSE IF s.qku THEN App(s.kuN) ELSE Ep(s.enc, s.encN),
    wrN |-> IF Dead THEN 0 ELSE IF s.qku THEN s.kuN ELSE IF s.enc = "app" THEN s.encN ELSE 0,
    mode |-> MapMode[1], skip |-> MapMode[2],
    finS |-> ~Dead /\ (s.enc \in {"app", "ccs"} \/ s.qku),
    finC |-> ~Dead /\ s.cph = "conn" /\ s.cs \in {"ExpectTraffic", "T12Traffic"},
    kuOwed |-> ~Dead /\ s.qku,
    pclosed |-> ~Dead /\ s.pcl,
    certFull |-> ~Dead /\ s.cs = "T12ClientKx" /\ s.certFull,
    nRecv |-> s.nRecv, nSend |-> s.nSend, outq |-> s.outq, ev |-> s.ev ]

R == INSTANCE Handshake WITH h <- Map

\* ServerHs refines the RFC spec.
RefinesSpec == R!SpecByEvent

-----------------------------------------------------------------------------
(* Properties *)

\* Application data reaches the application only after a client Finished
\* that verified (RFC 8446 2, 4.4.4; RFC 5246 7.4.9).
NoDataBeforeFinished == ~s.badData

\* Rejected early data is skipped within the allowance (RFC 8446 4.2.10).
TrialWithinBudget == s.trialSkips <= Skip /\ s.hrrSkips <= Skip

\* Early data is never accepted after a HelloRetryRequest (4.1.2, 4.2.10).
NoEarlyAfterHrr == ~s.earlyAfterHrr

\* At most one HelloRetryRequest (4.1.4).
OneHrr == s.hrrs <= 1

\* No abbreviated handshake across an EMS mismatch (RFC 7627 5.3).
EmsResume == ~s.badEms

\* A KeyUpdate answered before the next application data (4.6.3).
KeyUpdateBeforeData == ~s.badKU

\* A change_cipher_spec is dropped only during the handshake (5, D.4).
CcsOnlyInHandshake == ~s.lateCcs

\* No message processed after a key-change message in the same record (5.1).
KeyChangeAligned == ~s.unaligned

\* A refused flight leaves the connection as it was (negotiated_version
\* aside: see the README), and the retry does what the first call would
\* have done.
UnpaidChangesNothing == ~s.unpaidChanged
RetryAsFirst == ~s.retryDiffers
=============================================================================
