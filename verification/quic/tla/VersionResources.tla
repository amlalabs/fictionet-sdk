------------------------- MODULE VersionResources -------------------------
(***************************************************************************)
(* The storage of QUIC version negotiation (RFC 9368, RFC 9369), threaded  *)
(* through Resources.tla: every key derivation, retained key set and copy  *)
(* of a Retry is reserved from the connection's budget before it grows,   *)
(* and given back only after it is freed.                                  *)
(*                                                                         *)
(* One client connection and one server connection, each with a store.   *)
(* Units: K is one set of Initial keys as held, T the HKDF expanders a     *)
(* derivation holds beside them, P the copy of a Retry. A derivation is    *)
(* charged C = K + T (Session::initial_keys_charge). Base is what a        *)
(* connection holds of its own Initial keys, paid when it opened and       *)
(* outside the budget: K for the client, and K + T for the server, which   *)
(* derives its own keys during accept as a connection that keeps its       *)
(* version also does. Others is what the rest of the connection holds of   *)
(* the same budget; it changes between steps, so a charge can be refused   *)
(* at any point.                                                           *)
(*                                                                         *)
(* The steps and the code they follow (quinn-proto/src):                   *)
(*   ClientTry        connection/mod.rs prepare_other_initial,             *)
(*                    connection/negotiation.rs OtherInitial::derive       *)
(*   ClientAdopt      connection/mod.rs adopt_tried_version,               *)
(*                    OtherInitial::install                                *)
(*   ClientDropTried  negotiation.other = None in read_crypto,             *)
(*                    restart_in_version and the Retry arm                 *)
(*   ClientSettle     connection/mod.rs read_crypto                        *)
(*   ClientRestart    connection/mod.rs restart_in_version                 *)
(*   ClientRetryCopy  the Retry arm of process_decrypted_packet,           *)
(*                    packet/retry.rs PseudoPacket                         *)
(*   ClientRetryKeys  the same arm, its KeyCharge and new keys             *)
(*   ServerAccept     endpoint.rs accept and compatible_upgrade            *)
(*   ServerDrop       the Handshake arm of process_decrypted_packet        *)
(*   *Release         a charge given back after what it paid for is freed  *)
(* A server's Retry and Version Negotiation packet are written in its send *)
(* buffer and allocate nothing (Kani: retry_storage, version_negotiation,  *)
(* token_storage); they are not steps here.                                *)
(*                                                                         *)
(* Flags, TRUE in the code, each turned off by one control:                *)
(*   ChargeFirst        reserve before deriving (else derive, then try)    *)
(*   CoverDerivation    charge K + T (else K, the keys' size alone)        *)
(*   FreeFirst          free the keys before releasing their charge        *)
(*   ChargeRederive     charge a restart's and a Retry's new keys          *)
(*   ChargeRetryCopy    charge the copy of a Retry                         *)
(*   HonorRefusal       a refused charge stops the step                    *)
(***************************************************************************)
EXTENDS Naturals, Resources

CONSTANTS K, T, P, Limit,
          ChargeFirst, CoverDerivation, FreeFirst, ChargeRederive,
          ChargeRetryCopy, HonorRefusal

C == IF CoverDerivation THEN K + T ELSE K

(* Resources.tla compares a step's peak with what is reserved at its end,
   so a charge given back after the storage it paid for is freed starts a
   step of its own: crel and srel hold what the next step releases, and
   only that release runs before it. A release inside a step would hide
   the storage it paid for. *)
VARIABLES
    cstore, cothers,   \* client store, and the rest of its budget's use
    crel,              \* the charge the client gives back next
    cother,            \* the client holds an offered version's keys
    csettled,          \* the client knows the negotiated version
    cupgraded,         \* ... and it is the offered one
    creacted,          \* the client started again after Version Negotiation
    cretry,            \* "none", "copied" (checked, keys next), "done"
    sstore, sothers, srel,
    saccepted,         \* the server connection exists
    sretained,         \* it holds the original version's keys
    refused            \* whether a charge was refused

vars == <<cstore, cothers, crel, cother, csettled, cupgraded, creacted, cretry,
          sstore, sothers, srel, saccepted, sretained, refused>>
client == <<cstore, crel, cother, csettled, cupgraded, creacted, cretry>>
server == <<sstore, srel, saccepted, sretained>>

\* Budget left for a store, beside the other users and its own charges.
Room(s, base, others) == Limit - others - (s.reserved - base)

\* Whether a charge of n is granted.
Fits(s, base, others, n) == ~HonorRefusal \/ n <= Room(s, base, others)

Init ==
    /\ cstore = [held |-> K, peak |-> K, reserved |-> K]
    /\ cothers \in 0..Limit
    /\ crel = 0
    /\ cother = FALSE /\ csettled = FALSE /\ cupgraded = FALSE
    /\ creacted = FALSE /\ cretry = "none"
    /\ sstore = Store(0)
    /\ sothers \in 0..Limit
    /\ srel = 0
    /\ saccepted = FALSE /\ sretained = FALSE
    /\ refused = FALSE

\* A derivation of one key set: its keys and expanders, then the expanders go.
Derive(s) == Shrink(Grow(s, K + T), T)

\* Freeing a charged key set: the keys, then (next step) the charge; or the
\* charge first, in the control.
FreeKeys(s) == IF FreeFirst THEN Shrink(s, K) ELSE Shrink(Release(s, C), K)
KeysRelease == IF FreeFirst THEN C ELSE 0

\* The client is between packets: no release pending, no Retry half done.
ClientIdle == crel = 0 /\ cretry # "copied"

ClientRelease ==
    /\ crel > 0
    /\ cstore' = Release(Begin(cstore), crel)
    /\ crel' = 0
    /\ UNCHANGED <<cother, csettled, cupgraded, creacted, cretry, cothers, refused>>
    /\ UNCHANGED server /\ UNCHANGED sothers

(* A server Initial in an offered version: the client charges and derives
   that version's keys to try them. A refusal drops the packet. *)
ClientTry ==
    /\ ClientIdle /\ ~csettled /\ ~cother
    /\ LET s == Begin(cstore)
       IN IF Fits(s, K, cothers, C)
          THEN /\ cstore' = IF ChargeFirst THEN Derive(Reserve(s, C))
                                             ELSE Reserve(Derive(s), C)
               /\ cother' = TRUE
               /\ UNCHANGED refused
          ELSE /\ cstore' = IF ChargeFirst THEN s ELSE Shrink(Derive(s), K)
               /\ refused' = TRUE
               /\ UNCHANGED cother
    /\ UNCHANGED <<crel, csettled, cupgraded, creacted, cretry, cothers>>
    /\ UNCHANGED server /\ UNCHANGED sothers

(* The tried packet authenticates: the tried keys replace the current ones,
   which are freed. *)
ClientAdopt ==
    /\ ClientIdle /\ cother /\ ~csettled
    /\ cstore' = FreeKeys(Begin(cstore))
    /\ crel' = KeysRelease
    /\ cother' = FALSE /\ csettled' = TRUE /\ cupgraded' = TRUE
    /\ UNCHANGED <<creacted, cretry, cothers, refused>>
    /\ UNCHANGED server /\ UNCHANGED sothers

(* The tried keys go: CRYPTO data in the original version, or a restart or
   a Retry about to derive new keys. *)
ClientDropTried ==
    /\ crel = 0 /\ cother /\ ~csettled
    /\ cstore' = FreeKeys(Begin(cstore))
    /\ crel' = KeysRelease
    /\ cother' = FALSE
    /\ UNCHANGED <<csettled, cupgraded, creacted, cretry, cothers, refused>>
    /\ UNCHANGED server /\ UNCHANGED sothers

ClientSettle ==
    /\ ClientIdle /\ ~csettled /\ ~cother
    /\ cstore' = Begin(cstore)
    /\ csettled' = TRUE
    /\ UNCHANGED <<crel, cother, cupgraded, creacted, cretry, cothers, refused>>
    /\ UNCHANGED server /\ UNCHANGED sothers

(* New Initial keys beside the old ones, which are then freed: a restart or
   a Retry. The charge is given back in the next step. *)
Renew(s) == IF ChargeRederive THEN Shrink(Derive(Reserve(s, C)), K)
                              ELSE Shrink(Derive(s), K)
RenewRelease == IF ChargeRederive THEN C ELSE 0

(* Version Negotiation, once: a refused charge ignores the packet. *)
ClientRestart ==
    /\ ClientIdle /\ ~csettled /\ ~creacted /\ ~cother
    /\ LET s == Begin(cstore)
       IN IF ~ChargeRederive \/ Fits(s, K, cothers, C)
          THEN /\ cstore' = Renew(s)
               /\ crel' = RenewRelease
               /\ creacted' = TRUE
               /\ UNCHANGED refused
          ELSE /\ cstore' = s
               /\ refused' = TRUE
               /\ UNCHANGED <<crel, creacted>>
    /\ UNCHANGED <<cother, csettled, cupgraded, cretry, cothers>>
    /\ UNCHANGED server /\ UNCHANGED sothers

(* A Retry, once: its copy is charged, checked and freed. A refusal
   discards the Retry. *)
ClientRetryCopy ==
    /\ ClientIdle /\ ~csettled /\ cretry = "none"
    /\ LET s == Begin(cstore)
       IN IF ~ChargeRetryCopy
          THEN /\ cstore' = Shrink(Grow(s, P), P)
               /\ crel' = 0 /\ cretry' = "copied"
               /\ UNCHANGED refused
          ELSE IF Fits(s, K, cothers, P)
          THEN /\ cstore' = Shrink(Grow(Reserve(s, P), P), P)
               /\ crel' = P /\ cretry' = "copied"
               /\ UNCHANGED refused
          ELSE /\ cstore' = s
               /\ refused' = TRUE
               /\ UNCHANGED <<crel, cretry>>
    /\ UNCHANGED <<cother, csettled, cupgraded, creacted, cothers>>
    /\ UNCHANGED server /\ UNCHANGED sothers

(* The checked Retry's new keys; a refusal discards the Retry. *)
ClientRetryKeys ==
    /\ crel = 0 /\ cretry = "copied" /\ ~cother
    /\ LET s == Begin(cstore)
       IN IF ~ChargeRederive \/ Fits(s, K, cothers, C)
          THEN /\ cstore' = Renew(s)
               /\ crel' = RenewRelease
               /\ cretry' = "done"
               /\ UNCHANGED refused
          ELSE /\ cstore' = s
               /\ refused' = TRUE
               /\ cretry' = "none"
               /\ UNCHANGED crel
    /\ UNCHANGED <<cother, csettled, cupgraded, creacted, cothers>>
    /\ UNCHANGED server /\ UNCHANGED sothers

ServerRelease ==
    /\ srel > 0
    /\ sstore' = Release(Begin(sstore), srel)
    /\ srel' = 0
    /\ UNCHANGED <<saccepted, sretained, sothers, refused>>
    /\ UNCHANGED client /\ UNCHANGED cothers

(* The server accepts a first flight, upgrading when the client offered a
   compatible version and the budget pays for the retained keys. Its own
   keys' derivation, K + T, is the one a connection that keeps its version
   makes: the server's base, outside the budget. *)
ServerAccept ==
    /\ ~saccepted
    /\ \E offered \in BOOLEAN:
        LET s == Begin([sstore EXCEPT !.reserved = K + T])
        IN IF offered /\ Fits(s, K + T, sothers, C)
           THEN /\ sstore' = Derive(IF ChargeFirst THEN Derive(Reserve(s, C))
                                                  ELSE Reserve(Derive(s), C))
                /\ sretained' = TRUE
                /\ UNCHANGED refused
           ELSE /\ sstore' = Derive(IF offered /\ ~ChargeFirst
                                    THEN Shrink(Derive(s), K)
                                    ELSE s)
                /\ refused' = (refused \/ offered)
                /\ UNCHANGED sretained
    /\ UNCHANGED srel
    /\ saccepted' = TRUE
    /\ UNCHANGED sothers /\ UNCHANGED client /\ UNCHANGED cothers

(* A Handshake packet in the negotiated version: the retained keys go. *)
ServerDrop ==
    /\ srel = 0 /\ sretained
    /\ sstore' = FreeKeys(Begin(sstore))
    /\ srel' = KeysRelease
    /\ sretained' = FALSE
    /\ UNCHANGED <<saccepted, sothers, refused>>
    /\ UNCHANGED client /\ UNCHANGED cothers

(* The rest of each connection takes or frees budget between steps. *)
ClientOthers ==
    /\ cothers' \in 0..(Limit - (cstore.reserved - K))
    /\ UNCHANGED <<client, server, sothers, refused>>
ServerOthers ==
    /\ saccepted
    /\ sothers' \in 0..(Limit - (sstore.reserved - (K + T)))
    /\ UNCHANGED <<client, server, cothers, refused>>

Next == ClientRelease \/ ClientTry \/ ClientAdopt \/ ClientDropTried
        \/ ClientSettle \/ ClientRestart \/ ClientRetryCopy \/ ClientRetryKeys
        \/ ServerRelease \/ ServerAccept \/ ServerDrop
        \/ ClientOthers \/ ServerOthers

Spec == Init /\ [][Next]_vars

ClientPaid == Paid(cstore)
ServerPaid == Paid(sstore)
\* The charges, beside the budget's other users, stay within its limit.
ClientWithinLimit == WithinLimit(cstore, K + Limit - cothers)
ServerWithinLimit == ~saccepted \/ WithinLimit(sstore, K + T + Limit - sothers)
\* Each store holds the key sets the state says.
ClientTracks == Tracks(cstore, K + (IF cother THEN K ELSE 0))
ServerTracks == Tracks(sstore, IF saccepted THEN K + (IF sretained THEN K ELSE 0) ELSE 0)

\* Reachability: each must be violated, so the model is not vacuous.
NeverRefused == ~refused
NeverUpgradedWithRetry == ~(cupgraded /\ cretry = "done" /\ sretained)
NeverRestartedAfterRefusal == ~(creacted /\ refused)
=============================================================================
