-------------------------------- MODULE Join --------------------------------
(***************************************************************************)
(* Storage that is paid for before it grows, while a handshake message is *)
(* joined from records and then parsed (verification/README.md, "Resource *)
(* properties"; Resources.tla).                                           *)
(*                                                                         *)
(* Two places hold a peer's handshake message and grow with it:            *)
(*                                                                         *)
(*  - The buffer the parts are joined in: the SDK layer's input            *)
(*    (src/stdlib/services/tls/layer.rs, take_input) on the unbuffered     *)
(*    path, and rustls's read buffer (rustls/src/msgs/deframer/buffers.rs, *)
(*    DeframerVecBuffer::resize from prepare_read) on the buffered path,   *)
(*    which reads every ClientHello through the Acceptor. Both now grow a  *)
(*    buffer that has no room to at least twice its capacity, up to       *)
(*    Joined, charge the new allocation before it is made while the old   *)
(*    one is still held, and fail the message once its parts would need   *)
(*    more than Joined.                                                    *)
(*  - What parsing the message allocates (rustls/src/conn.rs,              *)
(*    take_handshake_message, and common_state.rs, reserve_parse): its     *)
(*    room, ParsePer for each byte, is charged before the message is      *)
(*    taken from the deframer, and given back once the parsed message is  *)
(*    dropped (Accepted::answer for the hello).                            *)
(*                                                                         *)
(* One unit is a byte of the message as it arrives. A step is a part of   *)
(* the message arriving (up to Piece units), the message parsed once      *)
(* whole, the parsed message dropped, or a charge given back. The store   *)
(* of each place is threaded through every allocation, free and charge in *)
(* the code's order. The code gives a charge back right after the free it *)
(* paid for; a TLA+ step's Paid compares its peak with the reservation at *)
(* its end, so a charge given back is its own step (Settle), which must   *)
(* follow before anything else moves. A message of any length up to       *)
(* MaxMessage arrives; one longer than Joined fails at the cap.            *)
(*                                                                         *)
(* Flags (TRUE in the code as it is; each control sets one FALSE):        *)
(*   Doubling  - a buffer that grows goes to at least twice its capacity; *)
(*               FALSE grows it to exactly what it holds, as take_input   *)
(*               did before 6371855ae and resize before 3675b51f1.        *)
(*   ChargeOld - the new allocation is charged in full while the old one  *)
(*               is held; FALSE charges only the difference, as resize    *)
(*               did before 3675b51f1.                                     *)
(*   Cap       - the parts of a message may need at most Joined;          *)
(*               FALSE drops the cap, as take_input did before 6371855ae. *)
(*   ParseRoom - parsing is charged before it allocates; FALSE charges     *)
(*               nothing for it, as rustls did before db6df25cc.           *)
(***************************************************************************)
EXTENDS Naturals, Resources

CONSTANTS
    Joined,      \* the most the parts of a message may need
    Piece,       \* the most of a message one record carries
    MaxMessage,  \* the longest message a client sends here
    ParsePer,    \* parse room for each byte
    Doubling, ChargeOld, Cap, ParseRoom

VARIABLES
    msg,      \* the length of the message the client sends
    arrived,  \* units of it delivered
    cap,      \* the join buffer's capacity
    asked,    \* units asked of the allocator for the join buffer, in all
    store,    \* the join buffer's store
    owed,     \* the join buffer's charge freed and not yet given back
    parsed,   \* units parsing holds
    pstore,   \* the parse's store
    powed,    \* the parse's charge freed and not yet given back
    phase     \* "joining", "parsed", "done" or "failed"

vars == <<msg, arrived, cap, asked, store, owed, parsed, pstore, powed, phase>>

Max(a, b) == IF a > b THEN a ELSE b
Min(a, b) == IF a < b THEN a ELSE b

Init ==
    /\ msg \in 1..MaxMessage
    /\ arrived = 0
    /\ cap = 0
    /\ asked = 0
    /\ store = Store(0)
    /\ owed = 0
    /\ parsed = 0
    /\ pstore = Store(0)
    /\ powed = 0
    /\ phase = "joining"

\* Nothing moves while a charge is owed back.
Settled == owed = 0 /\ powed = 0

\* The capacity a buffer of capacity c grows to for `need` units.
Grown(c, need) ==
    IF Doubling
    THEN Max(need, IF Cap THEN Min(2 * c, Joined) ELSE 2 * c)
    ELSE need

\* n more units of the message arrive. The layer's take_input and rustls's
\* prepare_read check the cap first; then, if the buffer has no room, they
\* charge the new allocation, make it, copy into it and free the old one,
\* whose charge goes back in the next step.
Arrive(n) ==
    /\ Settled
    /\ phase = "joining"
    /\ arrived < msg
    /\ n <= msg - arrived
    /\ LET need == arrived + n
           s0 == Begin(store)
       IN IF Cap /\ need > Joined
          THEN /\ phase' = "failed"
               /\ UNCHANGED <<msg, arrived, cap, asked, store, owed, parsed, pstore, powed>>
          ELSE IF need <= cap
          THEN /\ arrived' = need
               /\ store' = s0
               /\ UNCHANGED <<msg, cap, asked, owed, parsed, pstore, powed, phase>>
          ELSE LET g == Grown(cap, need)
                   s1 == IF ChargeOld THEN Reserve(s0, g) ELSE Reserve(s0, g - cap)
               IN /\ arrived' = need
                  /\ cap' = g
                  /\ asked' = asked + g
                  /\ store' = Shrink(Grow(s1, g), cap)
                  /\ owed' = IF ChargeOld THEN cap ELSE 0
                  /\ UNCHANGED <<msg, parsed, pstore, powed, phase>>

\* The whole message is taken and parsed: its room charged first, then
\* what parsing allocates. The join buffer, done with, is freed.
Parse ==
    /\ Settled
    /\ phase = "joining"
    /\ arrived = msg
    /\ LET room == ParsePer * msg
           p0 == Begin(pstore)
       IN /\ pstore' = IF ParseRoom THEN Grow(Reserve(p0, room), room) ELSE Grow(p0, room)
          /\ parsed' = room
    /\ store' = Shrink(Begin(store), cap)
    /\ owed' = cap
    /\ cap' = 0
    /\ phase' = "parsed"
    /\ UNCHANGED <<msg, arrived, asked, powed>>

\* The parsed message is dropped; its room goes back in the next step.
Drop ==
    /\ Settled
    /\ phase = "parsed"
    /\ pstore' = Shrink(Begin(pstore), parsed)
    /\ powed' = IF ParseRoom THEN parsed ELSE 0
    /\ parsed' = 0
    /\ phase' = "done"
    /\ UNCHANGED <<msg, arrived, cap, asked, store, owed>>

\* A charge freed is given back.
Settle ==
    /\ ~Settled
    /\ store' = Release(Begin(store), owed)
    /\ pstore' = Release(Begin(pstore), powed)
    /\ owed' = 0
    /\ powed' = 0
    /\ UNCHANGED <<msg, arrived, cap, asked, parsed, phase>>

Next == (\E n \in 1..Piece : Arrive(n)) \/ Parse \/ Drop \/ Settle

Spec == Init /\ [][Next]_vars

\* No moment of a step held more than was charged.
BufferPaid == Paid(store)
ParsePaid == Paid(pstore)

\* The charges stay within their limits: the join buffer's within twice
\* the cap (the old allocation and the new, for the moment both are held),
\* the parse's within its room for the longest message joined.
BufferWithinLimit == WithinLimit(store, 2 * Joined)
ParseWithinLimit == WithinLimit(pstore, ParsePer * Joined)

\* The stores hold what the model says the code holds.
StoresTrack == Tracks(store, cap) /\ Tracks(pstore, parsed)

\* Once settled, each charge is what its place holds.
ChargesHeld == Settled => store.reserved = cap /\ pstore.reserved = parsed

\* The bytes asked for the join buffer, in all, are at most four times the
\* bytes delivered: its growths at least double, so together they are at
\* most twice the last, which is at most twice what it held.
Linear == asked <= 4 * arrived

TypeOK ==
    /\ arrived \in 0..MaxMessage
    /\ owed \in 0..(2 * MaxMessage)
    /\ phase \in {"joining", "parsed", "done", "failed"}
=============================================================================
