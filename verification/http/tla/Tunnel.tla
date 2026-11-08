------------------------------- MODULE Tunnel -------------------------------
(***************************************************************************)
(* The room and the charges of `services::stack::Tunnel`                   *)
(* (src/stdlib/services/stack/tunnel.rs; written at commit 50b69c60d, when *)
(* it was layer/tunnel.rs, and unchanged but for its imports since): the   *)
(* bytes it holds each way, what the code's                                *)
(* writes are charged to the stack's budget, and what the code's reads     *)
(* return. Sizes are units; `Room` stands for `ROOM` (64 KiB).             *)
(*                                                                         *)
(*   Deliver      Tunnel::on_event, Data (tunnel.rs:137-146)               *)
(*   End, Reset   Tunnel::on_event, Ended and Reset (tunnel.rs:148-149)    *)
(*   Read         TunnelConn::poll_read (tunnel.rs:241-268)                *)
(*   Write        TunnelConn::poll_write (tunnel.rs:270-308), with         *)
(*                Budget::charge (layer/budget.rs:82-88)                   *)
(*   Take         Tunnel::take_command (tunnel.rs:172-186)                 *)
(*   Release      the layer below drops a chunk it took: Charge's drop     *)
(*                (layer/budget.rs:138-142)                                *)
(*   Shutdown     TunnelConn::poll_shutdown and its drop (tunnel.rs:310,   *)
(*                327-333)                                                 *)
(*                                                                         *)
(* The code starts only once the budget is known (take_work,               *)
(* tunnel.rs:192-201), so every write here is charged. Kani could not run  *)
(* on this code: see verification/http/README.md.                          *)
(***************************************************************************)
EXTENDS Naturals, Sequences

CONSTANTS
    Room,         \* ROOM
    Limit,        \* the budget's limit
    ChunkSizes,   \* sizes of the chunks that come from below
    WriteSizes,   \* sizes the code writes
    ReadSizes,    \* sizes of the code's read buffers
    MaxEvents,    \* chunks from below, and writes, in one behavior
    CheckRoom,        \* a write takes at most the room left (tunnel.rs:286-291)
    ChargeWrites,     \* a write is charged before it is queued (tunnel.rs:292-303)
    AdmitBelowRoom    \* a chunk is taken only below the room (tunnel.rs:141-143)

Sum(s) == LET F[i \in 0..Len(s)] == IF i = 0 THEN 0 ELSE F[i - 1] + s[i]
          IN F[Len(s)]
Min(a, b) == IF a < b THEN a ELSE b

VARIABLES
    inbound, ended, reset,     \* from below, not yet read
    outbound, finished, endSent,
    kept,       \* chunks the layer below took and still holds
    used,       \* the budget's count
    delivered, written,
    eofWhileOpen  \* a read returned end of input before the end came

vars == <<inbound, ended, reset, outbound, finished, endSent, kept, used,
          delivered, written, eofWhileOpen>>

Init ==
    /\ inbound = <<>> /\ ended = FALSE /\ reset = FALSE
    /\ outbound = <<>> /\ finished = FALSE /\ endSent = FALSE
    /\ kept = <<>> /\ used = 0
    /\ delivered = 0 /\ written = 0 /\ eofWhileOpen = FALSE

Deliver ==
    \E c \in ChunkSizes :
        /\ delivered < MaxEvents
        /\ delivered' = delivered + 1
        /\ IF reset \/ ended
           THEN UNCHANGED inbound                       \* Admit::Closed
           ELSE /\ Sum(inbound) < Room \/ ~AdmitBelowRoom \* else Admit::Blocked
                /\ inbound' = Append(inbound, c)
        /\ UNCHANGED <<ended, reset, outbound, finished, endSent, kept, used,
                       written, eofWhileOpen>>

End ==
    /\ ~ended /\ ended' = TRUE
    /\ UNCHANGED <<inbound, reset, outbound, finished, endSent, kept, used,
                   delivered, written, eofWhileOpen>>

Reset ==
    /\ ~reset /\ reset' = TRUE
    /\ UNCHANGED <<inbound, ended, outbound, finished, endSent, kept, used,
                   delivered, written, eofWhileOpen>>

(* A read of a buffer of `b` units: from the first chunk only. *)
Read ==
    \E b \in ReadSizes :
        /\ inbound # <<>>
        /\ LET n == Min(Head(inbound), b) IN
           /\ inbound' = IF n = Head(inbound) THEN Tail(inbound)
                         ELSE [inbound EXCEPT ![1] = @ - n]
           \* Ok(0) to a read with room is the end of input to the code.
           /\ eofWhileOpen' = (eofWhileOpen \/ (n = 0 /\ ~ended))
        /\ UNCHANGED <<ended, reset, outbound, finished, endSent, kept, used,
                       delivered, written>>

Write ==
    \E d \in WriteSizes :
        /\ ~reset /\ ~finished /\ written < MaxEvents
        /\ LET room == Room - Sum(outbound)
               n == IF CheckRoom THEN Min(room, d) ELSE d
           IN /\ room > 0                               \* else Pending
              /\ written' = written + 1
              /\ IF ChargeWrites
                 THEN IF used + n > Limit
                      THEN UNCHANGED <<outbound, used>> \* Err(Closed)
                      ELSE /\ used' = used + n
                           /\ outbound' = Append(outbound, n)
                 ELSE /\ outbound' = Append(outbound, n)
                      /\ UNCHANGED used
        /\ UNCHANGED <<inbound, ended, reset, finished, endSent, kept,
                       delivered, eofWhileOpen>>

Take ==
    \/ /\ outbound # <<>>
       /\ kept' = Append(kept, Head(outbound))
       /\ outbound' = Tail(outbound)
       /\ UNCHANGED <<inbound, ended, reset, finished, endSent, used,
                      delivered, written, eofWhileOpen>>
    \/ /\ outbound = <<>> /\ finished /\ ~endSent /\ ~reset
       /\ endSent' = TRUE
       /\ UNCHANGED <<inbound, ended, reset, outbound, finished, kept, used,
                      delivered, written, eofWhileOpen>>

Release ==
    /\ kept # <<>>
    /\ used' = IF ChargeWrites THEN used - Head(kept) ELSE used
    /\ kept' = Tail(kept)
    /\ UNCHANGED <<inbound, ended, reset, outbound, finished, endSent,
                   delivered, written, eofWhileOpen>>

Shutdown ==
    /\ ~finished /\ finished' = TRUE
    /\ UNCHANGED <<inbound, ended, reset, outbound, endSent, kept, used,
                   delivered, written, eofWhileOpen>>

Next == Deliver \/ End \/ Reset \/ Read \/ Write \/ Take \/ Release \/ Shutdown

Spec == Init /\ [][Next]_vars

-----------------------------------------------------------------------------
(* What the code writes never holds more than the room. *)
OutboundWithinRoom == Sum(outbound) <= Room

(* Every byte waiting or held below is charged, exactly. *)
ChargesMatch == used = Sum(outbound) + Sum(kept)

(* What comes from below stays under the room plus one chunk: a chunk     *)
(* that arrives below the room is taken whole.                            *)
InboundBelowRoomAndAChunk ==
    Sum(inbound) < Room + (LET M == CHOOSE m \in ChunkSizes :
                                       \A c \in ChunkSizes : c <= m
                           IN M)
       \/ inbound = <<>>

(* The doc comment's bound: "each way holds at most 64 KiB". *)
InboundWithinRoom == Sum(inbound) <= Room

(* A read returns end of input only after the stream ended. *)
NoEofWhileOpen == ~eofWhileOpen

=============================================================================
