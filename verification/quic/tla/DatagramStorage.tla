--------------------------- MODULE DatagramStorage ---------------------------
EXTENDS Integers, Sequences, Resources

(* ReceivedDatagrams reserves a byte ring, then reuses it for payloads and *)
(* length words. The receive quota conservatively counts Metadata per      *)
(* message; the ring stores one length word. One model unit is a byte.     *)
CONSTANTS Limit, Metadata, SkipCharge, ForgetOld, CopyOnPush
VARIABLES store, capacity, queue, phase, target, payload, window
vars == <<store, capacity, queue, phase, target, payload, window>>
RECURSIVE Held(_, _)
Held(q, overhead) == IF q = <<>> THEN 0
                    ELSE Head(q) + overhead + Held(Tail(q), overhead)
RECURSIVE Evict(_, _, _)
Evict(q, n, w) == IF Held(q, Metadata) + n <= w THEN q
                 ELSE Evict(Tail(q), n, w)

Init == /\ store = Store(0) /\ capacity = 0 /\ queue = <<>>
        /\ phase = "idle" /\ target = 0 /\ payload = 0 /\ window = 0

Receive(n, w) ==
    /\ phase = "idle" /\ n + Metadata <= w
    /\ IF w > capacity
       THEN /\ capacity + w <= Limit
            /\ store' = IF SkipCharge THEN Begin(store)
                        ELSE ReserveTo(Begin(store), w + IF ForgetOld THEN 0 ELSE capacity)
            /\ phase' = "allocate"
       ELSE /\ store' = Begin(store) /\ phase' = "push"
    /\ payload' = n /\ window' = w /\ target' = w
    /\ UNCHANGED <<capacity, queue>>

Allocate == /\ phase = "allocate"
            /\ store' = Shrink(Grow(Begin(store), target), capacity)
            /\ capacity' = target /\ phase' = "release"
            /\ UNCHANGED <<queue, target, payload, window>>

ReleaseCharge == /\ phase = "release"
                 /\ store' = Release(Begin(store), store.reserved - capacity)
                 /\ phase' = "push"
                 /\ UNCHANGED <<capacity, queue, target, payload, window>>

Push == /\ phase = "push"
        /\ queue' = Append(Evict(queue, payload + Metadata, window), payload)
        /\ store' = IF CopyOnPush THEN Shrink(Grow(Begin(store), payload), payload)
                    ELSE Begin(store)
        /\ phase' = "idle"
        /\ UNCHANGED <<capacity, target, payload, window>>

Read == /\ phase = "idle" /\ queue # <<>>
        /\ queue' = Tail(queue) /\ store' = Begin(store)
        /\ UNCHANGED <<capacity, phase, target, payload, window>>

Next == (\E n \in 0..2, w \in {4, 8}: Receive(n, w)) \/ Allocate \/ ReleaseCharge \/ Push \/ Read
Spec == Init /\ [][Next]_vars
PaidStorage == Paid(store)
Bounded == WithinLimit(store, Limit)
TracksStorage == Tracks(store, capacity)
FitsRing == Held(queue, 1) <= capacity
NoDelivery == queue = <<>>
=============================================================================
