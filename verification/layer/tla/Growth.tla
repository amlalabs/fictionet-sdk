----------------------------- MODULE Growth -----------------------------
(***************************************************************************)
(* Sources: src/stdlib/layer/charged.rs, charge_places, moving_out,          *)
(* ChargedDeque::reserve and shrink_to, ChargedVec::reserve and shrink_to;   *)
(* buf/src/budget.rs, Charge::grow_by_units_moving, Budget::try_charge;      *)
(* src/stdlib/layer/children.rs, Places::reserve, make_room, grow_to, keep,  *)
(* release, Kid::retire, and Children::on_event's Spare pop.                *)
(* One unit is one container place, or one place in one router table.      *)
(* Two tables stand for the router's several tables. Queue is fixed.       *)
(* Parts are a subaccount of paid places, not another budget charge.       *)
(* Growth takes moving and new units together, allocates then frees.       *)
(* Shrink charges the new block, allocates it, then frees the old block.   *)
(* Charge returns are separate steps: Resources.Paid compares peak with   *)
(* the current reservation. Begin resets peak only at these boundaries.   *)
(* No other operation interleaves with a pending charge return.            *)
(* The model omits item payloads, allocator rounding, command backlog,     *)
(* failed child construction, and external owners of retired parts.       *)
(* Real release keeps max(FLOOR, closing commands beyond QUEUE). Here     *)
(* closing commands are drained before release, so it keeps Floor.        *)
(* Under these open/close rules the spare cap is redundant: opening pops  *)
(* a spare, and closing converts a kid to a spare. Removing only the cap  *)
(* cannot increase their sum. The spare control exposes that limitation.  *)
(***************************************************************************)
EXTENDS Integers, Resources
CONSTANTS Limit, Most, Floor, Queue, ChildLimit, ChargeMove, CapSpares
VARIABLE x
Min(a, b) == IF a < b THEN a ELSE b
Max(a, b) == IF a > b THEN a ELSE b
More(p, most) == Min(Max(2 * p, 4), most)
Places(c) == IF c = 0 THEN 0 ELSE Queue + 2 * c
Fresh == [x EXCEPT !.container = Begin(@), !.places = Begin(@), !.parts = Begin(@)]
Room == Limit - x.container.reserved - x.places.reserved
Idle == x.returnContainer = 0 /\ x.returnPlaces = 0

Init == x = [p |-> 0, n |-> 0, c |-> 0, kids |-> 0, spares |-> 0,
             container |-> Store(0), places |-> Store(0), parts |-> Store(0),
             returnContainer |-> 0, returnPlaces |-> 0, movingContainer |-> 0, movingPlaces |-> 0]

Push ==
    /\ Idle /\ x.n < Most
    /\ IF x.n < x.p
       THEN x' = [Fresh EXCEPT !.n = @ + 1]
       ELSE LET moving == IF ChargeMove THEN x.p ELSE 0
                k == Min(More(x.p, Most) - x.p, Max(0, Room - moving))
            IN IF k = 0 THEN x' = Fresh
               ELSE x' = [Fresh EXCEPT
                   !.container = Shrink(Grow(Reserve(Begin(x.container), moving + k),
                                             x.p + k), x.p),
                   !.p = @ + k, !.n = @ + 1, !.returnContainer = moving,
                   !.movingContainer = moving]

Pop == /\ Idle /\ x.n > 0 /\ x' = [Fresh EXCEPT !.n = @ - 1]

Trim(wanted) ==
    /\ Idle
    /\ LET keep == Max(wanted, x.n)
           moving == IF ChargeMove THEN keep ELSE 0
       IN /\ keep < x.p
          /\ IF moving > Room THEN x' = Fresh
             ELSE x' = [Fresh EXCEPT
                 !.container = Shrink(Grow(Reserve(Begin(x.container), moving), keep), x.p),
                 !.p = keep, !.returnContainer = x.p - keep + moving,
                 !.movingContainer = moving]

ReservePlaces ==
    /\ Idle /\ x.c = 0
    /\ IF Places(Floor) > Room THEN x' = Fresh
       ELSE x' = [Fresh EXCEPT !.c = Floor,
           !.places = Grow(Reserve(Begin(x.places), Places(Floor)), Places(Floor)),
           !.parts = Reserve(Begin(x.parts), Floor)]

MakeRoom ==
    /\ Idle /\ x.c > 0 /\ x.kids = x.c /\ x.c < ChildLimit
    /\ LET moving == IF ChargeMove THEN Places(x.c) ELSE 0
           k == Min(More(x.c, Min(Most, ChildLimit)) - x.c,
                    Max(0, Room - moving) \div 2)
           paid == Reserve(Begin(x.places), moving + 2 * k)
           first == Shrink(Grow(paid, x.c + k), x.c)
           second == Shrink(Grow(first, x.c + k), x.c)
       IN IF k = 0 THEN x' = Fresh
          ELSE x' = [Fresh EXCEPT !.c = @ + k, !.places = second,
              !.parts = Reserve(Begin(x.parts), k), !.returnPlaces = moving,
              !.movingPlaces = moving]

Open ==
    /\ Idle /\ x.kids < x.c /\ x.kids < ChildLimit
    /\ x' = [Fresh EXCEPT !.kids = @ + 1,
        !.spares = IF x.spares > 0 THEN @ - 1 ELSE @,
        !.parts = IF x.spares > 0 THEN Begin(x.parts) ELSE Grow(Begin(x.parts), 1)]

Close ==
    /\ Idle /\ x.kids > 0
    /\ LET keep == ~CapSpares \/ x.spares < x.c - (x.kids - 1)
       IN x' = [Fresh EXCEPT !.kids = @ - 1,
           !.spares = IF keep THEN @ + 1 ELSE @,
           !.parts = IF keep THEN Begin(x.parts) ELSE Shrink(Begin(x.parts), 1)]

ReleasePlaces ==
    /\ Idle /\ x.kids = 0 /\ x.c > Floor
    /\ LET moving == IF ChargeMove THEN Places(Floor) ELSE 0
           kept == Min(x.spares, Floor)
       IN IF moving > Room THEN x' = Fresh
          ELSE x' = [Fresh EXCEPT !.c = Floor, !.spares = kept,
              !.places = Shrink(Grow(Reserve(Begin(x.places), moving), 2 * Floor), 2 * x.c),
              !.parts = Shrink(Begin(x.parts), x.spares - kept),
              !.returnPlaces = 2 * (x.c - Floor) + moving, !.movingPlaces = moving]

ReturnCharges ==
    /\ ~Idle
    /\ x' = [Fresh EXCEPT
        !.container = Release(Release(Begin(x.container),
                              x.returnContainer - x.movingContainer), x.movingContainer),
        !.places = Release(Release(Begin(x.places),
                           x.returnPlaces - x.movingPlaces), x.movingPlaces),
        !.parts = Release(Begin(x.parts), x.parts.reserved - x.c),
        !.returnContainer = 0, !.returnPlaces = 0, !.movingContainer = 0, !.movingPlaces = 0]

Next == Push \/ Pop \/ (\E keep \in 0..Most : Trim(keep))
        \/ ReservePlaces \/ MakeRoom \/ Open \/ Close \/ ReleasePlaces
        \/ ReturnCharges \/ x' = Fresh
Spec == Init /\ [][Next]_x
ContainerPaid == Paid(x.container)
PlacesPaid == Paid(x.places)
PartsPaid == Paid(x.parts)
BudgetWithinLimit == x.container.reserved + x.places.reserved <= Limit
ContainerTracks == Tracks(x.container, x.p)
PlacesTracks == Tracks(x.places, Places(x.c))
PartsTracks == Tracks(x.parts, x.kids + x.spares)
Shape == /\ x.n \in 0..x.p /\ x.p \in 0..Most
         /\ x.kids \in 0..x.c /\ x.c \in 0..ChildLimit
         /\ x.spares >= 0
=============================================================================
