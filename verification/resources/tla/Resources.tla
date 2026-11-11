----------------------------- MODULE Resources -----------------------------
(***************************************************************************)
(* Storage that is paid for before it grows.                              *)
(*                                                                         *)
(* A store is a record [held, peak, reserved, short]: what a part of the  *)
(* code holds now, the most it held at any moment of the current step,    *)
(* what it has reserved from its budget, and the most it held past what   *)
(* was reserved at any moment of the step. A TLA+ step is atomic, so a    *)
(* transient inside it (an entry added, then the old ones dropped) is     *)
(* invisible to an invariant on the state alone. A model threads the     *)
(* store through each part of the step that grows or shrinks storage, in  *)
(* the order the code does them. Grow records the peak, and Grow and      *)
(* Release record any moment that held more than was reserved then: a    *)
(* step that moves storage reserves the new block, grows it, frees the    *)
(* old one and releases its charge, so its peak is past what it reserves  *)
(* at the end, and only the moment says whether it was paid.              *)
(*                                                                         *)
(* A model:                                                                *)
(*   - starts each step with Begin, so the peak is the step's own;        *)
(*   - calls Reserve or ReserveTo where the code charges its budget, and  *)
(*     Release where it gives the charge back;                            *)
(*   - calls Grow and Shrink where the code allocates and frees, in the   *)
(*     code's order;                                                       *)
(*   - checks Paid (no moment held more than was reserved) and           *)
(*     WithinLimit (the reservation stays within the budget's limit) as   *)
(*     invariants, and Tracks (the store's held is what the model's own   *)
(*     state says is held), which catches a step that forgot to thread    *)
(*     the store.                                                          *)
(*                                                                         *)
(* Sizes are the model's own units; each model says what one stands for.  *)
(* Use it with EXTENDS Resources, and run TLC with                         *)
(* -DTLA-Library=<repository>/verification/resources/tla.                 *)
(***************************************************************************)
EXTENDS Naturals

\* What h held past r reserved comes to: zero when it was paid for.
Over(h, r) == IF h > r THEN h - r ELSE 0

Larger(a, b) == IF a > b THEN a ELSE b

\* A store holding nothing, with r reserved.
Store(r) == [held |-> 0, peak |-> 0, reserved |-> r, short |-> 0]

\* A new step: its peak and its shortfall start at what is held.
Begin(s) == [s EXCEPT !.peak = s.held, !.short = Over(s.held, s.reserved)]

\* The code allocates n more.
Grow(s, n) ==
    [s EXCEPT !.held = s.held + n,
              !.peak = Larger(s.held + n, s.peak),
              !.short = Larger(Over(s.held + n, s.reserved), s.short)]

\* The code frees n.
Shrink(s, n) == [s EXCEPT !.held = s.held - n]

\* The code's storage becomes h, by allocating or freeing.
SetHeld(s, h) == IF h >= s.held THEN Grow(s, h - s.held) ELSE Shrink(s, s.held - h)

\* The code charges its budget n more, or raises its charge to r.
Reserve(s, n) == [s EXCEPT !.reserved = s.reserved + n]
ReserveTo(s, r) == [s EXCEPT !.reserved = IF r > s.reserved THEN r ELSE s.reserved]

\* The code gives n of its charge back.
Release(s, n) ==
    [s EXCEPT !.reserved = s.reserved - n,
              !.short = Larger(Over(s.held, s.reserved - n), s.short)]

\* No moment of the step held more than was reserved at that moment.
Paid(s) == s.short = 0 /\ s.held <= s.reserved

\* The reservation stays within the budget's limit.
WithinLimit(s, limit) == s.reserved <= limit

\* The store holds what the model's state says the code holds.
Tracks(s, h) == s.held = h
=============================================================================
