------------------------------ MODULE RfcGoaway ------------------------------
(* RFC 9113 for an endpoint that ends a connection: GOAWAY and what may    *)
(* follow it, written from the RFC's text. An implementation module maps   *)
(* its output and streams onto the variables below.                       *)
(*                                                                        *)
(*   out      the frames the endpoint emits, in order: those written and   *)
(*            those queued behind them. A frame is a record [f (which      *)
(*            frame), kind ("data", "headers", "ctl", "rst", "ping",        *)
(*            "goaway"), part ("whole", or "head" and "payload" for a frame *)
(*            whose header and payload are queued apart), code (a GOAWAY's *)
(*            error), last (a GOAWAY's last stream)]                       *)
(*   cause    why the connection ends: "none" while it goes on, "budget"   *)
(*            for load it refuses, "error" for a peer's protocol error     *)
(*   acted    the streams the endpoint opened, so acted on                 *)
(*   unread   the stream of a header block the endpoint began to read but *)
(*            never decoded, or 0                                          *)
(*   live     the streams still open in the endpoint                      *)
EXTENDS Integers, Sequences, FiniteSets

VARIABLES out, cause, acted, unread, live
vars == <<out, cause, acted, unread, live>>

Terminal(fr) == fr.kind = "goaway" /\ fr.code # "NO_ERROR"
Goaways == {i \in DOMAIN out : out[i].kind = "goaway"}

\* Section 5.4.1: after the GOAWAY for an error, the endpoint closes the
\* connection: no frame follows it.
TerminalLast == \A i \in DOMAIN out : Terminal(out[i]) => i = Len(out)

\* Sections 5.4.1 and 7: a connection that ends for an error says so with
\* GOAWAY, and load the endpoint refuses is ENHANCE_YOUR_CALM.
RefusalSaysGoaway ==
  cause # "none" =>
    \E i \in DOMAIN out : Terminal(out[i])
                          /\ (cause = "budget" => out[i].code = "ENHANCE_YOUR_CALM")

\* Section 4.1: frames go out whole, one after another: a frame whose header
\* and payload are queued apart has nothing between them, so a GOAWAY
\* begins a frame of its own.
WholeFrames ==
  \A i \in DOMAIN out :
    /\ out[i].part = "head" => i < Len(out) /\ out[i + 1].part = "payload" /\ out[i + 1].f = out[i].f
    /\ out[i].part = "payload" => i > 1 /\ out[i - 1].part = "head" /\ out[i - 1].f = out[i].f

\* Section 6.8: the last stream of each GOAWAY is at most the one before.
LastNeverGrows ==
  \A i, j \in Goaways : i < j => out[j].last <= out[i].last

\* Section 6.8: the last stream of the GOAWAY that ends the connection
\* covers every stream the endpoint acted on, and not a stream whose
\* header block it never read whole (the peer may send that one again).
LastCoversActed ==
  \A i \in DOMAIN out :
    Terminal(out[i]) => /\ \A s \in acted : s <= out[i].last
                        /\ unread # 0 => out[i].last < unread

\* Section 6.8: a connection that ends leaves no stream open in it, so no
\* stream's state is carried on.
NoStreamCarriedOn == cause # "none" => live = {}

\* Section 6.8: once the connection ends, the endpoint acts on no stream.
NothingAfterEnd == [][cause # "none" => acted' = acted]_vars
=============================================================================
