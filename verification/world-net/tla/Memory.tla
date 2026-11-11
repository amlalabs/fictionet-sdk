------------------------------ MODULE Memory ------------------------------
(***************************************************************************)
(* Sources: src/cable.rs, pair, pair_with_limit, Direction::reserve,        *)
(* End::send and take; src/packet_queue.rs, cost, PacketQueue::try_push     *)
(* and pop; src/listen.rs, OutQueue::new; src/stdlib/network/ports.rs,      *)
(* Ports::add; src/stdlib/world/net/attachments.rs, Context::routed and    *)
(* join_lan, Attached::new, Filter::bound_now; src/stdlib/layer/driver.rs, *)
(* Observations::observe; src/stdlib/layer/charged.rs, ChargedDeque.        *)
(* One unit is one scaled byte of capacity or overhead. Record + Place   *)
(* represents a backing record and queue slot. OldPacketCost represents  *)
(* the old 64-byte allowance; RecordCost selects the corrected allowance. *)
(* The corrected source counts Chunk::RECORD_BYTES, Packet and two words. *)
(* Send counts before queueing; delivery unqueues before releasing.      *)
(* A report already exists in the flight store. Observe charges its heap *)
(* then its place, then transfers ownership, or drops the report.         *)
(* Sandbox allocations charge first. Charge returns are separate steps   *)
(* so Paid checks allocation peaks before the reservation is reduced.    *)
(* EngineBlocks is an assumed bound for channel block overhead. Topology *)
(* and application maxima are trusted world assumptions, not code limits.*)
(* WorldBind includes binds triggered by received agent packets: calling *)
(* this a world step describes ownership, not causal independence from   *)
(* agent traffic. Persistent address entries make that distinction matter.*)
(* The model has one representative link, one sandbox and one report     *)
(* store. The listener's outbound queue uses the same admission rule but  *)
(* is not a second modeled queue. Queue reallocation, packet sharing,     *)
(* report draining, allocator rounding and topology removal are omitted. *)
(* Report slots are exact single places; Growth models moving containers.*)
(* An unlimited link counts nothing. Its control checks AgentBounded;    *)
(* it also lacks the limited-link payment guarantee.                     *)
(***************************************************************************)
EXTENDS Integers, Sequences, Resources
CONSTANTS LinkLimit, SandboxLimit, ReportLimit, ReportMax, EngineBlocks,
          TopologyMax, AppMax, MaxPacket, Record, Place, OldPacketCost,
          CountFirst, RecordCost, AgentOnLimitedLink, ChargeReportFirst
VARIABLE x
PacketCost == IF RecordCost THEN Record + Place ELSE OldPacketCost
Cost(c) == c + PacketCost
Kept(c) == c + Record + Place
RECURSIVE Sum(_)
Sum(q) == IF q = <<>> THEN 0 ELSE Kept(Head(q)) + Sum(Tail(q))
Fresh == [x EXCEPT !.link = Begin(@), !.sandbox = Begin(@),
                  !.reports = Begin(@), !.report = Begin(@), !.engine = Begin(@),
                  !.topology = Begin(@), !.app = Begin(@),
                  !.beforeTopology = x.topologyBytes, !.beforeApp = x.appBytes,
                  !.kind = "agent"]
Init == x = [link |-> Store(0), sandbox |-> Store(0), reports |-> Store(0),
             report |-> Store(ReportMax), engine |-> Store(EngineBlocks),
             topology |-> Store(TopologyMax), app |-> Store(AppMax),
             queue |-> <<>>, sandboxBytes |-> 0, reportBytes |-> 0,
             flight |-> 0, engineBytes |-> 0, topologyBytes |-> 0, appBytes |-> 0,
             beforeTopology |-> 0, beforeApp |-> 0, kind |-> "initial",
             phase |-> "idle", pending |-> 0, open |-> TRUE]

Send(c) ==
    /\ x.phase = "idle"
    /\ IF ~x.open THEN x' = Fresh
       ELSE IF AgentOnLimitedLink /\ CountFirst /\ x.link.reserved + Cost(c) > LinkLimit
       THEN x' = Fresh
       ELSE x' = [Fresh EXCEPT !.queue = Append(@, c), !.pending = c,
           !.link = Grow(IF AgentOnLimitedLink /\ CountFirst
                         THEN Reserve(Begin(x.link), Cost(c)) ELSE Begin(x.link), Kept(c)),
           !.phase = IF AgentOnLimitedLink /\ ~CountFirst THEN "count" ELSE "idle"]

LateCount ==
    /\ x.phase = "count"
    /\ IF x.link.reserved + Cost(x.pending) <= LinkLimit
       THEN x' = [Fresh EXCEPT !.link = Reserve(Begin(x.link), Cost(x.pending)), !.phase = "idle"]
       ELSE x' = [Fresh EXCEPT !.link = Shrink(Begin(x.link), Kept(x.pending)),
           !.queue = SubSeq(@, 1, Len(@) - 1), !.phase = "idle"]

Deliver ==
    /\ x.phase = "idle" /\ x.queue # <<>>
    /\ x' = [Fresh EXCEPT !.link = Shrink(Begin(x.link), Kept(Head(x.queue))),
        !.pending = Cost(Head(x.queue)), !.queue = Tail(@),
        !.phase = IF AgentOnLimitedLink THEN "releaseLink" ELSE "idle"]
ReleaseLink ==
    /\ x.phase = "releaseLink"
    /\ x' = [Fresh EXCEPT !.link = Release(Begin(x.link), x.pending), !.phase = "idle"]
CloseLink == /\ x.phase = "idle" /\ x.open /\ x' = [Fresh EXCEPT !.open = FALSE]

SandboxGrow(k) ==
    /\ x.phase = "idle"
    /\ IF x.sandbox.reserved + k > SandboxLimit THEN x' = Fresh
       ELSE x' = [Fresh EXCEPT !.sandbox = Grow(Reserve(Begin(x.sandbox), k), k),
                              !.sandboxBytes = @ + k]
SandboxFree(k) ==
    /\ x.phase = "idle" /\ k <= x.sandboxBytes
    /\ x' = [Fresh EXCEPT !.sandbox = Shrink(Begin(x.sandbox), k),
        !.sandboxBytes = @ - k, !.pending = k, !.phase = "releaseSandbox"]
ReleaseSandbox ==
    /\ x.phase = "releaseSandbox"
    /\ x' = [Fresh EXCEPT !.sandbox = Release(Begin(x.sandbox), x.pending), !.phase = "idle"]

Report(h) ==
    /\ x.phase = "idle"
    /\ x' = [Fresh EXCEPT !.report = Grow(Begin(x.report), h), !.flight = h,
        !.pending = h, !.phase = IF ChargeReportFirst THEN "reportHeap" ELSE "earlyKeep"]
EarlyKeep ==
    /\ x.phase = "earlyKeep"
    /\ x' = [Fresh EXCEPT !.reports = Grow(Begin(x.reports), x.pending + 1),
        !.reportBytes = @ + x.pending + 1,
        !.report = Shrink(Begin(x.report), x.flight), !.flight = 0, !.phase = "lateReport"]
LateReport ==
    /\ x.phase = "lateReport"
    /\ IF x.reports.reserved + x.pending + 1 <= ReportLimit
       THEN x' = [Fresh EXCEPT !.reports = Reserve(Reserve(Begin(x.reports), x.pending), 1),
                              !.phase = "idle"]
       ELSE x' = [Fresh EXCEPT !.reports = Shrink(Begin(x.reports), x.pending + 1),
                              !.reportBytes = @ - x.pending - 1, !.phase = "idle"]
ReportHeap ==
    /\ x.phase = "reportHeap"
    /\ IF x.reports.reserved + x.pending > ReportLimit
       THEN x' = [Fresh EXCEPT !.phase = "dropReport"]
       ELSE x' = [Fresh EXCEPT !.reports = Reserve(Begin(x.reports), x.pending),
                              !.phase = "reportPlace"]
ReportPlace ==
    /\ x.phase = "reportPlace"
    /\ IF x.reports.reserved + 1 > ReportLimit
       THEN x' = [Fresh EXCEPT !.reports = Release(Begin(x.reports), x.pending),
                              !.phase = "dropReport"]
       ELSE x' = [Fresh EXCEPT !.reports = Reserve(Begin(x.reports), 1), !.phase = "keepReport"]
KeepReport ==
    /\ x.phase = "keepReport"
    /\ x' = [Fresh EXCEPT !.reports = Grow(Begin(x.reports), x.pending + 1),
        !.reportBytes = @ + x.pending + 1,
        !.report = Shrink(Begin(x.report), x.flight), !.flight = 0, !.phase = "idle"]
DropReport ==
    /\ x.phase = "dropReport"
    /\ x' = [Fresh EXCEPT !.report = Shrink(Begin(x.report), x.flight),
                          !.flight = 0, !.phase = "idle"]

Engine(held) ==
    /\ x.phase = "idle"
    /\ x' = [Fresh EXCEPT !.engine = IF held >= x.engineBytes
        THEN Grow(Begin(x.engine), held - x.engineBytes)
        ELSE Shrink(Begin(x.engine), x.engineBytes - held), !.engineBytes = held]
WorldTopology(kind) ==
    /\ x.phase = "idle" /\ x.topologyBytes < TopologyMax
    /\ x' = [Fresh EXCEPT !.topology = Grow(Begin(x.topology), 1),
        !.topologyBytes = @ + 1, !.kind = kind]
WorldAddPort == WorldTopology("port")
WorldAttach == WorldTopology("attach")
WorldBind == WorldTopology("bind")
AppAlloc ==
    /\ x.phase = "idle" /\ x.appBytes < AppMax
    /\ x' = [Fresh EXCEPT !.app = Grow(Begin(x.app), 1), !.appBytes = @ + 1, !.kind = "app"]
AppFree ==
    /\ x.phase = "idle" /\ x.appBytes > 0
    /\ x' = [Fresh EXCEPT !.app = Shrink(Begin(x.app), 1), !.appBytes = @ - 1, !.kind = "app"]

Next == (\E c \in 0..MaxPacket : Send(c)) \/ LateCount \/ Deliver \/ ReleaseLink \/ CloseLink
        \/ (\E k \in 1..SandboxLimit : SandboxGrow(k) \/ SandboxFree(k)) \/ ReleaseSandbox
        \/ (\E h \in 0..ReportMax : Report(h)) \/ EarlyKeep \/ LateReport
        \/ ReportHeap \/ ReportPlace \/ KeepReport \/ DropReport
        \/ (\E held \in 0..EngineBlocks : Engine(held))
        \/ WorldAddPort \/ WorldAttach \/ WorldBind \/ AppAlloc \/ AppFree \/ x' = Fresh
Spec == Init /\ [][Next]_x
LinkPaid == Paid(x.link)
SandboxPaid == Paid(x.sandbox)
ReportsPaid == Paid(x.reports)
EnginePaid == Paid(x.engine) /\ Paid(x.report)
TrustedPaid == Paid(x.topology) /\ Paid(x.app)
BudgetsWithinLimit == /\ WithinLimit(x.link, LinkLimit)
                      /\ WithinLimit(x.sandbox, SandboxLimit)
                      /\ WithinLimit(x.reports, ReportLimit)
                      /\ WithinLimit(x.report, ReportMax)
                      /\ WithinLimit(x.engine, EngineBlocks)
                      /\ WithinLimit(x.topology, TopologyMax)
                      /\ WithinLimit(x.app, AppMax)
StoresTrack == /\ Tracks(x.link, Sum(x.queue)) /\ Tracks(x.sandbox, x.sandboxBytes)
               /\ Tracks(x.reports, x.reportBytes) /\ Tracks(x.report, x.flight)
               /\ Tracks(x.engine, x.engineBytes) /\ Tracks(x.topology, x.topologyBytes)
               /\ Tracks(x.app, x.appBytes)
AgentHeld == x.link.held + x.sandbox.held + x.reports.held + x.report.held + x.engine.held
AgentBounded == AgentHeld <= LinkLimit + SandboxLimit + ReportLimit + ReportMax + EngineBlocks
TotalHeld == Sum(x.queue) + x.sandboxBytes + x.reportBytes + x.flight
             + x.engineBytes + x.topologyBytes + x.appBytes
Decomposition ==
    /\ TotalHeld = (x.link.held + x.sandbox.held + x.reports.held)
                   + (x.engine.held + x.report.held) + x.topology.held + x.app.held
    /\ x.topologyBytes <= TopologyMax /\ x.appBytes <= AppMax
    /\ (x.kind = "agent" => x.topologyBytes = x.beforeTopology /\ x.appBytes = x.beforeApp)
=============================================================================
