---------------------------- MODULE Boundary ----------------------------
\* Source: src/stdlib/services/ssh.rs:996-1009 authentication success;
\* :1264-1293 packet authorization (connection messages need a user,
\* 1287); :1294-1476 negotiation and queued input (queued packets are
\* taken only in State::Established, 1322 and 1342-1346; Rekeying is
\* its own state, services/ssh/transport.rs:205-220); :788-802 child
\* factory; src/stdlib/layer/children.rs:858-922 reservation and factory
\* ordering; src/stdlib/services/ssh/transport.rs:242-285 fatal poll errors.
EXTENDS Naturals, Sequences
CONSTANT Mutation
VARIABLES transport, authenticated, queue, delivered, factory
vars == <<transport, authenticated, queue, delivered, factory>>
\* ssh.rs packet, progress, connection_message and sessions; transport.rs poll.
\* An application delivery records the authorization at delivery, not afterward.
Init == /\ transport = "pending" /\ authenticated = FALSE
        /\ queue = <<>> /\ delivered = <<>> /\ factory = FALSE
Negotiate == /\ transport = "pending" /\ transport' = "ready"
             /\ UNCHANGED <<authenticated, queue, delivered, factory>>
Fail == /\ transport \in {"pending", "ready", "rekey"} /\ transport' = "failed"
        /\ UNCHANGED <<authenticated, queue, delivered, factory>>
Authenticate == /\ transport = "ready" /\ ~authenticated
                /\ authenticated' = TRUE
                /\ UNCHANGED <<transport, queue, delivered, factory>>
Receive == /\ transport # "failed" /\ Len(queue) < 2
           /\ queue' = Append(queue, "open")
           /\ UNCHANGED <<transport, authenticated, delivered, factory>>
Deliver == /\ Len(queue) > 0 /\ Len(delivered) < 2
           /\ (transport = "ready" \/ (Mutation = "failure" /\ transport = "failed")
               \/ (Mutation = "rekey" /\ transport = "rekey"))
           /\ (authenticated \/ Mutation = "authentication")
           /\ delivered' = Append(delivered, [auth |-> authenticated, state |-> transport])
           /\ queue' = Tail(queue)
           /\ UNCHANGED <<transport, authenticated, factory>>
Factory == /\ ~factory /\ (Len(delivered) > 0 \/ Mutation = "factory")
           /\ factory' = TRUE /\ UNCHANGED <<transport, authenticated, queue, delivered>>
BeginRekey == /\ transport = "ready" /\ transport' = "rekey"
              /\ UNCHANGED <<authenticated, queue, delivered, factory>>
FinishRekey == /\ transport = "rekey" /\ transport' = "ready"
               /\ UNCHANGED <<authenticated, queue, delivered, factory>>
Next == Negotiate \/ Fail \/ Authenticate \/ Receive \/ Deliver \/ Factory
        \/ BeginRekey \/ FinishRekey
Authenticated == \A i \in 1..Len(delivered): delivered[i].auth
Negotiated == \A i \in 1..Len(delivered): delivered[i].state = "ready"
FactoryAfterOpen == factory => Len(delivered) > 0
=============================================================================
