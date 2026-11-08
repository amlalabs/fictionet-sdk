---------------------------- MODULE Boundary ----------------------------
\* Source: src/stdlib/services/ssh.rs:1013-1027 authentication success;
\* :1265-1309 packet authorization; :1311-1478 negotiation and queued input;
\* :804-818 child factory; src/stdlib/layer/children.rs:394-479 reservation
\* and factory ordering; src/stdlib/services/ssh/transport.rs:214-264 fatal poll errors.
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
