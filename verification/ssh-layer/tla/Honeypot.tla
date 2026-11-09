---------------------------- MODULE Honeypot ----------------------------
\* Source: demos/honeypot/src/ssh.rs:150-202 (factory and line submission);
\* src/stdlib/services/ssh/session.rs:64-68,259-261,338-392 (policy and drain);
\* src/stdlib/services/ssh.rs:1254-1263,1294-1310 (draining and policy priority).
EXTENDS Naturals
CONSTANT Mutation
VARIABLES phase, policy, commandSeen, executed, callbacks, stoppedAt
vars == <<phase, policy, commandSeen, executed, callbacks, stoppedAt>>
\* demos/honeypot/src/ssh.rs Application::open and Shell::input: nonempty
\* lines, exec and subsystem call hangup; empty lines and interrupts prompt.
\* session.rs on_event refuses after hangup; account publishes policy;
\* ssh.rs progress checks policy before pending_packets, packet ignores input
\* while draining but still accepts window adjustments needed to flush echo.
Init == /\ phase = "prompt" /\ policy = FALSE /\ commandSeen = FALSE
        /\ executed = FALSE /\ callbacks = 0 /\ stoppedAt = 0
Prompt == /\ phase = "prompt" /\ callbacks < 2 /\ callbacks' = callbacks + 1
          /\ UNCHANGED <<phase, policy, commandSeen, executed, stoppedAt>>
Submit == /\ phase = "prompt"
          /\ phase' = "drain" /\ policy' = TRUE /\ commandSeen' = TRUE
          /\ executed' = (Mutation = "execute") /\ stoppedAt' = callbacks
          /\ UNCHANGED callbacks
MoreInput == /\ phase = "drain" /\ callbacks < 3 /\ Mutation = "gate"
             /\ callbacks' = callbacks + 1
             /\ UNCHANGED <<phase, policy, commandSeen, executed, stoppedAt>>
Flush == /\ phase = "drain" /\ phase' = "closed"
         /\ UNCHANGED <<policy, commandSeen, executed, callbacks, stoppedAt>>
Next == Prompt \/ Submit \/ MoreInput \/ Flush
NeverExecute == ~executed
StopInput == commandSeen => callbacks = stoppedAt
=============================================================================
