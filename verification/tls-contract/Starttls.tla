-------------------------- MODULE Starttls --------------------------
EXTENDS Naturals, Sequences
CONSTANTS MaxBytes, Boundary, DropSuffix, StopPlain, WaitWritten
VARIABLES phase, received, plain, discarded, pending, tlsInput, produced, written
vars == <<phase, received, plain, discarded, pending, tlsInput, produced, written>>

\* Source: tests/it/services/tls.rs 199-209 makes Secure at STARTTLS;
\* 244-259 stops parsing and clears the same-read suffix, discards later data;
\* 279-282 counts output, 299-306 waits for completion and hands only control
\* events to the successor. src/stdlib/layer/switch.rs 138-146 routes by phase,
\* 198-223 transfers leftovers once. Boundary abstracts the end of STARTTLS,
\* every byte position is distinct, and Read explores every chunk boundary.
\* Only the concrete Mail handoff has the discard rule: generic Switch does
\* not and cannot distinguish arbitrary protocol plaintext from TLS records.
Init == /\ phase = "plain" /\ received = 0 /\ plain = <<>>
        /\ discarded = <<>> /\ pending = <<>> /\ tlsInput = <<>>
        /\ produced = 0 /\ written = 0
Min(a,b) == IF a < b THEN a ELSE b
Range(a,b) == [i \in 1..(b-a+1) |-> a+i-1]
Read(n) ==
    /\ received < n /\ n <= MaxBytes
    /\ received' = n
    /\ IF phase = "plain"
       THEN /\ plain' = plain \o Range(received+1, IF StopPlain THEN Min(n,Boundary) ELSE n)
            /\ phase' = IF n >= Boundary THEN "waiting" ELSE "plain"
            /\ pending' = IF n > Boundary /\ ~DropSuffix THEN Range(Boundary+1,n) ELSE pending
            /\ discarded' = IF n > Boundary /\ DropSuffix THEN discarded \o Range(Boundary+1,n) ELSE discarded
            /\ UNCHANGED tlsInput
       ELSE IF phase = "waiting"
       THEN /\ pending' = IF DropSuffix THEN pending ELSE pending \o Range(received+1,n)
            /\ discarded' = IF DropSuffix THEN discarded \o Range(received+1,n) ELSE discarded
            /\ UNCHANGED <<phase, plain, tlsInput>>
       ELSE /\ tlsInput' = tlsInput \o [i \in 1..(n-received) |-> [byte |-> received+i, old |-> FALSE]]
            /\ UNCHANGED <<phase, plain, pending, discarded>>
    /\ UNCHANGED <<produced,written>>
Produce == /\ phase = "waiting" /\ produced = 0 /\ produced' = 2
           /\ UNCHANGED <<phase,received,plain,discarded,pending,tlsInput,written>>
Complete == /\ written < produced /\ written' = written+1
            /\ UNCHANGED <<phase,received,plain,discarded,pending,tlsInput,produced>>
Switch == /\ phase = "waiting" /\ produced = 2
          /\ (~WaitWritten \/ written = produced)
          /\ phase' = "tls"
          /\ tlsInput' = [i \in 1..Len(pending) |-> [byte |-> pending[i], old |-> TRUE]]
          /\ pending' = <<>>
          /\ UNCHANGED <<received,plain,discarded,produced,written>>
Next == (\E n \in 1..MaxBytes: Read(n)) \/ Produce \/ Complete \/ Switch
Spec == Init /\ [][Next]_vars
NoPlainPastBoundary == \A i \in 1..Len(plain): plain[i] <= Boundary
NoPlaintextReplay == \A i \in 1..Len(tlsInput): ~tlsInput[i].old
PlaintextFence == phase = "tls" => written = produced
=====================================================================
