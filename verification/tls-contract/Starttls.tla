-------------------------- MODULE Starttls --------------------------
EXTENDS Naturals, Sequences
CONSTANTS MaxBytes, Boundary, DropSuffix, StopPlain, WaitWritten, SwitchDrops
VARIABLES phase, received, plain, discarded, pending, tlsInput, produced, written
vars == <<phase, received, plain, discarded, pending, tlsInput, produced, written>>

\* Source: tests/it/services/tls.rs 273-288 makes Secure at STARTTLS;
\* 323-370 stops parsing at STARTTLS and, unless the session is careless,
\* drops the rest of the chunk and later data; a careless session hands
\* them over or refuses them. 380-384 counts output, 413-425 waits for
\* completion before handing over. src/stdlib/layer/switch.rs 167-194
\* routes by phase and drops a refused event Secure does not inherit when
\* it comes again; 245-264 drops the handed-over events Secure does not
\* inherit and transfers the rest once; services/tls/secure.rs 175-177
\* says Secure inherits no data. Boundary abstracts the end of STARTTLS,
\* every byte position is distinct, and Read explores every chunk boundary.
\* pending is what the session kept past the boundary, handed over or left
\* below: both are input the switch saw before it switched. DropSuffix is
\* the careful session's own drop, SwitchDrops the switch's.
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
          /\ tlsInput' = IF SwitchDrops THEN <<>>
                         ELSE [i \in 1..Len(pending) |-> [byte |-> pending[i], old |-> TRUE]]
          /\ discarded' = IF SwitchDrops THEN discarded \o pending ELSE discarded
          /\ pending' = <<>>
          /\ UNCHANGED <<received,plain,produced,written>>
Next == (\E n \in 1..MaxBytes: Read(n)) \/ Produce \/ Complete \/ Switch
Spec == Init /\ [][Next]_vars
NoPlainPastBoundary == \A i \in 1..Len(plain): plain[i] <= Boundary
NoPlaintextReplay == \A i \in 1..Len(tlsInput): ~tlsInput[i].old
PlaintextFence == phase = "tls" => written = produced
=====================================================================
