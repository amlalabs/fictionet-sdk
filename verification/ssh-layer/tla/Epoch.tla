---------------------------- MODULE Epoch ----------------------------
\* Source: src/stdlib/services/ssh/transport.rs:214-264 (one poll/handle);
\* src/stdlib/protocols/ssh/transport.rs:478-495 (incoming NEWKEYS),
\* :592-668 (outgoing NEWKEYS), :670-680 (application output gate);
\* src/stdlib/services/ssh.rs:1326-1328,1561-1575,1718-1728 (ordered output).
EXTENDS Naturals, Sequences
CONSTANT Mutation
VARIABLES position, epoch, pending, observed, output, produced, sent
vars == <<position, epoch, pending, observed, output, produced, sent>>
\* StandardTransport::poll calls Stream::next once, then Transport::handle
\* installs incoming NEWKEYS before the next decode. Output write_packet is
\* synchronous and Ssh drains out before polling or accepting another command.
\* The same ordered boundary applies independently in each direction.
wire == <<[key |-> 0, kind |-> "data"], [key |-> 0, kind |-> "keys"],
          [key |-> 1, kind |-> "data"], [key |-> 1, kind |-> "keys"],
          [key |-> 2, kind |-> "data"]>>
Init == /\ position = 1 /\ epoch = 0 /\ pending = FALSE /\ observed = <<>>
        /\ output = <<>> /\ produced = 0 /\ sent = <<>>
Decode == /\ position <= Len(wire)
          /\ (~pending \/ Mutation = "install")
          /\ observed' = Append(observed, [used |-> epoch, expected |-> wire[position].key])
          /\ pending' = (pending \/ wire[position].kind = "keys")
          /\ position' = position + 1 /\ UNCHANGED <<epoch, output, produced, sent>>
Install == /\ pending /\ epoch' = epoch + 1 /\ pending' = FALSE
           /\ UNCHANGED <<position, observed, output, produced, sent>>
Emit == /\ produced < Len(wire)
        /\ output' = Append(output, produced + 1) /\ produced' = produced + 1
        /\ UNCHANGED <<position, epoch, pending, observed, sent>>
Write == /\ Len(output) > 0
         /\ IF Mutation = "fifo" /\ Len(output) > 1
             THEN /\ sent' = Append(sent, output[2])
                  /\ output' = <<Head(output)>> \o SubSeq(output, 3, Len(output))
             ELSE /\ sent' = Append(sent, Head(output)) /\ output' = Tail(output)
         /\ UNCHANGED <<position, epoch, pending, observed, produced>>
Next == Decode \/ Install \/ Emit \/ Write
OutgoingOrder == \A i \in 1..Len(sent): sent[i] = i
EpochOrder == \A i \in 1..Len(observed): observed[i].used = observed[i].expected
=============================================================================
