----------------------------- MODULE Socket -----------------------------
EXTENDS Naturals

CONSTANTS OptionReset, Absent

Ports == {0, 1, 65535}
Addresses == {"a", "b"}
Wildcard == "wildcard"
Endpoints == [addr : Addresses, port : Ports]
Listeners == [addr : Addresses \cup {Wildcard}, port : Ports]
Tuples == [local : Endpoints, remote : Endpoints]
Phases == {"Closed", "Listen", "SynSent", "SynReceived", "Established",
           "FinWait1", "FinWait2", "Closing", "CloseWait", "LastAck", "TimeWait"}

VARIABLES phase, listener, tuple, origin, requested
vars == <<phase, listener, tuple, origin, requested>>

Init == /\ phase = "Closed"
        /\ listener = Absent
        /\ tuple = Absent
        /\ origin = "none"
        /\ requested = Absent

Open == phase \notin {"Closed", "TimeWait"}
Matches(endpoint, local) ==
    /\ endpoint.port = local.port
    /\ endpoint.addr = Wildcard \/ endpoint.addr = local.addr

\* This follows the ordered guards in Socket::accepts.
Accepts(packet, control, ack) ==
    IF phase = "Closed" THEN FALSE
    ELSE IF phase = "Listen" /\ (ack \/ control = "Rst") THEN FALSE
    ELSE IF tuple # Absent THEN packet = tuple
    ELSE IF listener # Absent THEN Matches(listener, packet.local)
    ELSE FALSE

\* Reset clears listener and tuple before listen or connect installs its state.
Listen(endpoint) ==
    /\ ~Open
    /\ phase' = "Listen"
    /\ listener' = endpoint
    /\ tuple' = Absent
    /\ origin' = "passive"
    /\ requested' = endpoint

Connect(endpoints) ==
    /\ ~Open
    /\ phase' = "SynSent"
    /\ listener' = Absent
    /\ tuple' = endpoints
    /\ origin' = "active"
    /\ requested' = endpoints

PassiveSyn(packet) ==
    /\ phase = "Listen"
    /\ Accepts(packet, "Syn", FALSE)
    /\ phase' = "SynReceived"
    /\ tuple' = packet
    /\ UNCHANGED <<listener, origin, requested>>

ActiveSyn(ack) ==
    /\ phase = "SynSent"
    /\ phase' = IF ack THEN "Established" ELSE "SynReceived"
    /\ UNCHANGED <<listener, tuple, origin, requested>>

\* An accepted RST has passed ACK and sequence validation in process.
ReceiveReset ==
    /\ phase \notin {"Closed", "Listen"}
    /\ LET restore == phase = "SynReceived" /\ listener # Absent
                         /\ (OptionReset \/ listener.port # 0)
       IN /\ phase' = IF restore THEN "Listen" ELSE "Closed"
          /\ tuple' = Absent
    /\ UNCHANGED <<listener, origin, requested>>

ReceiveAck(finAcknowledged) ==
    /\ phase \in {"SynReceived", "Established", "FinWait1", "FinWait2",
                   "Closing", "CloseWait", "LastAck", "TimeWait"}
    /\ phase' = CASE phase = "SynReceived" -> "Established"
                  [] phase = "FinWait1" /\ finAcknowledged -> "FinWait2"
                  [] phase = "Closing" /\ finAcknowledged -> "TimeWait"
                  [] phase = "LastAck" /\ finAcknowledged -> "Closed"
                  [] OTHER -> phase
    /\ tuple' = IF phase = "LastAck" /\ finAcknowledged THEN Absent ELSE tuple
    /\ UNCHANGED <<listener, origin, requested>>

ReceiveFin(finAcknowledged) ==
    /\ phase \in {"SynReceived", "Established", "FinWait1", "FinWait2"}
    /\ phase' = CASE phase \in {"SynReceived", "Established"} -> "CloseWait"
                  [] phase = "FinWait1" /\ finAcknowledged -> "TimeWait"
                  [] phase = "FinWait1" -> "Closing"
                  [] OTHER -> "TimeWait"
    /\ UNCHANGED <<listener, tuple, origin, requested>>

Close ==
    /\ phase' = CASE phase \in {"Listen", "SynSent"} -> "Closed"
                  [] phase \in {"SynReceived", "Established"} -> "FinWait1"
                  [] phase = "CloseWait" -> "LastAck"
                  [] OTHER -> phase
    /\ tuple' = IF phase = "SynSent" THEN Absent ELSE tuple
    /\ UNCHANGED <<listener, origin, requested>>

\* Abort and a connection timeout both retain the tuple for reset dispatch.
Abort == /\ phase' = "Closed"
         /\ UNCHANGED <<listener, tuple, origin, requested>>

DispatchReset ==
    /\ phase = "Closed"
    /\ tuple # Absent
    /\ tuple' = Absent
    /\ UNCHANGED <<phase, listener, origin, requested>>

\* The TIME-WAIT close timer calls forget_connection.
Expire ==
    /\ phase = "TimeWait"
    /\ phase' = "Closed"
    /\ listener' = Absent
    /\ tuple' = Absent
    /\ UNCHANGED <<origin, requested>>

Next == (\E endpoint \in Listeners : Listen(endpoint))
        \/ (\E endpoints \in Tuples : Connect(endpoints) \/ PassiveSyn(endpoints))
        \/ (\E ack \in BOOLEAN : ActiveSyn(ack)
                                 \/ ReceiveAck(ack) \/ ReceiveFin(ack))
        \/ ReceiveReset \/ Close \/ Abort \/ DispatchReset \/ Expire

Spec == Init /\ [][Next]_vars

TypeOK == /\ phase \in Phases
          /\ listener \in Listeners \cup {Absent}
          /\ tuple \in Tuples \cup {Absent}
          /\ origin \in {"none", "active", "passive"}
          /\ requested \in Listeners \cup Tuples \cup {Absent}

ListenerProvenance ==
    /\ (phase = "Listen" => /\ origin = "passive"
                              /\ listener = requested
                              /\ listener # Absent
                              /\ tuple = Absent)
    /\ (origin = "active" => listener = Absent)
    /\ (phase = "SynSent" => origin = "active")

ConnectionIdentity ==
    /\ (phase \notin {"Closed", "Listen"} => tuple # Absent)
    /\ (tuple # Absent /\ origin = "active" => tuple = requested)
    /\ (tuple # Absent /\ origin = "passive" => Matches(requested, tuple.local))

\* This contract uses call history, independently of the stored Option.
Admission ==
    \A packet \in Tuples, control \in {"Syn", "Ack", "Fin", "Rst"}, ack \in BOOLEAN :
        Accepts(packet, control, ack) =
            CASE phase = "Closed" -> FALSE
              [] phase = "Listen" -> /\ ~ack
                                       /\ control # "Rst"
                                       /\ Matches(requested, packet.local)
              [] OTHER -> packet = tuple

PassiveResetRestores ==
    [][(ReceiveReset /\ phase = "SynReceived" /\ origin = "passive") =>
        /\ phase' = "Listen"
        /\ listener' = requested
        /\ tuple' = Absent]_vars

ActiveResetCloses ==
    [][(ReceiveReset /\ origin = "active") =>
        /\ phase' = "Closed"
        /\ tuple' = Absent
        /\ listener' = Absent]_vars
=============================================================================
