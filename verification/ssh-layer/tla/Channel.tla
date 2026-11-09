---------------------------- MODULE Channel ----------------------------
\* Source: src/stdlib/services/ssh.rs:649-692 (Channel and its two
\* debits), :1085-1202 (open, adjust, data, EOF and peer close),
\* :1347-1399 (confirmation, advertisement and credit), :1561-1569
\* (receive credit from Children), :1570-1584 and :1625-1632 (close),
\* :1617-1624 (local EOF), :1737-1773 (channel_write);
\* src/stdlib/layer/children.rs:858-922 (receive backing reserved at
\* 874-887 before the factory runs at 888; credit granted at 813-818),
\* :923-939 (terminal reset: remove at 535-544 unlinks the child's
\* timers and work, 928 cancels its owner).
\* Units are bytes. window, advertised and max_packet are u32; granted
\* and receive are u64; the model's windows of two and three bytes stand
\* for any value. A grant is window.min(max_packet) (:1394); the model
\* has no max_packet, so a grant is the whole window, which is the
\* code's when the window is the smaller. Adjust is checked_add (:1141-
\* 1144) and Credit is checked_add capped at u32::MAX (:1563-1567); both
\* fail the connection on overflow, which the model's bounds never reach.
\* Both debits check every bound before subtracting (:664-691); that
\* arithmetic is proved for all values in ../kani/mod.rs.
EXTENDS Naturals
CONSTANT Mutation
VARIABLES phase, reserved, accepted, confirmed, receive, advertised, held,
          sendWindow, granted, sent, peerGrant, eofIn, eofOut, eofCount,
          child, timer, work, deliveries, badDelivery
vars == <<phase, reserved, accepted, confirmed, receive, advertised, held,
          sendWindow, granted, sent, peerGrant, eofIn, eofOut, eofCount,
          child, timer, work, deliveries, badDelivery>>
\* ssh.rs Channel, input, progress, on_command, channel_write.
\* Children reserves receive backing before granting credit; its terminal
\* reset removes the child, cancels the owner and drops timers and queued work.
Init == /\ phase = "opening" /\ reserved = FALSE /\ accepted = FALSE
        /\ confirmed = FALSE /\ receive = 0 /\ advertised = 0 /\ held = 0
        /\ sendWindow = 2 /\ granted = 0 /\ sent = 0 /\ peerGrant = 2
        /\ eofIn = FALSE /\ eofOut = FALSE /\ eofCount = 0
        /\ child = TRUE /\ timer = TRUE /\ work = TRUE
        /\ deliveries = 0 /\ badDelivery = FALSE
Reserve == /\ phase = "opening" /\ ~reserved
           /\ reserved' = TRUE /\ receive' = 2
           /\ UNCHANGED <<phase, accepted, confirmed, advertised, held, sendWindow, granted,
                sent, peerGrant, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
Accept == /\ phase = "opening" /\ ~accepted /\ accepted' = TRUE
          /\ UNCHANGED <<phase, reserved, confirmed, receive, advertised, held, sendWindow, granted,
                sent, peerGrant, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
Confirm == /\ phase = "opening" /\ accepted
           /\ (reserved \/ Mutation = "reserve")
           /\ phase' = "open" /\ confirmed' = TRUE /\ advertised' = receive
           /\ UNCHANGED <<reserved, accepted, receive, held, sendWindow, granted, sent,
                peerGrant, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
Input == /\ phase = "open" /\ deliveries < 3
         /\ (~eofIn \/ Mutation = "inputeof")
         /\ (advertised > 0 \/ Mutation = "receive")
         /\ receive' = receive - 1 /\ advertised' = advertised - 1 /\ held' = held + 1
         /\ deliveries' = deliveries + 1 /\ badDelivery' = (badDelivery \/ eofIn)
         /\ UNCHANGED <<phase, reserved, accepted, confirmed, sendWindow, granted, sent,
                peerGrant, eofIn, eofOut, eofCount, child, timer, work>>
Release == /\ phase = "open" /\ held > 0
           /\ receive' = receive + 1 /\ held' = held - 1
           /\ UNCHANGED <<phase, reserved, accepted, confirmed, advertised, sendWindow, granted,
                sent, peerGrant, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
Advertise == /\ phase = "open" /\ receive > advertised
             /\ advertised' = receive + IF Mutation = "advertise" THEN 1 ELSE 0
             /\ UNCHANGED <<phase, reserved, accepted, confirmed, receive, held, sendWindow, granted,
                sent, peerGrant, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
Grant == /\ phase = "open" /\ granted = 0 /\ sendWindow > 0 /\ ~eofOut
         /\ granted' = sendWindow
         /\ UNCHANGED <<phase, reserved, accepted, confirmed, receive, advertised, held, sendWindow,
                sent, peerGrant, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
Send == /\ phase = "open" /\ sent < 3
        /\ (~eofOut \/ Mutation = "outputeof")
        /\ ((granted > 0 /\ sendWindow > 0) \/ Mutation = "send")
        /\ granted' = granted - 1 /\ sendWindow' = sendWindow - 1 /\ sent' = sent + 1
        /\ badDelivery' = (badDelivery \/ eofOut)
        /\ UNCHANGED <<phase, reserved, accepted, confirmed, receive, advertised, held, peerGrant,
                eofIn, eofOut, eofCount, child, timer, work, deliveries>>
Adjust == /\ phase = "open" /\ peerGrant < 3
          /\ peerGrant' = peerGrant + 1 /\ sendWindow' = sendWindow + 1
          /\ UNCHANGED <<phase, reserved, accepted, confirmed, receive, advertised, held, granted,
                sent, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
PeerEof == /\ phase = "open" /\ ~eofIn /\ eofIn' = TRUE
           /\ UNCHANGED <<phase, reserved, accepted, confirmed, receive, advertised, held, sendWindow,
                granted, sent, peerGrant, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
LocalEof == /\ phase = "open" /\ eofCount < 2
            /\ (~eofOut \/ Mutation = "eofonce") /\ eofOut' = TRUE /\ eofCount' = eofCount + 1
            /\ UNCHANGED <<phase, reserved, accepted, confirmed, receive, advertised, held, sendWindow,
                granted, sent, peerGrant, eofIn, child, timer, work, deliveries, badDelivery>>
Close == /\ phase \in {"opening", "open"} /\ phase' = "closing"
         /\ child' = (Mutation = "retire")
         /\ timer' = (Mutation = "timer") /\ work' = (Mutation = "work")
         /\ UNCHANGED <<reserved, accepted, confirmed, receive, advertised, held, sendWindow,
                granted, sent, peerGrant, eofIn, eofOut, eofCount, deliveries, badDelivery>>
Ack == /\ phase = "closing" /\ phase' = "closed"
       /\ UNCHANGED <<reserved, accepted, confirmed, receive, advertised, held, sendWindow, granted,
                sent, peerGrant, eofIn, eofOut, eofCount, child, timer, work, deliveries, badDelivery>>
Next == Reserve \/ Accept \/ Confirm \/ Input \/ Release \/ Advertise \/ Grant \/ Send
        \/ Adjust \/ PeerEof \/ LocalEof \/ Close \/ Ack
ReservedBeforeConfirmation == confirmed => reserved /\ accepted
ReceiveWindow == receive >= 0 /\ advertised >= 0 /\ held >= 0 /\ receive + held <= 2
AdvertisedCapacity == advertised <= receive
SendWindow == sendWindow >= 0 /\ granted >= 0 /\ granted <= sendWindow /\ sent + sendWindow = peerGrant
DirectionalEof == ~badDelivery
EofOnce == eofCount <= 1
Retired == phase \in {"closing", "closed"} => ~child
NoTimer == phase \in {"closing", "closed"} => ~timer
NoWork == phase \in {"closing", "closed"} => ~work
=============================================================================
