# Security

Please report security problems privately, by email to hi@amlalabs.com. Do not open
a public issue for them.

Say what you found, how to reproduce it, and which version or commit you used. We
will reply to confirm we got your report, and tell you what we plan to do.

## What counts

Fictionet treats whoever sends packets into a world as untrusted: the agent in a
sandbox, and, when a world routes the internet in through `Net::route` (as the
MPTCP honeypot in `demos/honeypot` does), anyone on the internet. World code is
trusted: it runs with the host's network and can do anything a program can. So
the reports we most want are ways for an agent inside a sandbox to:

* reach a network other than the world, such as the host's or the internet;
* reach the world's socket, files or processes;
* crash or stall a world, or `fictionet attach`, with the packets it sends;
* affect another sandbox attached to the same world.

And ways for anyone on the internet, sending to a world through a route, to:

* crash or stall the world, or make it hold memory or other state without
  bound, with any packets, spoofed sources included;
* send packets in the name of a sandbox or host inside the world;
* open connections in the name of an address that never sent the packets,
  such as by predicting sequence numbers or forging SYN cookies, or have the
  honeypot log a connection's segments in such a name (its `syn` and `burst`
  lines name the source a SYN claims, which may be spoofed);
* keep a packet out of the honeypot's log while the world still takes it, or
  stop the world through its log or packet capture.

A route keeps nothing per source address and drops packets whose source the
world has elsewhere, or that no router forwards (loopback, multicast or
broadcast). Its TCP gives each connection an initial sequence number
from a keyed hash (RFC 6528), answers SYNs past the backlog with SYN cookies
keyed apart from that, and forgets handshakes and closing connections on
fixed timers, as Linux does.
