# Security

Please report security problems privately, by email to hi@amlalabs.com. Do not open
a public issue for them.

Say what you found, how to reproduce it, and which version or commit you used. We
will reply to confirm we got your report, and tell you what we plan to do.

## What counts

Fictionet treats the agent in the sandbox as the only untrusted party. World code
is trusted: it runs with the host's network and can do anything a program can. So
the reports we most want are ways for an agent inside a sandbox to:

* reach a network other than the world, such as the host's or the internet;
* reach the world's socket, files or processes;
* crash or stall a world, or `fictionet attach`, with the packets it sends;
* affect another sandbox attached to the same world.
