---------------------------- MODULE Listener ----------------------------
EXTENDS Naturals, Sequences

(* Source map, with paths relative to src/stdlib.
   Install and FirstFactory: world/net/hosts.rs:1882,1943-1946 retain the
   first installed server while adding each site's entries.
   Accept and FactoryIsolation: world/net/hosts.rs:2137-2156 select the
   current port's first server; web/httpd/sites.rs:496-497 returns its factory.
   Select and CertificateIsolation: world/net/hosts.rs:1891-1895 stores each
   site's config; 2067-2093 resolves the requested name in the current port,
   falls back to the empty name, and awaits that entry's config.
   ProtocolIsolation: web/httpd/sites.rs:515-518 preserves the later site's
   application and protocols; world/net/hosts.rs:1891-1895 stores them and
   1556-1571 overlays the selected entry's ALPN on its config; 1558-1559
   preserves the provider's ALPN when the site's override list is empty.
   ConfigUnchanged: world/net/hosts.rs:1567-1570 clones before editing ALPN.
   Build, ApplicationAfterNegotiation and ApplicationOnce:
   services/tls/secure.rs:121-135 guards construction with Established and
   consumes make; services/tls/factory.rs:80-81 passes negotiated metadata.
   NegotiatedApplication: world/net/hosts.rs:2097-2129 uses the established
   name and ALPN; web/httpd/sites.rs:483-493 invokes the routed application.
   This is a bounded abstraction, not a mechanically checked refinement. *)

CONSTANTS KeepFirst, LocalFactory, LocalCertificate, LocalProtocols,
          CopyConfig, WaitEstablished, TakeFactory, UseNegotiated

Listeners == {1, 2}
Sites == {1, 2}
Names == {"named", "other", "absent"}
NoSite == 0
NoProtocol == <<0, 0, 0>>
Protocols(l, s) == {<<l, s, 1>>, <<l, s, 2>>}
Provided(l, s) == {<<l, s, 0>>}

(* Listener one has a fallback; listener two has two exact names.
   Identities stand for distinct closures, certificates and protocol bytes. *)
Route(l, n) == IF n = "named" THEN 1
               ELSE IF l = 1 \/ n = "other" THEN 2 ELSE NoSite

VARIABLES overrides, installed, first, history, phase, listener, requested,
          factory, certificate, advertised, original,
          negotiatedName, negotiatedProtocol, builds, builtState,
          application, applicationProtocol

vars == <<overrides, installed, first, history, phase, listener, requested,
          factory, certificate, advertised, original,
          negotiatedName, negotiatedProtocol, builds, builtState,
          application, applicationProtocol>>

Init ==
    /\ overrides \in [Listeners -> [Sites -> BOOLEAN]]
    /\ installed = [l \in Listeners |-> {}]
    /\ first = [l \in Listeners |-> NoSite]
    /\ history = [l \in Listeners |-> <<>>]
    /\ phase = "install"
    /\ listener = 1
    /\ requested = "absent"
    /\ factory = <<0, 0>>
    /\ certificate = <<0, 0>>
    /\ advertised = {}
    /\ original = [l \in Listeners |-> [s \in Sites |-> Provided(l, s)]]
    /\ negotiatedName = "absent"
    /\ negotiatedProtocol = NoProtocol
    /\ builds = 0
    /\ builtState = "unbuilt"
    /\ application = NoSite
    /\ applicationProtocol = NoProtocol

Install(l, s) ==
    /\ phase = "install"
    /\ s \notin installed[l]
    /\ installed' = [installed EXCEPT ![l] = @ \cup {s}]
    /\ history' = [history EXCEPT ![l] = Append(@, s)]
    /\ first' = [first EXCEPT ![l] =
          IF KeepFirst /\ @ # NoSite THEN @ ELSE s]
    /\ UNCHANGED <<overrides, phase, listener, requested, factory, certificate,
          advertised, original, negotiatedName, negotiatedProtocol,
          builds, builtState, application, applicationProtocol>>

Accept(l, n) ==
    /\ phase = "install"
    /\ \A p \in Listeners : installed[p] = Sites
    /\ phase' = "pending"
    /\ listener' = l
    /\ requested' = n
    /\ factory' = IF LocalFactory THEN <<l, first[l]>>
                  ELSE <<3 - l, first[3 - l]>>
    /\ UNCHANGED <<overrides, installed, first, history, certificate, advertised,
          original, negotiatedName, negotiatedProtocol, builds,
          builtState, application, applicationProtocol>>

Select ==
    /\ phase = "pending"
    /\ LET s == Route(listener, requested)
           certListener == IF LocalCertificate THEN listener ELSE 3 - listener
           protoSite == IF LocalProtocols THEN s ELSE 3 - s
       IN /\ phase' = IF s = NoSite THEN "failed" ELSE "selected"
          /\ certificate' = IF s = NoSite THEN <<0, 0>> ELSE <<certListener, s>>
          /\ advertised' = IF s = NoSite THEN {}
                           ELSE IF overrides[listener][protoSite]
                                THEN Protocols(listener, protoSite)
                                ELSE original[listener][protoSite]
          /\ original' = IF CopyConfig \/ s = NoSite THEN original
                          ELSE IF overrides[listener][protoSite]
                               THEN [original EXCEPT ![listener][s] = advertised']
                               ELSE original
    /\ UNCHANGED <<overrides, installed, first, history, listener, requested, factory,
          negotiatedName, negotiatedProtocol, builds, builtState,
          application, applicationProtocol>>

Establish(n, p) ==
    /\ phase = "selected"
    /\ p \in advertised \cup {NoProtocol}
    /\ phase' = "established"
    /\ negotiatedName' = n
    /\ negotiatedProtocol' = p
    /\ UNCHANGED <<overrides, installed, first, history, listener, requested, factory,
          certificate, advertised, original, builds, builtState,
          application, applicationProtocol>>

Fail ==
    /\ phase \in {"pending", "selected"}
    /\ phase' = "failed"
    /\ UNCHANGED <<overrides, installed, first, history, listener, requested, factory,
          certificate, advertised, original, negotiatedName,
          negotiatedProtocol, builds, builtState, application, applicationProtocol>>

Build ==
    /\ phase \in {"pending", "selected", "established", "failed"}
    /\ ~WaitEstablished \/ phase = "established"
    /\ IF TakeFactory THEN builds = 0 ELSE builds < 2
    /\ builds' = builds + 1
    /\ builtState' = phase
    /\ application' = Route(listener, IF UseNegotiated THEN negotiatedName ELSE requested)
    /\ applicationProtocol' = IF UseNegotiated THEN negotiatedProtocol ELSE NoProtocol
    /\ UNCHANGED <<overrides, installed, first, history, phase, listener, requested,
          factory, certificate, advertised, original, negotiatedName, negotiatedProtocol>>

Next == (\E l \in Listeners, s \in Sites : Install(l, s))
        \/ (\E l \in Listeners, n \in Names : Accept(l, n))
        \/ Select \/ Fail \/ Build
        \/ (\E n \in Names, p \in (UNION {Protocols(l, s) \cup Provided(l, s) : l \in Listeners, s \in Sites}) \cup {NoProtocol} : Establish(n, p))

Spec == Init /\ [][Next]_vars

FirstFactory == \A l \in Listeners :
    history[l] # <<>> => first[l] = Head(history[l])
FactoryIsolation == phase # "install" => factory = <<listener, Head(history[listener])>>
CertificateIsolation == certificate # <<0, 0>> => certificate = <<listener, Route(listener, requested)>>
ProtocolIsolation == advertised # {} =>
    LET s == Route(listener, requested)
    IN advertised = IF overrides[listener][s] THEN Protocols(listener, s)
                    ELSE Provided(listener, s)
ConfigUnchanged == original = [l \in Listeners |-> [s \in Sites |-> Provided(l, s)]]
ApplicationAfterNegotiation == builds > 0 => builtState = "established"
ApplicationOnce == builds <= 1
NegotiatedApplication == builds > 0 =>
    /\ application = Route(listener, negotiatedName)
    /\ applicationProtocol = negotiatedProtocol

=============================================================================
