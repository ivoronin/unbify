unbify
======

This is a small wrapper (LD_PRELOAD) library designed to (transparently) enable existing
applications to use Unbound DNS Resolver, that does TCP requests, caching, DNSSEC validation
and can use different forwarders for different domains. It is extremely useful when using
SOCKS and HTTP proxies.

Build requirements
------------------

 - ldns (http://www.nlnetlabs.nl/projects/ldns/)
 - unbound (http://unbound.net/)

Limitations
-----------

 - IPv6 is not supported (yet)
