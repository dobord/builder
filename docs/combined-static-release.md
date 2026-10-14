# Combined static SDK release

`release-combined-request.yml` in the private registry signs Linux and Windows
platform-scoped requests from the same immutable tag. They share one release ID,
salt, source revision, package graph, requester identity and approved builder.
Acquisition recipes remain explicit per platform, permitting the independently
qualified Linux and Windows engine profiles without silently changing either.

`build-combined-release.yml` independently authenticates/prepares both inputs and
builds both native SDKs. Each platform retains its existing installed/relocated
consumer, archive audit and runtime gates. Only encrypted artifacts leave jobs.
The combined producer succeeds only when BOTH platform jobs produce fully
qualified SDKs. One publication job checks both scoped signatures and exact shared
identity/graph, then uploads two SDK ZIPs and one manifest/checksum pair atomically.

The v0.3.0 request uses the current lfc-ui 0.5.0 and OpenSSL 4.0.3 registry inputs.
The exact successful v0.2.5 Linux engine/package cache and Windows package cache
retain their original authenticated contexts. Windows CEF uses its exact READY
V27 source checkpoint. vcpkg still computes current package ABIs; changed packages
must rebuild. Cache restoration itself is never SDK readiness or publication.
