# Outline forwarder Android spike

This directory is the project-owned JNI boundary for the Outline SDK
`network/lwip2transport` experiment. The upstream revision is immutably pinned
in `OUTLINE_REVISION`; changing it is an explicit dependency upgrade and must
repeat the capability, license, packaging, and size review in
[`docs/outline-lwip-integration-spike.md`](../../docs/outline-lwip-integration-spike.md).

The spike library exposes only a deterministic build probe. It does not accept
a TUN descriptor, open a socket, start a VPN, or forward traffic. Gradle builds
and packages it only for `arm64-v8a` and `x86_64`.

The production adapter must not grow here until it can enforce both admission
and Android `VpnService.protect(fd)` synchronously before any dial/send call.
