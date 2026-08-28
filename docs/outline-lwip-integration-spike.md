# Outline/lwIP Android integration spike

**Result:** packaging probe accepted; forwarding remains disabled.  
**Reviewed:** 2026-08-28  
**Outline SDK:** `OutlineFoundation/outline-sdk` commit
`6f5902f532d67ffde0c02f9ec19bb176d859f173`

## Reproducibility and scope

`native/outline-forwarder/OUTLINE_REVISION` is the single checked-in pin. The
JNI result embeds the same revision, so a stale binary fails the Kotlin probe.
The Android configuration has an explicit allow-list of `arm64-v8a` and
`x86_64`; no other ABI is supported or claimed. `externalNativeBuild` compiles
the adapter for both and the resulting APK contains
`lib/<abi>/liboutline_forwarder_probe.so`.

This is deliberately a load/build probe, not forwarding. It has no TUN API and
contains no dial, connect, send, socket, SOCKS, remote-VPN, telemetry, or
payload-logging code. It is not referenced by `FirewallVpnService`, and no VPN
route was added.

## Pinned API review

The review used the pinned source, specifically
`network/lwip2transport/lwip2transport.go`,
`network/lwip2transport/tcp.go`, `network/lwip2transport/udp.go`, and the
`transport` interfaces they consume.

| Gate | Pinned API evidence | Result |
|---|---|---|
| TCP | The lwIP TCP accept callback exposes the original local/remote endpoint and delegates each accepted flow to a supplied stream dialer. | Pass |
| UDP | The UDP receive callback exposes both endpoints and delegates datagrams to a supplied packet transport. | Pass |
| Original destination | TCP and UDP callbacks retain destination address and port rather than replacing them with a proxy endpoint. | Pass |
| Local direct forwarding | Dialer/packet-transport implementations are injected by the caller. The bridge has no mandatory remote VPN. | Pass |
| No required SOCKS | The component depends on transport interfaces, not a SOCKS client or server. A direct transport is permitted. | Pass |
| Pre-I/O admission | A project wrapper can decide from callback endpoint metadata before invoking the injected dialer/packet transport. | Pass, required for the later forwarding adapter |
| Pre-I/O protection | The injected transport owns socket creation. Its sole future socket factory can create the descriptor, synchronously invoke `protect(fd)`, fail closed, and only then dial/send. lwIP has no alternate host-socket path. | Pass, required for the later forwarding adapter |

These are API acceptance results, not claims that live forwarding has been
implemented. A future adapter must add order-observing tests for admission and
protection before any capture route is eligible to ship.

## License inventory

The pinned SDK root license is Apache License 2.0. Its embedded lwIP is under
lwIP's permissive BSD-style license. The reviewed Go graph used by
`lwip2transport` consists of the Go standard library (BSD-3-Clause), Go mobile
support packages (BSD-3-Clause), and Outline/go-tun2socks lwIP bindings
(BSD-3-Clause). No GPL or AGPL code is copied, translated, linked, or packaged;
NetGuard was not used as an implementation source.

This probe binary contains only project-owned JNI code and revision metadata;
it does not yet embed upstream object code. Before a forwarding binary is
introduced, CI must regenerate a dependency inventory from the pinned module
graph and package the applicable upstream `LICENSE`/`NOTICE` texts. The
attributions reviewed for this spike are preserved in
`native/outline-forwarder/THIRD_PARTY_NOTICES.md`.

## Binary impact

The baseline is commit `a3bf34a` (before this spike). Measure uncompressed ABI
cost from the same debug build, because APK compression can obscure the native
delta:

```bash
unzip -l app/build/outputs/apk/debug/app-debug.apk 'lib/*/liboutline_forwarder_probe.so'
stat --printf='%s bytes\n' app/build/outputs/apk/debug/app-debug.apk
```

| Artifact | Before | After / delta |
|---|---:|---:|
| `arm64-v8a` probe library | 0 bytes | recorded by CI artifact inspection |
| `x86_64` probe library | 0 bytes | recorded by CI artifact inspection |
| Debug APK | baseline commit artifact | current CI artifact |

The exact signed/compressed APK size depends on the build-tools version, so CI
records it alongside the APK rather than presenting a non-reproducible local
number. This spike is expected to add only the two probe libraries; forwarding
and its Go/lwIP binary impact must be measured separately before adoption.
