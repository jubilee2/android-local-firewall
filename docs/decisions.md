# Forwarding architecture decisions

## ADR-001: Use Outline SDK’s lwIP transport bridge

**Status:** accepted for prototyping; dependency adoption still requires an Android integration spike
**Research reviewed:** 2026-08-28

### Context and constraints

A TUN file descriptor supplies IP packets, not socket byte streams. In particular, a TCP packet cannot be written to a Java `Socket`: TCP connection state, sequencing, acknowledgements, retransmission, congestion/flow control, and teardown require a network stack. The firewall must remain entirely on-device, handle TCP and UDP, and must not depend on a remote VPN, backend, proxy, or SOCKS server. We will not create a TCP/IP stack.

No default IPv4 or IPv6 route is added by this decision. Capturing all traffic is deferred until a working ALLOW path is protected against VPN recursion and tested end-to-end.

### Decision

Use the maintained [Outline SDK](https://github.com/OutlineFoundation/outline-sdk) `network/lwip2transport` bridge, which embeds the mature lwIP userspace TCP/IP stack, behind the Kotlin `PacketForwarder` boundary. Write a small project-owned Go/JNI adapter that supplies direct (not SOCKS) TCP and UDP transports to the packets’ original destinations. The adapter must expose synchronous flow-admission and socket-protection callbacks before any outbound connection or datagram.

This selection is architectural, not approval to add an unverified binary. Before importing the dependency or adding a default route, a focused Android spike must prove the acceptance gates below against a pinned revision. If the current API cannot provide direct original-destination TCP **and** UDP forwarding or cannot guarantee pre-I/O socket protection, this ADR must be superseded rather than weakened with a remote/local proxy or an unprotected path.

The eventual implementation will own the TUN duplicate/JNI handle, lwIP instance, flow table, protected outbound sockets, and workers. `PacketForwarderLifecycle` establishes lifecycle and cleanup semantics only; it is intentionally not connected to `FirewallVpnService` yet. No native dependency, binary, capture route, backend, remote VPN, or SOCKS server is added by this decision.

### Required forwarding path

```text
TUN packet
  -> Outline SDK lwIP userspace IP/TCP/UDP bridge
  -> new-flow metadata + Android UID resolution
  -> RuleEngine decision
       BLOCK -> reject/drop; create no Internet socket
       ALLOW -> create OS TCP/UDP socket -> VpnService.protect(fd) -> connect/send
  -> relay response through userspace stack -> TUN
```

#### Firewall and UID hook

The hook is at **new-flow admission, before the host socket is connected or receives payload**. The adapter reports the original IP version, protocol, source/destination address, and ports to Kotlin. Kotlin resolves the UID using the existing `ConnectionOwnerResolver`, caches the decision by flow key, and invokes `RuleEngine`. Non-initial fragments remain governed by the fragment decision cache. An unavailable or ambiguous UID must follow an explicit fail-closed policy rather than silently becoming allowed.

This placement prevents a blocked flow from opening a real connection. A decision belongs to its flow; later rule changes apply to new flows unless a future requirement explicitly terminates existing flows.

#### TCP strategy

lwIP terminates the app-side TCP connection and handles sequence numbers, ACKs, retransmission, congestion, windows, and teardown. After an ALLOW decision, the adapter creates a host TCP socket for the original destination, protects it, connects it, and performs bounded, back-pressured bidirectional relay. A blocked TCP flow creates no outbound socket.

#### UDP strategy

lwIP supplies UDP endpoints and IP handling. Allowed datagrams use protected host UDP sockets keyed by flow, bounded queues, and idle expiry; responses return only to the matching stack endpoint. Blocked datagrams are discarded without creating a host socket. Flow-count, queue, and datagram-size limits are mandatory. DNS receives no remote or special bypass path.

#### Loop prevention

Every Internet-facing socket must come from one adapter socket factory. Immediately after socket creation—and **before** `connect()`, `sendto()`, or exposure to a worker—the adapter synchronously calls Kotlin, which invokes `VpnService.protect(fd)`. A false return, thrown error, JNI error, or lost callback closes the descriptor and fails the flow closed. The adapter must expose no unprotected outbound-socket path.

Protection prevents routing loops; it is not policy bypass. Only an ALLOW decision may reach the socket factory. `Builder.allowBypass()` and `addDisallowedApplication()` are not used.

### Alternatives and comparison

| Approach | Android, protocols, and IP | Maintenance, licensing, and integration | Size, battery, performance, and security | Status |
|---|---|---|---|---|
| **Direct gVisor `pkg/tcpip`** | Mature TCP/UDP and IPv4/IPv6, but requires a larger project-owned Go adapter for TUN endpoints, flow admission, direct dialing, UID hooks, and protection. | Actively maintained and Apache-2.0; Go/JNI packaging is required. | Memory-safe Go reduces C memory hazards, but the runtime/netstack can increase per-ABI size. Android packaging and mobile API stability require proof. Embedding netstack does not provide the full gVisor sandbox. | Not selected: more integration surface than the purpose-built Outline bridge. Retain as fallback if the spike invalidates the selection. |
| **Outline `network/lwip2transport` / PacketRelay** | Purpose-built TUN-to-transport bridge using lwIP, with TCP/UDP support and an IPv4/IPv6-capable underlying stack. Android API 29+, direct original-destination behavior, IPv6 integration, protection hooks, and ABI packaging still require proof. | Actively maintained. Go/JNI plus native lwIP artifacts are expected; pin and audit the complete license/NOTICE graph. | lwIP is compact and established. Native C adds memory-safety and patch-monitoring obligations; relay copies, wakeups, throughput, and idle cost need device measurements. | **Selected**, contingent on every acceptance gate. |
| **NetGuard native engine** | Proven Android VPN, TCP/UDP, IPv4/IPv6, UID-aware policy, protected sockets; requires C/JNI. | [NetGuard](https://github.com/M66B/NetGuard) is GPL-3.0 and is an architectural reference only. Copying/linking it would impose incompatible distribution obligations for the intended project licensing. | Mature and optimized for this problem, but carries native audit and update obligations. | Reference only; do not copy or link. |
| **hev-socks5-tunnel / lwIP tun2socks** | Android, TCP/UDP, and IPv4/IPv6; C/JNI. Its normal topology requires SOCKS5, while this firewall requires direct destinations. | [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) is maintained under MIT and uses BSD-style lwIP. | Potentially compact and event driven, but an extra local SOCKS layer adds lifecycle, copies, wakeups, and another policy boundary. | Rejected for this design because SOCKS is unnecessary and must not become a requirement. |
| **Java/Kotlin NIO plus custom TCP** | UDP is feasible; TCP and future IPv6 would create a new stack. | No dependency license/JNI, but the project would own security-critical protocol code. | High correctness, performance, battery, and security risk. | Rejected and out of scope. |
| **Root/kernel NAT, remote VPN, backend, or per-app bypass** | Root is unavailable; remote infrastructure violates local-only requirements; disallowed apps bypass enforcement. | Not applicable. | Changes the privacy model or permits traffic outside policy. | Rejected. |

Binary size and battery statements are qualitative until measured. The spike must record per-ABI APK/AAB deltas, memory, idle CPU/wakeups, sustained TCP throughput, and bursty UDP behavior on representative devices.

### Licensing implications

Outline SDK is published under Apache-2.0; lwIP uses a permissive BSD-style license, and the currently referenced `go-tun2socks` component is permissively licensed. Before dependency adoption, the spike must inventory and pin the exact SDK revision and every transitive native/Go dependency, verify each actual license from that revision, confirm distribution compatibility, and preserve required copyright, license, and NOTICE files. GPL/AGPL implementation code, including NetGuard code, must not be copied, translated, linked, or used to derive source structure. No third-party code or binary is added in this scaffold.

### Failure behavior

The forwarder fails closed:

- `start()` succeeds only after native linkage, stack/TUN ownership, callbacks, and workers are ready. Any exception, linkage error, or other failure cleans every partially initialized endpoint, socket, descriptor duplicate, JNI reference, and worker before propagating.
- No default route is installed before readiness. Once routes exist in a future change, forwarder death tears down the VPN instead of bypassing policy or leaving an unserviced capture route.
- Parse errors, unsupported protocols, fragments without decisions, UID-resolution failures, exhausted limits, failed `protect()`, and dial failures never fall back to an unprotected/direct allow path.
- Per-flow errors close that flow when safe; stack corruption, callback loss, TUN failure, or worker failure is fatal to the forwarder and VPN session.

### Shutdown behavior

`stop()` is idempotent and bounded. It refuses new flows, cancels and joins workers, closes host sockets and stack endpoints, clears flow decisions and UID/fragment caches, releases native TUN duplicates and JNI references, and returns. Forced native close must unblock reads. The service closes its `ParcelFileDescriptor` only after the forwarder stops. Failed-start cleanup and Android service destruction use the same path. If stop fails, lifecycle ownership is retained and another forwarder cannot start; cleanup may be retried, and a fresh instance is permitted only after the previous forwarder is known to be quiescent.

### Spike and acceptance gates before adding a default route

The spike must prove, not infer, all of the following for each viable candidate:

1. Reproducible Android API 29+ build and packaging for every supported ABI.
2. TCP forwarding directly to the original destination without a remote proxy, VPN, backend, or SOCKS server.
3. UDP forwarding directly to the original destination under the same local-only constraint.
4. Every outbound TCP and UDP socket is protected before `connect()`/`sendto()`/send, with tests observing call order.
5. A false or failed `protect()` closes the socket and fails the flow closed.
6. BLOCK opens no outbound socket; ALLOW returns traffic through the TUN path.
7. UID attribution and explicit unknown-UID behavior work for TCP and UDP.
8. Startup/linkage failure cleanup, forwarder death, interface revocation, repeated lifecycle calls, and clean bounded shutdown are tested.
9. Exact revisions and compatible licenses/notices are pinned and supported ABI artifacts are reproducible.
10. IPv4 works first; no IPv6 default route is added until equivalent IPv6 forwarding and protection tests pass.
11. APK/AAB size, memory, throughput, CPU, wakeups, and battery observations are documented.
