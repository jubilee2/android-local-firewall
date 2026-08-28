# Forwarding architecture decisions

## ADR-001: Embed a maintained userspace network stack

**Status:** selected for a future implementation (prototype boundary only)
**Research reviewed:** 2026-08-28

### Context and constraints

A TUN file descriptor supplies IP packets, not socket byte streams. In particular, a TCP packet cannot be written to a Java `Socket`: TCP connection state, sequencing, acknowledgements, retransmission, congestion/flow control, and teardown must be implemented by a network stack. The firewall must remain entirely on-device, handle TCP and UDP, and must not depend on a remote VPN or proxy server. We will not create a new TCP/IP stack.

No default IPv4 or IPv6 route is added by this decision. Capturing all traffic is deferred until an ALLOW path is implemented, protected against VPN recursion, and tested end-to-end.

### Decision

Use **gVisor netstack**, consumed through a small, pinned Apache-2.0-licensed Go/JNI adapter, as the userspace TCP/IP stack. Treat the maintained [Outline SDK tun2socks implementation](https://github.com/Jigsaw-Code/outline-sdk/tree/main/x/tun2socks) as the primary integration reference and upstream packaging candidate. The adapter will put the TUN file descriptor into netstack, accept local TCP and UDP flows, and relay allowed flows to ordinary OS sockets connected directly to the original destination. It will not configure or contact a SOCKS server: “tun2socks” describes the reusable TUN-to-stream/datagram machinery, not this application's deployment topology.

Before implementation, a spike must pin an exact Outline SDK/gVisor revision and prove Android API 29–35 builds for every shipped ABI, TCP and UDP forwarding, FD protection before connect/send, shutdown, and IPv4. If the reusable Outline boundary cannot support a direct protected dialer without copying substantial code, build the thin adapter against [gVisor's `pkg/tcpip` netstack](https://github.com/google/gvisor/tree/master/pkg/tcpip) instead. This is one selected architecture (embedded gVisor netstack), with two packaging options—not a fallback to a custom stack.

The Kotlin boundary is `PacketForwarder`. Its implementation will own the TUN duplicate/JNI handle, native stack, flow tables, protected outbound sockets, and worker threads. `PacketForwarderLifecycle` makes start/stop idempotent and cleans up a partially started implementation. This issue intentionally supplies no native binary and does not connect the boundary to `FirewallVpnService` yet.

### Planned forwarding path

```text
TUN packet
  -> gVisor IP/TCP/UDP processing and flow creation
  -> flow metadata + Android UID resolution
  -> RuleEngine decision
       BLOCK -> reject/drop inside the local stack; create no Internet socket
       ALLOW -> create OS TCP/UDP socket -> VpnService.protect(fd) -> connect/send
  -> relay response through gVisor -> TUN
```

#### Firewall and UID hook

The hook is at **new-flow admission, before the host socket is created or receives payload**. The adapter reports the original IP version, protocol, source/destination address, and ports to Kotlin. Kotlin resolves the UID with Android's `ConnectivityManager.getConnectionOwnerUid()` mechanism already wrapped by `ConnectionOwnerResolver`, caches the decision by flow key, and invokes `RuleEngine`. Non-initial fragments remain governed by the existing fragment decision cache. A missing/ambiguous UID is not silently treated as allowed; the eventual policy must explicitly handle `UID_UNKNOWN`.

This placement avoids opening a real connection for a blocked flow. Rules are evaluated once when a flow is admitted and the immutable result belongs to that flow; a later ruleset change applies to new flows unless product requirements explicitly require terminating existing flows.

#### TCP strategy

Netstack terminates the app-side TCP connection and supplies the TCP state machine. For an allowed flow, the adapter creates a host TCP socket for the original destination, protects it, connects it, then performs bounded, back-pressured bidirectional copying between the netstack endpoint and host socket. Netstack, rather than Kotlin code, handles sequence numbers, ACKs, retransmission, windows, and IPv4 fragmentation/reassembly behavior. A blocked TCP SYN is initially dropped (timeout semantics); an explicit reset can be considered later if it cannot leak policy details or introduce malformed responses.

#### UDP strategy

Netstack supplies UDP endpoints and IP handling. Allowed datagrams are relayed through protected host UDP sockets, keyed by flow, with bounded queues and idle expiry. Responses are returned only to the matching netstack endpoint. Blocked datagrams are discarded and create no host socket. Queue, flow-count, and datagram-size limits are mandatory to bound memory; DNS receives no special remote handling.

#### Loop prevention

Every Internet-facing socket must be created through one native dial/socket factory. Immediately after socket creation—and **before** `connect()`, `sendto()`, or exposure to a worker—the native adapter calls a synchronous Kotlin callback that invokes `VpnService.protect(fd)`. A false return or callback/JNI error closes the descriptor and fails the flow closed. The adapter must not offer an unprotected socket constructor. TUN and local control descriptors are not Internet-facing sockets.

Protecting sockets is loop prevention, not firewall bypass: only an ALLOW decision may reach the protected-socket factory. `Builder.allowBypass()` and `addDisallowedApplication()` are not used.

### Alternatives considered

| Approach | Android / protocols / IP | Maintenance, license, and integration | Size, battery, performance, and security | Decision |
|---|---|---|---|---|
| **Embedded gVisor netstack; Outline SDK integration patterns** | Android requires Go mobile/JNI packaging. Mature TCP and UDP; IPv4 and IPv6 exist upstream. Direct dial and a socket-protection callback can be placed after admission. UID remains an Android-side pre-forwarding lookup. | [gVisor](https://github.com/google/gvisor) and [Outline SDK](https://github.com/Jigsaw-Code/outline-sdk) are actively developed Google/Jigsaw projects. Both are Apache-2.0. Pin revisions and retain notices. Native ABI artifacts and JNI are required. | Larger than a small C relay because a Go runtime and netstack are packaged (measure per ABI during spike). One userspace stack plus relays costs CPU/battery, but event-driven bounded I/O avoids per-packet JNI and is likely preferable to a Kotlin packet loop. gVisor publishes [security advisories](https://github.com/google/gvisor/security/advisories); embedding netstack does not provide the full gVisor sandbox, so upstream fixes still require prompt updates. | **Selected.** Best combination of compatible licensing, maintained TCP/IP behavior, both transports, IPv6 path, and a clean pre-dial policy/protection hook without inventing TCP. |
| **NetGuard native engine** | Proven Android `VpnService`, TCP/UDP, IPv4/IPv6, UID-aware policy, and protected sockets; requires C/JNI. | [NetGuard](https://github.com/M66B/NetGuard) is an important architectural reference. Its repository is GPL-3.0, which is not compatible with distributing copied/linked code under this project's intended permissive boundary without relicensing the combined work. | Mature and optimized for this exact class of application; compact native code, but audit/update burden and native memory-safety risk remain. Its issue tracker/history are useful references, not evidence that code may be copied. | Reference only; do not copy or link GPL code. |
| **hev-socks5-tunnel / lwIP-based tun2socks** | Supports Android, TCP/UDP and IPv4/IPv6 with a mature lwIP TCP/IP stack; C/JNI and a SOCKS5 proxy endpoint are normally required. FD protection can be integrated in the socket hook. | [hev-socks5-tunnel](https://github.com/heiher/hev-socks5-tunnel) is actively maintained and MIT licensed; lwIP is BSD-style. Its standard architecture forwards to SOCKS5. Running a second local SOCKS component solely to reach direct destinations adds another lifecycle and policy boundary. | Typically smaller than Go and designed for high-performance event-driven I/O. Native C/lwIP expands memory-safety and patch-monitoring responsibilities; two local forwarding layers add copies/wakeups and battery cost. | Viable fallback subject to a new ADR, but unnecessary local SOCKS layering makes firewall admission and failure behavior less direct. |
| **Java/Kotlin NIO plus a custom TCP implementation** | UDP is straightforward, but TCP requires a complete stateful stack; IPv6 doubles protocol scope. UID lookup and `protect()` would be easy at Java socket creation. | No third-party licensing/JNI, but the application would own a security-sensitive TCP/IP implementation indefinitely. | Potentially small binary, but high correctness, performance, battery, and security risk. | Rejected: explicitly out of scope and unsafe. Raw TUN TCP is not socket data. |
| **Root/kernel NAT, remote VPN, or per-app VPN bypass** | Root is unavailable; a remote server violates the local-only requirement. Disallowed apps bypass policy rather than being blocked. | Not applicable. | Either changes the trust/privacy model or allows traffic outside enforcement. | Rejected. |

No candidate's binary size or battery cost is stated as a guaranteed number: build flags, ABIs, traffic mix, radio state, and device dominate. The implementation spike must record AAB/APK size deltas and benchmark idle, sustained TCP, bursty UDP, throughput, CPU, wakeups, and memory against an established baseline.

### Licensing implications

The planned adapter and pinned dependencies must remain Apache-2.0 compatible. Release artifacts must include upstream copyright, license, and NOTICE material; Gradle/Go lock metadata must identify exact revisions and an automated dependency/license inventory should be added with the native integration. GPL/AGPL code, including NetGuard implementation code, must not be copied, translated, linked, or used to derive code structure. Reading public projects to understand architecture and Android edge cases is permitted. MIT/BSD alternatives remain legally plausible but are not dependencies selected by this ADR.

### Failure behavior

The forwarding implementation fails closed:

- `start()` succeeds only after JNI loads, the stack owns a valid TUN duplicate, callbacks are installed, and workers are ready. Partial initialization closes every native endpoint, socket, descriptor duplicate, and worker before propagating failure.
- No default route is installed before successful readiness. When route installation is eventually added, any forwarder death tears the VPN down rather than leaving captured traffic on an unserviced interface or bypassing policy.
- Parse errors, unsupported protocols, unknown fragments, UID-resolution failure under a UID-dependent policy, resource-limit exhaustion, failed `protect()`, and native dial failures never fall back to an unprotected or direct allow path.
- Per-flow errors close only that flow where isolation is safe; corruption, callback loss, TUN failure, or worker failure is fatal to the forwarder and VPN session.

### Shutdown behavior

`stop()` is idempotent. It first refuses new flows, cancels/joins workers, closes host sockets and netstack endpoints, clears decisions and UID/fragment flow caches, closes native TUN duplicates/JNI references, and only then returns. Shutdown is bounded; a forced native close must unblock reads. The service closes its `ParcelFileDescriptor` after the forwarder stops. A stop error is contained while ownership is cleared so a later start receives a fresh instance. Android service destruction and start-failure cleanup use this same path.

### Acceptance gates before adding a default route

1. Pinned source/dependency license review and reproducible Android builds for all supported ABIs.
2. Instrumented IPv4 TCP and UDP forwarding to direct destinations with no proxy/server.
3. Verified `protect(fd)` ordering and fail-closed behavior for every outbound socket.
4. BLOCK tests proving no outbound socket is opened; ALLOW tests proving return traffic.
5. UID attribution tests for TCP/UDP and defined unknown-UID behavior.
6. Startup failure, native crash/death notification, repeated lifecycle, interface revocation, and bounded shutdown tests.
7. IPv6 design retained, but no `::/0` route until equivalent IPv6 forwarding tests pass.
8. Size, memory, throughput, and battery measurements documented.
