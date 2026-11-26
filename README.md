# Android Local Firewall

An Android local firewall application using Android VpnService.

## Goal

Create a privacy-focused Android firewall that runs completely on the device.

No external VPN server.
No backend server.
No cloud database.
No traffic upload.

The application uses Android VpnService to intercept device network traffic
and apply local firewall rules.

## Current status

Pre-release (`0.1.0`, active development). **IPv4 device traffic is captured (`0.0.0.0/0`) and enforced locally on-device** using the verified Outline SDK `network/lwip2transport` Go/JNI userspace stack (`OutlineFoundation/outline-sdk@ff3fcd3bf7571967a6e2fa324e93f242505f514a`).

Per ADR-001 Gate #10, `FirewallVpnService` currently installs the IPv4 default capture route (`0.0.0.0/0`) and intentionally omits `allowFamily(AF_INET6)` and IPv6 `::/0` routes so apps use enforced IPv4 rather than bypassing firewall policy over IPv6 while upstream `go-tun2socks@v1.16.11` binds its singleton UDP PCB to IPv4 only.

### Implemented features

- Jetpack Compose UI with four tabs (`Status`, `Apps`, `Rules`, `Logs`), VPN permission flow, and start/stop controls
- Foreground `FirewallVpnService` with `0.0.0.0/0` IPv4 capture route, `onRevoke()` handling, and `AndroidUnderlyingNetworkMonitor` (`setUnderlyingNetworks`)
- Reproducible Android NDK/Go JNI build (`native/outline-forwarder`, `arm64-v8a` & `x86_64`) against pinned `OutlineFoundation/outline-sdk` `network/lwip2transport` with BuildInfo pin verification
- Direct original-destination TCP and UDP forwarding with synchronous pre-stack 5-tuple admission, fail-closed Android UID resolution (`ConnectionOwnerResolver`), and pre-I/O `VpnService.protect(fd)` enforcement
- Per-application (`uid`) allow/block rules (`InstalledAppsProvider`, `AppFirewallRule`) and IPv4/IPv6 address, CIDR, TCP/UDP, and destination-port rules (`RuleEngine`, `FragmentDecisionEngine`)
- Room local persistence (`FirewallDatabase`, `FirewallRepository`) for app rules, network rules, settings, and bounded metadata-only traffic logs (zero packet payload storage)
- GitHub Actions CI running Go race tests, JVM unit tests, Android Lint, debug/instrumentation APK builds, native `.so` module verification, and KVM Android API 30 Emulator JNI + Room instrumentation tests

### Remaining roadmap items

- Always-on VPN (`SUPPORTS_ALWAYS_ON` and system-initiated `android.net.VpnService` start handling) and release workflow automation
- End-to-end IPv6 `::/0` capture route once dual-stack UDP PCB support replaces `go-tun2socks@v1.16.11`'s IPv4-bound singleton UDP PCB
- Physical-device battery, throughput, and block-connections-without-VPN validation

## Target features

- Start / stop firewall (implemented)
- Per-app allow/block (implemented)
- IP allow/block (implemented for IPv4 & IPv6 literals; IPv4 enforced on TUN route)
- CIDR allow/block (implemented for IPv4 & IPv6 CIDRs; IPv4 enforced on TUN route)
- TCP/UDP filtering (implemented)
- Port filtering (implemented)
- Local traffic log (implemented, metadata-only in Room)
- IPv4 support (implemented and enforced end-to-end)
- IPv6 support (parser, CIDR/rule engine, and UI implemented; `::/0` TUN route gated on upstream IPv6 UDP stack support)
- Always-on VPN support (next stage)
- Block connections when VPN is unavailable (validated alongside Always-on VPN)

## Technology

- Kotlin
- Jetpack Compose
- Android VpnService
- Outline SDK `network/lwip2transport` (Go/CGo JNI)
- Room
- Gradle Kotlin DSL
- GitHub Actions

## Important constraints

- No root required
- No remote VPN server
- No backend service
- No user traffic leaves the device except normal allowed Internet traffic
- Do not implement custom encryption
- Do not implement a TCP/IP stack from scratch unless absolutely necessary
