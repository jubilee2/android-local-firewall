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

Early pre-release foundation (`0.1.0`, in development). **This application does not yet capture general device traffic or enforce allow/block packet forwarding.**

`FirewallVpnService` currently establishes a minimal `/32` TUN interface without default IPv4/IPv6 routes while userspace packet forwarding remains gated on ADR-001 acceptance checks (PR #30 is recorded as a failed Outline SDK `lwip2transport` integration spike and must be replaced by a verified upstream build before any default capture route is enabled).

### Implemented foundations

- Android Kotlin + Jetpack Compose shell with VPN permission flow, start/stop controls, and service status indicator
- Foreground `FirewallVpnService` lifecycle with minimal `/32` TUN interface management (no default route)
- Non-blocking `PacketProcessor` reading TUN packets and extracting IPv4, TCP, and UDP header metadata
- `ConnectionOwnerResolver` flow-level Android UID attribution with bounded LRU/TTL caching
- Pure, unit-tested `RuleEngine` and `FragmentDecisionEngine` for IPv4 address, IPv4 CIDR, protocol (TCP/UDP), and destination port rules
- `PacketForwarder` / `PacketForwarderLifecycle` boundary and ADR-001 forwarding design (not yet wired to a verified native stack or `FirewallVpnService`)
- GitHub Actions CI running JVM unit tests, Android Lint, and debug APK builds

### Planned / not yet implemented

- Enforced local TCP/UDP packet forwarding and blocking via a verified Outline SDK `lwip2transport` build and default VPN routes (PR #30 failed this gate)
- Per-application firewall rules (`uid` matching, installed-application listing, and app rule UI)
- Local rule and settings persistence with Room (`data/` layer and `FirewallRepository` not yet created)
- Local traffic log storage and Compose UI screen
- IPv6 packet parsing, rule matching, and forwarding (currently only `allowFamily(AF_INET6)` is set on the minimal TUN builder)
- Always-on VPN (`SUPPORTS_ALWAYS_ON` is currently `false`) and block-connections-without-VPN validation
- Android instrumentation, emulator, and physical-device end-to-end validation

## Target features

- Start / stop firewall (service lifecycle implemented; traffic capture/enforcement pending forwarding gate)
- Per-app allow/block (planned; UID lookup foundation only)
- IP allow/block (IPv4 rule evaluation foundation implemented; enforcement and Room UI pending)
- CIDR allow/block (IPv4 CIDR evaluation foundation implemented; enforcement and Room UI pending)
- TCP/UDP filtering (header parsing and rule evaluation foundation implemented; enforcement pending)
- Port filtering (destination port evaluation foundation implemented; enforcement pending)
- Local traffic log (planned)
- IPv4 support (header parsing and rule engine foundation implemented; forwarding pending)
- IPv6 support (planned)
- Always-on VPN support (planned)
- Block connections when VPN is unavailable (planned)

## Technology

- Kotlin
- Jetpack Compose
- Android VpnService
- Room (planned for local persistence)
- Gradle
- GitHub Actions

## Important constraints

- No root required
- No remote VPN server
- No backend service
- No user traffic leaves the device except normal allowed Internet traffic
- Do not implement custom encryption
- Do not implement a TCP/IP stack from scratch unless absolutely necessary
