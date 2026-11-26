# Roadmap

> **Enforcement status:** Phases 1–7 and the ADR-001 IPv4 forwarding gate are implemented and enforced locally on-device via `FirewallVpnService` (`0.0.0.0/0` route + verified Outline SDK `network/lwip2transport` JNI bridge). IPv6 `::/0` capture remains gated on upstream `go-tun2socks` dual-stack UDP PCB support (while `AF_INET6` bypass is blocked on the VPN interface).

## Phase 1 - Project bootstrap

- [x] Create Android Kotlin project
- [x] Configure Gradle
- [x] Add Jetpack Compose
- [x] Add basic CI
- [x] Verify debug APK builds

## Phase 2 - VPN foundation

- [x] Add VpnService declaration
- [x] Request VPN permission
- [x] Start VPN
- [x] Stop VPN
- [x] Create TUN interface and install enforced IPv4 `0.0.0.0/0` capture route
- [x] Show firewall status

## Phase 3 - Packet processing

- [x] Read IPv4 and IPv6 packets (`IPv4PacketParser`, `IPv6PacketParser`, `PacketProcessor`, and Go pre-stack header inspector)
- [x] Parse IPv4 and IPv6 headers (including RFC 8200 extension and Fragment headers)
- [x] Parse TCP (`TcpPacketParser`)
- [x] Parse UDP (`UdpPacketParser`)
- [x] Unit tests for packet parsers

## Phase 4 - Firewall engine

- [x] Define firewall rule model (`FirewallRule`, `FirewallAction`)
- [x] Implement allow/block decision evaluation (`RuleEngine`, `FragmentDecisionEngine`, `PacketDecisionCoordinator` with `failClosedOnUnknownUid = true`)
- [x] IP rules (IPv4 and IPv6 destination matching)
- [x] CIDR rules (`IPv4Cidr` and `IPv6Cidr` matching)
- [x] Port rules (destination port matching)
- [x] TCP/UDP rules (`TransportProtocol` matching)
- [x] RuleEngine unit tests

## Forwarding & enforcement gate

- [x] Define `PacketForwarder` / `PacketForwarderLifecycle` boundary and ADR-001 architecture
- [x] Add `ConnectionOwnerResolver` flow UID attribution for TCP/UDP
- [x] Replace failed PR #30 spike with verified pinned upstream Android build (`OutlineFoundation/outline-sdk@ff3fcd3bf7571967a6e2fa324e93f242505f514a`)
- [x] Prove direct original-destination TCP/UDP forwarding, pre-I/O `VpnService.protect()`, fail-closed UID/protection handling, and bounded shutdown on Linux race tests and Android API 30 Emulator JNI tests
- [x] Wire `OutlinePacketForwarder` to `FirewallVpnService` and install IPv4 `0.0.0.0/0` capture route without `AF_INET6` bypass

## Phase 5 - App filtering

- [x] List installed applications (`InstalledAppsProvider`)
- [x] Create per-app rules (`AppFirewallRule`, UID matching in `RuleEngine`)
- [x] Store app rules in Room
- [x] Apply app rules to enforced flows (blocked apps take precedence before network rules)

## Phase 6 - Persistence

- [x] Add Room (`FirewallDatabase`, `FirewallLocalStore`, `FirewallRepository`)
- [x] Store firewall rules
- [x] Store settings
- [x] Store bounded metadata-only traffic logs (no packet payloads)

## Phase 7 - Traffic log

- [x] Traffic log screen (`Logs` tab in Compose UI)
- [x] Allow/block status
- [x] Application name and package name
- [x] Destination
- [x] Protocol
- [x] Port

## Phase 8 - Reliability

- [x] IPv6 packet parsing, CIDR/address rules, and UI validation (`::/0` TUN capture route gated on upstream dual-stack UDP PCB support)
- [x] VPN revocation and restart handling (`onRevoke()`, `FirewallVpnSessionOrchestrator`)
- [x] Network change handling (`UnderlyingNetworkTracker` and `AndroidUnderlyingNetworkMonitor`)
- [x] Always-on VPN support (`SUPPORTS_ALWAYS_ON = true` and system `android.net.VpnService` start handling)
- [x] Reproducible GitHub Actions release/deployment bundle workflow (`.github/workflows/release.yml`)
- [ ] Physical-device battery and throughput profiling

## Phase 9 - Testing

- [x] Unit tests for VPN session orchestration, Always-on command handling, packet parsers, UID resolver, rule engine, Room repository, and Compose state holder
- [x] Go `-race` integration tests for `lwip2transport` TCP/UDP forwarding, socket protection order, and fail-closed admission
- [x] Android instrumentation tests (Room database, Compose UI, and JNI `OutlineForwarderInstrumentedTest`)
- [x] Automated GitHub Actions Android API 30 Emulator (`x86_64` KVM) JNI & Room test job
- [ ] Physical device end-to-end validation
