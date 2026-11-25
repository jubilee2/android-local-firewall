# Roadmap

> **Note on enforcement status:** Phases 1–4 below reflect implemented on-device foundations and JVM unit tests. Actual device-wide traffic capture and enforced allow/block packet forwarding remain **unimplemented** until the ADR-001 userspace packet-forwarding gate passes (see Forwarding Gate below).

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
- [x] Create TUN interface (minimal `/32` interface only; no default capture route installed yet)
- [x] Show firewall status (service start/stop state; does not yet enforce traffic filtering)

## Phase 3 - Packet processing

- [x] Read IPv4 packets (`PollingTunPacketSource` and `PacketProcessor`)
- [x] Parse IPv4 header (`IPv4PacketParser`)
- [x] Parse TCP (`TcpPacketParser`)
- [x] Parse UDP (`UdpPacketParser`)
- [x] Unit tests for packet parser

## Phase 4 - Firewall engine (pure evaluation foundation)

- [x] Define firewall rule model (`FirewallRule`, `FirewallAction`)
- [x] Implement allow/block decision evaluation (`RuleEngine`, `FragmentDecisionEngine`; active `FirewallVpnService` currently evaluates against an empty rule list without dropping or forwarding packets)
- [x] IP rules (IPv4 destination matching)
- [x] CIDR rules (`IPv4Cidr` matching)
- [x] Port rules (destination port matching)
- [x] TCP/UDP rules (`TransportProtocol` matching)
- [x] RuleEngine unit tests

## Forwarding & enforcement gate (blocking real traffic capture)

- [x] Define `PacketForwarder` / `PacketForwarderLifecycle` boundary and ADR-001 architecture
- [x] Add `ConnectionOwnerResolver` flow UID attribution foundation for TCP/UDP
- [ ] Replace failed Outline SDK `lwip2transport` spike (PR #30 failed gate: unverified commit and constant-string C stub without `lwip2transport`) with a verified pinned upstream Android build
- [ ] Prove direct original-destination TCP/UDP forwarding, pre-I/O `VpnService.protect()`, fail-closed UID/protection handling, and bounded shutdown
- [ ] Wire `PacketForwarder` to `FirewallVpnService` and install capture routes only after all ADR-001 gates pass

## Phase 5 - App filtering

- [ ] List installed applications
- [ ] Create per-app rules (extend `FirewallRule` / `RuleEngine` beyond UID attribution foundation)
- [ ] Store app rules
- [ ] Apply app rules to enforced flows

## Phase 6 - Persistence

- [ ] Add Room (`data/` package and `FirewallRepository`)
- [ ] Store firewall rules
- [ ] Store settings
- [ ] Store traffic metadata

## Phase 7 - Traffic log

- [ ] Traffic log screen
- [ ] Allow/block status
- [ ] Application name
- [ ] Destination
- [ ] Protocol
- [ ] Port

## Phase 8 - Reliability

- [ ] IPv6 support (packet parsing, CIDR/address rules, and verified IPv6 forwarding)
- [ ] VPN restart handling
- [ ] Network change handling
- [ ] Always-on VPN testing (`SUPPORTS_ALWAYS_ON` currently `false`)
- [ ] Battery usage testing

## Phase 9 - Testing

- [x] Unit tests for Phase 1–4 foundations (VPN lifecycle, packet parsers, UID resolver, and rule engine)
- [ ] Unit tests for forwarding integration, app filtering, Room persistence, and UI ViewModels
- [ ] Android instrumentation tests
- [ ] Emulator tests
- [ ] Physical device tests
