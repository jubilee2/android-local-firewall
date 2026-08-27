# Roadmap

## Phase 1 - Project bootstrap

- [ ] Create Android Kotlin project
- [ ] Configure Gradle
- [ ] Add Jetpack Compose
- [ ] Add basic CI
- [ ] Verify debug APK builds

## Phase 2 - VPN foundation

- [ ] Add VpnService declaration
- [ ] Request VPN permission
- [ ] Start VPN
- [ ] Stop VPN
- [ ] Create TUN interface
- [ ] Show firewall status

## Phase 3 - Packet processing

- [ ] Read IPv4 packets
- [ ] Parse IPv4 header
- [ ] Parse TCP
- [ ] Parse UDP
- [ ] Unit tests for packet parser

## Phase 4 - Firewall engine

- [ ] Define firewall rule model
- [ ] Implement allow/block
- [ ] IP rules
- [ ] CIDR rules
- [ ] Port rules
- [ ] TCP/UDP rules
- [ ] RuleEngine unit tests

## Phase 5 - App filtering

- [ ] List installed applications
- [ ] Create per-app rules
- [ ] Store app rules
- [ ] Apply app rules

## Phase 6 - Persistence

- [ ] Add Room
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

- [ ] IPv6 support
- [ ] VPN restart handling
- [ ] Network change handling
- [ ] Always-on VPN testing
- [ ] Battery usage testing

## Phase 9 - Testing

- [ ] Unit tests
- [ ] Android instrumentation tests
- [ ] Emulator tests
- [ ] Physical device tests
