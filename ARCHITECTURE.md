# Architecture

## High-level architecture

Android applications

        |
        v

Android network stack

        |
        v

VpnService

        |
        v

TUN interface

        |
        v

Packet Processor

        |
        v

Firewall Rule Engine

      /     \
     /       \
 ALLOW       BLOCK
   |
   v

Network forwarding

   |
   v

Internet


## Android modules

Initial implementation may use a single Android app module.

Package structure:

`com.localfirewall.app`

- `ui/` (implemented Compose start/stop shell; app rules, network rules, and traffic log screens planned)
- `vpn/` (implemented `FirewallVpnService`, permission flow, `/32` TUN lifecycle, and `PacketProcessor`)
- `firewall/` (implemented IPv4/CIDR/protocol/port `RuleEngine`, `FragmentDecisionEngine`, and `ConnectionOwnerResolver`; per-app rule matching planned)
- `network/` (implemented IPv4/TCP/UDP parsers, `PacketMetadata`, `FlowKey`, and `PacketForwarderLifecycle` scaffold; actual userspace packet forwarding not yet implemented)
- `data/` (planned `FirewallRepository` and Room persistence)


## Components

### FirewallVpnService

Responsible for:

- creating VPN
- creating TUN interface (currently a minimal `/32` interface with no default capture routes until forwarding passes ADR-001 gates)
- starting packet processing
- stopping VPN

It should NOT contain firewall rule logic.

### PacketProcessor

Responsible for:

- reading packets from TUN
- parsing IP packets (currently IPv4 + TCP/UDP headers; IPv6 planned)
- resolving owning Android UID via `ConnectionOwnerResolver`
- sending packet metadata to `FragmentDecisionEngine` / `RuleEngine`

Note: `PacketProcessor` currently evaluates metadata in-memory without forwarding allowed packets or enforcing blocked flows on device traffic.

### Network forwarding (`PacketForwarder`)

Planned userspace forwarding boundary (ADR-001 selects Outline SDK `network/lwip2transport` contingent on acceptance gates; PR #30 is recorded as a failed integration spike, so no native stack or default route is wired yet).

### RuleEngine

Target input:

- application (planned; UID resolution exists in `PacketMetadata`, `FirewallRule` currently matches network fields only)
- destination IP / CIDR (IPv4 implemented; IPv6 planned)
- protocol (TCP/UDP implemented)
- destination port (implemented)

Output:

ALLOW or BLOCK

RuleEngine must be independently unit testable.

### FirewallRepository (planned)

Responsible for loading and storing firewall rules.

### Room database (planned)

Stores:

- application rules
- network rules
- traffic log

### UI

Jetpack Compose.

UI communicates with repositories/view models.

UI must not directly manipulate the VPN packet loop.
