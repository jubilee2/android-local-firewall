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

com.example.localfirewall

ui/
vpn/
firewall/
network/
data/


## Components

### FirewallVpnService

Responsible for:

- creating VPN
- creating TUN interface
- starting packet processing
- stopping VPN

It should NOT contain firewall rule logic.

### PacketProcessor

Responsible for:

- reading packets from TUN
- parsing IP packets
- extracting protocol information
- sending packet metadata to RuleEngine

### RuleEngine

Input:

- application
- destination IP
- protocol
- destination port

Output:

ALLOW or BLOCK

RuleEngine must be independently unit testable.

### FirewallRepository

Responsible for loading and storing firewall rules.

### Room database

Stores:

- application rules
- network rules
- traffic log

### UI

Jetpack Compose.

UI communicates with repositories/view models.

UI must not directly manipulate the VPN packet loop.
