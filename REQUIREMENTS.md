# Requirements

## Version 0.1

The first version is a local Android firewall.

## Required features

### Firewall service

- User can start firewall
- User can stop firewall
- Firewall runs using Android VpnService
- Firewall status is visible in the UI

### Application filtering

The user can view installed applications.

Each application can have one of these states:

- Allow
- Block

Default policy:

Allow

### Network filtering

Support rules for:

- IPv4 address
- CIDR subnet
- TCP
- UDP
- destination port

Example:

BLOCK 8.8.8.8
BLOCK 192.168.0.0/16
BLOCK TCP port 443
ALLOW UDP port 53

### Traffic log

Store locally:

- timestamp
- application
- protocol
- source IP
- destination IP
- source port
- destination port
- allow/block result

Do not store packet payload.

### Persistence

Firewall rules must survive application restart.

Use Room database.

---

# Privacy

No telemetry.

No analytics.

No cloud sync.

No remote database.

No packet payload upload.

---

# Out of scope for version 0.1

Do not implement:

- Remote VPN servers
- WireGuard
- OpenVPN
- HTTPS interception
- TLS MITM
- Packet payload inspection
- ad blocking lists
- parental control
