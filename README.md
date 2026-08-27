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

## Main features

- Start / stop firewall
- Per-app allow/block
- IP allow/block
- CIDR allow/block
- TCP/UDP filtering
- Port filtering
- Local traffic log
- IPv4 support
- IPv6 support
- Always-on VPN support
- Block connections when VPN is unavailable

## Technology

- Kotlin
- Jetpack Compose
- Android VpnService
- Room
- Gradle
- GitHub Actions

## Important constraints

- No root required
- No remote VPN server
- No backend service
- No user traffic leaves the device except normal allowed Internet traffic
- Do not implement custom encryption
- Do not implement a TCP/IP stack from scratch unless absolutely necessary
