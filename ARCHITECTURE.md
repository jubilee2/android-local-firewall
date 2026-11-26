# Architecture

## High-level architecture

Android applications

        |
        v

Android network stack

        |
        v

FirewallVpnService (TUN 10.0.0.2/32, route 0.0.0.0/0)

        |
        v

OutlinePacketForwarder (Go/JNI pre-stack IPv4/IPv6 + TCP/UDP/Fragment inspection)
  + ConnectionOwnerResolver (Android ConnectivityManager UID lookup)

        |
        v

PacketDecisionCoordinator -> FragmentDecisionEngine / RuleEngine (fail-closed on unknown UID)

      /     \
     /       \
 ALLOW       BLOCK (dropped before lwIP; zero sockets opened)
   |
   v

Outline SDK network/lwip2transport (userspace lwIP)
  -> Protected OS TCP/UDP socket (VpnService.protect before connect/send)

   |
   v

Internet


## Android & native modules

Single Android application module (`:app`) with reproducible Go/CGo JNI library (`native/outline-forwarder` -> `liboutline_forwarder.so` for `arm64-v8a` and `x86_64`).

Package structure (`com.localfirewall.app`):

- `ui/` — Jetpack Compose `Status`, `Apps`, `Rules`, and `Logs` screens plus `FirewallStateHolder` / `FirewallViewModel` and `NetworkRuleInputParser`
- `vpn/` — `FirewallVpnService`, `FirewallVpnSessionOrchestrator`, `PacketDecisionCoordinator`, `InstalledAppsProvider`, `AndroidUnderlyingNetworkMonitor`, VPN permission flow, and standalone `PacketProcessor`
- `firewall/` — `RuleEngine` (UID + IPv4/IPv6 CIDR + TCP/UDP + destination port + `failClosedOnUnknownUid`), `FragmentDecisionEngine`, and `ConnectionOwnerResolver`
- `network/` — `PacketForwarder`, `PacketForwarderLifecycle`, `network/outline/` (`OutlinePacketForwarder`, `OutlineNativeBridge`), IPv4/IPv6/TCP/UDP parsers, `PacketMetadata`, and `FlowKey`
- `data/` — `FirewallRepository`, `FirewallLocalStore`, and Room persistence (`data/local/FirewallDatabase`, entities, DAOs)


## Components

### FirewallVpnService & FirewallVpnSessionOrchestrator

Responsible for:

- establishing the foreground `VpnService` TUN interface (`10.0.0.2/32`, MTU `1500`, IPv4 default route `0.0.0.0/0`, omitting `allowFamily(AF_INET6)` so uncaptured IPv6 cannot bypass policy)
- tracking active underlying networks via `AndroidUnderlyingNetworkMonitor` (`setUnderlyingNetworks`)
- starting `PacketDecisionCoordinator` (`failClosedOnUnknownUid = true`) and `OutlinePacketForwarder` through `PacketForwarderLifecycle`
- tearing down the forwarder before closing the coordinator, network monitor, and TUN descriptor on `ACTION_STOP`, `onRevoke()`, `onDestroy()`, startup failure, or fatal forwarder error

Contains no firewall rule matching logic.

### OutlinePacketForwarder & `native/outline-forwarder`

Responsible for:

- verifying compiled Go module metadata against `BuildConfig.OUTLINE_SDK_COMMIT` before starting
- duplicating the TUN file descriptor and running non-blocking `unix.Poll` + wakeup-pipe I/O loops
- extracting 5-tuple and fragment headers before `lwip2transport` (`IPDevice.Write`), resolving the owning Android UID via `ConnectionOwnerResolver`, and consulting `PacketDecisionCoordinator`
- forwarding `ALLOW` flows directly to original destinations over `lwip2transport` using outbound OS TCP/UDP sockets protected synchronously via `VpnService.protect(fd)` inside `syscall.RawConn.Control` before `connect()`/`sendto()`

### RuleEngine & FragmentDecisionEngine

Inputs:

- Android application UID (`uid`, with `failClosedOnUnknownUid = true` in enforced VPN mode)
- destination IP / CIDR (`IPv4Cidr` and `IPv6Cidr`)
- transport protocol (`TCP` / `UDP`)
- destination port

Output:

- `ALLOW` or `BLOCK` (correlating initial-fragment decisions across subsequent fragments in `FragmentDecisionEngine`)

Independently unit-testable on the host JVM without Android UI.

### FirewallRepository & Room database

Persists locally on-device:

- per-application firewall rules (`app_rules`)
- IPv4/IPv6 CIDR, protocol, and port rules (`network_rules`)
- firewall settings (`firewall_settings`)
- bounded metadata-only traffic logs (`traffic_logs`, zero packet payload storage)

### UI

Jetpack Compose screens communicating exclusively through `FirewallViewModel` / `FirewallStateHolder` and `FirewallRepository` without touching the VPN packet loop directly.
