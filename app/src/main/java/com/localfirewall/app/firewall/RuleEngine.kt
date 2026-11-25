package com.localfirewall.app.firewall

import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol

/** Pure, deterministic firewall evaluation. Rules are evaluated in their supplied order. */
class RuleEngine(
    private val rules: List<FirewallRule>,
    private val defaultAction: FirewallAction = FirewallAction.ALLOW,
    private val failClosedOnUnknownUid: Boolean = false,
) {
    fun evaluate(packet: PacketMetadata): FirewallAction {
        if (failClosedOnUnknownUid && packet.uid == null) {
            return FirewallAction.BLOCK
        }
        return rules.firstOrNull { it.matches(packet) }?.action ?: defaultAction
    }

    private fun FirewallRule.matches(packet: PacketMetadata): Boolean {
        if (uid != null && uid != packet.uid) return false
        if (destinationAddress != null && destinationAddress != packet.destinationAddress) return false
        if (destinationCidr != null && !destinationCidr.contains(packet.destinationAddress)) return false
        if (destinationIpv6Cidr != null && !destinationIpv6Cidr.contains(packet.destinationAddress)) return false
        if (protocol != TransportProtocol.ANY && protocol != packet.protocol) return false
        if (destinationPort != null && destinationPort != packet.destinationPort) return false
        return true
    }
}
