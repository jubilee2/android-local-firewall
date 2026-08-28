package com.localfirewall.app.firewall

import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol

/** Pure, deterministic firewall evaluation. Rules are evaluated in their supplied order. */
class RuleEngine(
    private val rules: List<FirewallRule>,
    private val defaultAction: FirewallAction = FirewallAction.ALLOW,
) {
    fun evaluate(packet: PacketMetadata): FirewallAction =
        rules.firstOrNull { it.matches(packet) }?.action ?: defaultAction

    private fun FirewallRule.matches(packet: PacketMetadata): Boolean {
        if (destinationAddress != null && destinationAddress != packet.destinationAddress) return false
        if (destinationCidr != null && !destinationCidr.contains(packet.destinationAddress)) return false
        if (protocol != TransportProtocol.ANY && protocol != packet.protocol) return false
        if (destinationPort != null && destinationPort != packet.destinationPort) return false
        return true
    }
}
