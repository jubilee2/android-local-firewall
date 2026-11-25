package com.localfirewall.app.ui

import com.localfirewall.app.data.StoredNetworkRule
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.IPv4Cidr
import com.localfirewall.app.network.TransportProtocol

sealed interface NetworkRuleParseResult {
    data class Valid(val rule: StoredNetworkRule) : NetworkRuleParseResult
    data class Invalid(val message: String) : NetworkRuleParseResult
}

/** Validates and parses user-entered IPv4/CIDR/protocol/port network rule inputs without DNS lookups. */
object NetworkRuleInputParser {
    fun parse(
        action: FirewallAction,
        destinationInput: String,
        protocol: TransportProtocol,
        portInput: String,
        priority: Int = 0,
    ): NetworkRuleParseResult {
        val trimmedDestination = destinationInput.trim()
        val trimmedPort = portInput.trim()

        val destinationAddress = if (trimmedDestination.isNotEmpty() && '/' !in trimmedDestination) {
            try {
                IPv4Cidr.parseAddress(trimmedDestination)
            } catch (_: IllegalArgumentException) {
                return NetworkRuleParseResult.Invalid(
                    "Enter a valid IPv4 address (e.g. 8.8.8.8) or CIDR (e.g. 192.168.0.0/16)",
                )
            }
        } else {
            null
        }

        val destinationCidr = if ('/' in trimmedDestination) {
            try {
                IPv4Cidr.parse(trimmedDestination)
            } catch (_: IllegalArgumentException) {
                return NetworkRuleParseResult.Invalid(
                    "Enter a valid IPv4 CIDR subnet (e.g. 192.168.0.0/16)",
                )
            }
        } else {
            null
        }

        val destinationPort = if (trimmedPort.isNotEmpty()) {
            val parsedPort = trimmedPort.toIntOrNull()
            if (parsedPort == null || parsedPort !in 0..65535) {
                return NetworkRuleParseResult.Invalid("Destination port must be between 0 and 65535")
            }
            parsedPort
        } else {
            null
        }

        if (
            destinationAddress == null &&
            destinationCidr == null &&
            protocol == TransportProtocol.ANY &&
            destinationPort == null
        ) {
            return NetworkRuleParseResult.Invalid(
                "Specify at least an IPv4/CIDR destination, TCP/UDP protocol, or destination port",
            )
        }

        return NetworkRuleParseResult.Valid(
            StoredNetworkRule(
                action = action,
                destinationAddress = destinationAddress,
                destinationCidr = destinationCidr,
                protocol = protocol,
                destinationPort = destinationPort,
                enabled = true,
                priority = priority,
            ),
        )
    }
}
