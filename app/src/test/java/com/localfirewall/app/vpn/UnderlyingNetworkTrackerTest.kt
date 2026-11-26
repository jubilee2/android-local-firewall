package com.localfirewall.app.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class UnderlyingNetworkTrackerTest {
    @Test
    fun `tracks eligible non-VPN internet networks deduplicates emissions and handles network loss`() {
        val emissions = ArrayList<List<String>>()
        val tracker = UnderlyingNetworkTracker<String>(onSelectionChanged = emissions::add)

        // VPN network itself must never be selected as an underlying upstream network.
        tracker.onCapabilitiesChanged(network = "tun0", isNotVpn = false, hasInternet = true)
        assertEquals(listOf(emptyList<String>()), emissions)

        // Wi-Fi upstream becomes active.
        tracker.onCapabilitiesChanged(network = "wlan0", isNotVpn = true, hasInternet = true)
        // Duplicate capability callback does not re-emit unchanged selection.
        tracker.onCapabilitiesChanged(network = "wlan0", isNotVpn = true, hasInternet = true)
        assertEquals(listOf(emptyList(), listOf("wlan0")), emissions)

        // Cellular backup joins, then Wi-Fi loses internet capability, then cellular disconnects.
        tracker.onCapabilitiesChanged(network = "rmnet0", isNotVpn = true, hasInternet = true)
        tracker.onCapabilitiesChanged(network = "wlan0", isNotVpn = true, hasInternet = false)
        tracker.onLost(network = "rmnet0")

        assertEquals(
            listOf(
                emptyList(),
                listOf("wlan0"),
                listOf("wlan0", "rmnet0"),
                listOf("rmnet0"),
                emptyList(),
            ),
            emissions,
        )
    }
}
