package com.localfirewall.app.ui

import org.junit.Assert.assertEquals
import org.junit.Test

class FirewallStatusTest {
    @Test
    fun `initial firewall status is displayed as off`() {
        assertEquals("OFF", FirewallStatus.OFF.displayName)
    }

    @Test
    fun `started status uses neutral wording`() {
        assertEquals("STARTED", FirewallStatus.STARTED.displayName)
    }
}
