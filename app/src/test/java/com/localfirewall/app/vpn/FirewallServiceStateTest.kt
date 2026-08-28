package com.localfirewall.app.vpn

import org.junit.After
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallServiceStateTest {
    @After
    fun resetState() {
        FirewallServiceState.setStarted(false)
    }

    @Test
    fun `service state reflects lifecycle updates within the process`() {
        assertFalse(FirewallServiceState.isStarted.value)

        FirewallServiceState.setStarted(true)
        assertTrue(FirewallServiceState.isStarted.value)

        FirewallServiceState.setStarted(false)
        assertFalse(FirewallServiceState.isStarted.value)
    }
}
