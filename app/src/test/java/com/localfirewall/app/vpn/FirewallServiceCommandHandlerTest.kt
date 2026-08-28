package com.localfirewall.app.vpn

import android.app.Service
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallServiceCommandHandlerTest {
    @Test
    fun `start and stop actions are distinct`() {
        assertTrue(FirewallVpnService.ACTION_START.isNotBlank())
        assertTrue(FirewallVpnService.ACTION_STOP.isNotBlank())
        assertNotEquals(FirewallVpnService.ACTION_START, FirewallVpnService.ACTION_STOP)
    }

    @Test
    fun `start command promotes service without stopping it`() {
        var started = false
        var stopped = false
        val result = FirewallServiceCommandHandler(
            start = { started = true },
            stop = { stopped = true },
        ).handle(FirewallVpnService.ACTION_START)

        assertTrue(started)
        assertFalse(stopped)
        assertEquals(Service.START_STICKY, result)
    }

    @Test
    fun `stop command invokes shutdown without starting foreground execution`() {
        var started = false
        var stopped = false
        val result = FirewallServiceCommandHandler(
            start = { started = true },
            stop = { stopped = true },
        ).handle(FirewallVpnService.ACTION_STOP)

        assertFalse(started)
        assertTrue(stopped)
        assertEquals(Service.START_NOT_STICKY, result)
    }
}
