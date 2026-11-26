package com.localfirewall.app.vpn

import android.app.Service
import android.net.VpnService
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
            start = {
                started = true
                true
            },
            stop = { stopped = true },
        ).handle(FirewallVpnService.ACTION_START)

        assertTrue(started)
        assertFalse(stopped)
        assertEquals(Service.START_REDELIVER_INTENT, result)
    }

    @Test
    fun `start command requests intent redelivery after service restart`() {
        val result = FirewallServiceCommandHandler(
            start = { true },
            stop = {},
        ).handle(FirewallVpnService.ACTION_START)

        assertEquals(Service.START_REDELIVER_INTENT, result)
    }

    @Test
    fun `system always-on VpnService interface action starts firewall session`() {
        var started = false
        var stopped = false
        val result = FirewallServiceCommandHandler(
            start = {
                started = true
                true
            },
            stop = { stopped = true },
        ).handle(VpnService.SERVICE_INTERFACE)

        assertTrue(started)
        assertFalse(stopped)
        assertEquals(Service.START_REDELIVER_INTENT, result)
    }

    @Test
    fun `null restart intent action starts firewall session`() {
        var started = false
        val result = FirewallServiceCommandHandler(
            start = {
                started = true
                true
            },
            stop = {},
        ).handle(null)

        assertTrue(started)
        assertEquals(Service.START_REDELIVER_INTENT, result)
    }

    @Test
    fun `stop command invokes shutdown without starting foreground execution`() {
        var started = false
        var stopped = false
        val result = FirewallServiceCommandHandler(
            start = {
                started = true
                true
            },
            stop = { stopped = true },
        ).handle(FirewallVpnService.ACTION_STOP)

        assertFalse(started)
        assertTrue(stopped)
        assertEquals(Service.START_NOT_STICKY, result)
    }

    @Test
    fun `failed start is not redelivered`() {
        val result = FirewallServiceCommandHandler(
            start = { false },
            stop = {},
        ).handle(FirewallVpnService.ACTION_START)

        assertEquals(Service.START_NOT_STICKY, result)
    }

    @Test
    fun `unknown explicit action neither starts nor stops service`() {
        var started = false
        var stopped = false
        val result = FirewallServiceCommandHandler(
            start = {
                started = true
                true
            },
            stop = { stopped = true },
        ).handle("com.localfirewall.app.vpn.action.UNKNOWN")

        assertFalse(started)
        assertFalse(stopped)
        assertEquals(Service.START_NOT_STICKY, result)
    }
}
