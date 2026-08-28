package com.localfirewall.app.vpn

import org.junit.Assert.assertEquals
import org.junit.Test

class VpnPermissionDecisionTest {
    @Test
    fun `permission already granted starts service`() {
        assertEquals(
            VpnPermissionAction.StartService,
            VpnPermissionDecision.afterPrepare(permissionRequired = false),
        )
    }

    @Test
    fun `permission requiring approval requests consent`() {
        assertEquals(
            VpnPermissionAction.RequestPermission,
            VpnPermissionDecision.afterPrepare(permissionRequired = true),
        )
    }

    @Test
    fun `approved permission starts service`() {
        assertEquals(
            VpnPermissionAction.StartService,
            VpnPermissionDecision.afterPermissionResult(permissionGranted = true),
        )
    }

    @Test
    fun `cancelled permission keeps firewall off`() {
        assertEquals(
            VpnPermissionAction.KeepFirewallOff,
            VpnPermissionDecision.afterPermissionResult(permissionGranted = false),
        )
    }
}
