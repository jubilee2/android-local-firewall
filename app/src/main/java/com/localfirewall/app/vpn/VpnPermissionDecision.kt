package com.localfirewall.app.vpn

sealed interface VpnPermissionAction {
    data object StartService : VpnPermissionAction

    data object RequestPermission : VpnPermissionAction

    data object KeepFirewallOff : VpnPermissionAction
}

object VpnPermissionDecision {
    fun afterPrepare(permissionRequired: Boolean): VpnPermissionAction =
        if (permissionRequired) {
            VpnPermissionAction.RequestPermission
        } else {
            VpnPermissionAction.StartService
        }

    fun afterPermissionResult(permissionGranted: Boolean): VpnPermissionAction =
        if (permissionGranted) {
            VpnPermissionAction.StartService
        } else {
            VpnPermissionAction.KeepFirewallOff
        }
}
