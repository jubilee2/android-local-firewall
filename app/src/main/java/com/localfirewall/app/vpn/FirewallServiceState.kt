package com.localfirewall.app.vpn

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Process-lifetime state owned and updated by [FirewallVpnService]. */
object FirewallServiceState {
    private val mutableIsStarted = MutableStateFlow(false)

    val isStarted: StateFlow<Boolean> = mutableIsStarted.asStateFlow()

    internal fun setStarted(started: Boolean) {
        mutableIsStarted.value = started
    }
}
