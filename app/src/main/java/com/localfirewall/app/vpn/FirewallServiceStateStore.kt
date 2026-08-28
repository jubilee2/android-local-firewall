package com.localfirewall.app.vpn

import android.content.Context

/** Persists whether the firewall service has been requested to run across Activity recreation. */
class FirewallServiceStateStore(context: Context) {
    private val preferences = context.applicationContext.getSharedPreferences(
        PREFERENCES_NAME,
        Context.MODE_PRIVATE,
    )

    fun isStarted(): Boolean = preferences.getBoolean(KEY_STARTED, false)

    fun setStarted(started: Boolean) {
        preferences.edit().putBoolean(KEY_STARTED, started).apply()
    }

    private companion object {
        const val PREFERENCES_NAME = "firewall_service_state"
        const val KEY_STARTED = "started"
    }
}
