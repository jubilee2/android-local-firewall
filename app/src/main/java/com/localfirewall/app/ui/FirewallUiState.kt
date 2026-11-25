package com.localfirewall.app.ui

import com.localfirewall.app.data.FirewallSettings
import com.localfirewall.app.data.StoredNetworkRule
import com.localfirewall.app.data.TrafficLogEntry
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.InstalledApp

enum class FirewallTab(val title: String) {
    STATUS("Status"),
    APPS("Apps"),
    RULES("Rules"),
    LOGS("Logs"),
}

data class AppPolicyItem(
    val app: InstalledApp,
    val action: FirewallAction,
)

data class FirewallUiState(
    val selectedTab: FirewallTab = FirewallTab.STATUS,
    val appSearchQuery: String = "",
    val apps: List<AppPolicyItem> = emptyList(),
    val blockedAppCount: Int = 0,
    val networkRules: List<StoredNetworkRule> = emptyList(),
    val trafficLogs: List<TrafficLogEntry> = emptyList(),
    val settings: FirewallSettings = FirewallSettings(),
    val ruleInputError: String? = null,
)
