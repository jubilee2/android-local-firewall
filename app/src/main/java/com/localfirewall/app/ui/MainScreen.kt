package com.localfirewall.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview
import androidx.compose.ui.unit.dp
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.InstalledApp
import com.localfirewall.app.network.TransportProtocol

enum class FirewallStatus(val displayName: String) {
    OFF("OFF"),
    STARTED("STARTED"),
}

@Composable
fun AndroidLocalFirewallApp(
    serviceStarted: Boolean = false,
    uiState: FirewallUiState = FirewallUiState(),
    onStartFirewall: () -> Unit = {},
    onStopFirewall: () -> Unit = {},
    onSelectTab: (FirewallTab) -> Unit = {},
    onAppSearchQueryChange: (String) -> Unit = {},
    onIncludeSystemAppsChange: (Boolean) -> Unit = {},
    onAppActionChange: (InstalledApp, FirewallAction) -> Unit = { _, _ -> },
    onAddNetworkRule: (FirewallAction, String, TransportProtocol, String) -> Boolean = { _, _, _, _ -> false },
    onClearRuleError: () -> Unit = {},
    onToggleNetworkRuleEnabled: (Long, Boolean) -> Unit = { _, _ -> },
    onDeleteNetworkRule: (Long) -> Unit = {},
    onTrafficLoggingEnabledChange: (Boolean) -> Unit = {},
    onClearTrafficLogs: () -> Unit = {},
) {
    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            Column(modifier = Modifier.fillMaxSize()) {
                TabRow(
                    selectedTabIndex = uiState.selectedTab.ordinal,
                    modifier = Modifier.fillMaxWidth(),
                ) {
                    FirewallTab.entries.forEach { tab ->
                        Tab(
                            selected = uiState.selectedTab == tab,
                            onClick = { onSelectTab(tab) },
                            text = { Text(tab.title) },
                        )
                    }
                }

                when (uiState.selectedTab) {
                    FirewallTab.STATUS -> MainScreen(
                        status = if (serviceStarted) FirewallStatus.STARTED else FirewallStatus.OFF,
                        blockedAppCount = uiState.blockedAppCount,
                        enabledNetworkRuleCount = uiState.networkRules.count { it.enabled },
                        onStartFirewall = onStartFirewall,
                        onStopFirewall = onStopFirewall,
                        modifier = Modifier.weight(1f),
                    )
                    FirewallTab.APPS -> AppsTabContent(
                        apps = uiState.apps,
                        searchQuery = uiState.appSearchQuery,
                        includeSystemApps = uiState.settings.includeSystemApps,
                        onSearchQueryChange = onAppSearchQueryChange,
                        onIncludeSystemAppsChange = onIncludeSystemAppsChange,
                        onAppActionChange = onAppActionChange,
                        modifier = Modifier.weight(1f),
                    )
                    FirewallTab.RULES -> RulesTabContent(
                        rules = uiState.networkRules,
                        inputError = uiState.ruleInputError,
                        onAddRule = onAddNetworkRule,
                        onClearError = onClearRuleError,
                        onToggleRuleEnabled = onToggleNetworkRuleEnabled,
                        onDeleteRule = onDeleteNetworkRule,
                        modifier = Modifier.weight(1f),
                    )
                    FirewallTab.LOGS -> LogsTabContent(
                        logs = uiState.trafficLogs,
                        loggingEnabled = uiState.settings.trafficLoggingEnabled,
                        onLoggingEnabledChange = onTrafficLoggingEnabledChange,
                        onClearLogs = onClearTrafficLogs,
                        modifier = Modifier.weight(1f),
                    )
                }
            }
        }
    }
}

@Composable
fun MainScreen(
    status: FirewallStatus = FirewallStatus.OFF,
    onStartFirewall: () -> Unit = {},
    onStopFirewall: () -> Unit = {},
    blockedAppCount: Int = 0,
    enabledNetworkRuleCount: Int = 0,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(24.dp),
        verticalArrangement = Arrangement.SpaceEvenly,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "Android Local Firewall",
            style = MaterialTheme.typography.headlineMedium,
        )
        Column(
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(8.dp),
        ) {
            Text(
                text = "Firewall: ${status.displayName}",
                style = MaterialTheme.typography.titleLarge,
            )
            Text(
                text = "Blocked apps: $blockedAppCount  |  Active network rules: $enabledNetworkRuleCount",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        }
        val isStarted = status == FirewallStatus.STARTED
        Button(onClick = if (isStarted) onStopFirewall else onStartFirewall) {
            Text(if (isStarted) "Stop Firewall" else "Start Firewall")
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun MainScreenPreview() {
    AndroidLocalFirewallApp()
}
