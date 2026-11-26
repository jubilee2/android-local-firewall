package com.localfirewall.app.ui

import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.viewModelScope
import com.localfirewall.app.data.FirewallRepository
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.InstalledApp
import com.localfirewall.app.firewall.InstalledAppsProvider
import com.localfirewall.app.network.TransportProtocol
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * Pure coroutine-based UI state coordinator decoupled from Android's [ViewModel] base class for
 * deterministic JVM unit testing.
 */
class FirewallStateHolder(
    private val scope: CoroutineScope,
    private val repository: FirewallRepository,
    private val installedAppsProvider: InstalledAppsProvider,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) {
    private val selectedTab = MutableStateFlow(FirewallTab.STATUS)
    private val appSearchQuery = MutableStateFlow("")
    private val installedApps = MutableStateFlow<List<InstalledApp>>(emptyList())
    private val ruleInputError = MutableStateFlow<String?>(null)

    private data class UiLocalInputs(
        val tab: FirewallTab,
        val searchQuery: String,
        val apps: List<InstalledApp>,
        val error: String?,
    )

    val uiState: StateFlow<FirewallUiState> = combine(
        combine(selectedTab, appSearchQuery, installedApps, ruleInputError, ::UiLocalInputs),
        repository.appRules,
        repository.networkRules,
        repository.trafficLogs,
        repository.settings,
    ) { local, appRules, networkRules, trafficLogs, settings ->
        val actionByPackage = appRules.associate { it.packageName to it.action }
        val blockedCount = appRules.count { it.action == FirewallAction.BLOCK }
        val query = local.searchQuery.trim()
        val filteredApps = local.apps
            .asSequence()
            .filter { app ->
                query.isEmpty() ||
                    app.appName.contains(query, ignoreCase = true) ||
                    app.packageName.contains(query, ignoreCase = true)
            }
            .map { app ->
                AppPolicyItem(
                    app = app,
                    action = actionByPackage[app.packageName] ?: FirewallAction.ALLOW,
                )
            }
            .toList()

        FirewallUiState(
            selectedTab = local.tab,
            appSearchQuery = local.searchQuery,
            apps = filteredApps,
            blockedAppCount = blockedCount,
            networkRules = networkRules,
            trafficLogs = trafficLogs,
            settings = settings,
            ruleInputError = local.error,
        )
    }.stateIn(
        scope = scope,
        started = SharingStarted.Eagerly,
        initialValue = FirewallUiState(),
    )

    init {
        scope.launch {
            repository.settings
                .map { it.includeSystemApps }
                .distinctUntilChanged()
                .collect { includeSystemApps ->
                    installedApps.value = withContext(ioDispatcher) {
                        installedAppsProvider.listInternetApps(includeSystemApps = includeSystemApps)
                    }
                }
        }
    }

    fun selectTab(tab: FirewallTab) {
        selectedTab.value = tab
    }

    fun updateAppSearchQuery(query: String) {
        appSearchQuery.value = query
    }

    fun refreshInstalledApps() {
        scope.launch {
            val includeSystem = uiState.value.settings.includeSystemApps
            installedApps.value = withContext(ioDispatcher) {
                installedAppsProvider.listInternetApps(includeSystemApps = includeSystem)
            }
        }
    }

    fun setAppAction(app: InstalledApp, action: FirewallAction) {
        scope.launch {
            repository.setAppRule(uid = app.uid, packageName = app.packageName, action = action)
        }
    }

    fun setIncludeSystemApps(includeSystemApps: Boolean) {
        scope.launch {
            val current = uiState.value.settings
            repository.updateSettings(current.copy(includeSystemApps = includeSystemApps))
        }
    }

    fun setTrafficLoggingEnabled(enabled: Boolean) {
        scope.launch {
            val current = uiState.value.settings
            repository.updateSettings(current.copy(trafficLoggingEnabled = enabled))
        }
    }

    fun addNetworkRule(
        action: FirewallAction,
        destinationInput: String,
        protocol: TransportProtocol,
        portInput: String,
    ): Boolean {
        val nextPriority = (uiState.value.networkRules.maxOfOrNull { it.priority } ?: 0) + 1
        return when (
            val parsed = NetworkRuleInputParser.parse(
                action = action,
                destinationInput = destinationInput,
                protocol = protocol,
                portInput = portInput,
                priority = nextPriority,
            )
        ) {
            is NetworkRuleParseResult.Invalid -> {
                ruleInputError.value = parsed.message
                false
            }
            is NetworkRuleParseResult.Valid -> {
                ruleInputError.value = null
                scope.launch {
                    repository.addOrUpdateNetworkRule(parsed.rule)
                }
                true
            }
        }
    }

    fun clearRuleInputError() {
        ruleInputError.value = null
    }

    fun setNetworkRuleEnabled(id: Long, enabled: Boolean) {
        scope.launch {
            repository.setNetworkRuleEnabled(id = id, enabled = enabled)
        }
    }

    fun deleteNetworkRule(id: Long) {
        scope.launch {
            repository.deleteNetworkRule(id = id)
        }
    }

    fun clearTrafficLogs() {
        scope.launch {
            repository.clearTrafficLogs()
        }
    }
}

class FirewallViewModel(
    repository: FirewallRepository,
    installedAppsProvider: InstalledAppsProvider,
) : ViewModel() {
    val stateHolder = FirewallStateHolder(
        scope = viewModelScope,
        repository = repository,
        installedAppsProvider = installedAppsProvider,
    )

    val uiState: StateFlow<FirewallUiState> = stateHolder.uiState

    class Factory(
        private val repository: FirewallRepository,
        private val installedAppsProvider: InstalledAppsProvider,
    ) : ViewModelProvider.Factory {
        override fun <T : ViewModel> create(modelClass: Class<T>): T {
            require(modelClass.isAssignableFrom(FirewallViewModel::class.java)) {
                "Unsupported ViewModel class: ${modelClass.name}"
            }
            @Suppress("UNCHECKED_CAST")
            return FirewallViewModel(repository, installedAppsProvider) as T
        }
    }
}
