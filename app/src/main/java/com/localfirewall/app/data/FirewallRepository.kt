package com.localfirewall.app.data

import com.localfirewall.app.data.local.FirewallDatabase
import com.localfirewall.app.data.local.toEntity
import com.localfirewall.app.firewall.AppFirewallRule
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.FirewallRule
import com.localfirewall.app.firewall.toEffectiveFirewallRules
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map

/**
 * Coordinates local storage and domain compilation for per-app rules, network rules, settings,
 * and metadata-only traffic logs.
 */
@OptIn(ExperimentalCoroutinesApi::class)
class FirewallRepository(
    private val store: FirewallLocalStore,
    private val currentTimeMillis: () -> Long = System::currentTimeMillis,
) {
    val appRules: Flow<List<AppFirewallRule>> = store.observeAppRules()
        .map { entities -> entities.map { it.toDomain() } }
        .distinctUntilChanged()

    val networkRules: Flow<List<StoredNetworkRule>> = store.observeNetworkRules()
        .map { entities -> entities.map { it.toDomain() } }
        .distinctUntilChanged()

    val settings: Flow<FirewallSettings> = store.observeSettings()
        .map { entity -> entity?.toDomain() ?: FirewallSettings() }
        .distinctUntilChanged()

    val trafficLogs: Flow<List<TrafficLogEntry>> = settings
        .map { it.maxTrafficLogEntries }
        .distinctUntilChanged()
        .flatMapLatest { limit ->
            store.observeTrafficLogs(limit).map { entities -> entities.map { it.toDomain() } }
        }

    /**
     * Ordered list of active [FirewallRule]s for [com.localfirewall.app.firewall.RuleEngine].
     *
     * Effective per-app [FirewallAction.BLOCK] rules are placed before network rules so a blocked
     * application cannot bypass its block via a permissive network rule (e.g. `ALLOW UDP 53`),
     * while allowed applications remain subject to all enabled network rules before falling through
     * to the engine's default `ALLOW` policy.
     */
    val activeFirewallRules: Flow<List<FirewallRule>> = combine(
        appRules,
        networkRules,
    ) { configuredAppRules, configuredNetworkRules ->
        compileActiveFirewallRules(configuredAppRules, configuredNetworkRules)
    }.distinctUntilChanged()

    suspend fun setAppRule(uid: Int, packageName: String, action: FirewallAction) {
        if (action == FirewallAction.ALLOW) {
            // Default per-app policy is ALLOW; removing an explicit row keeps storage minimal,
            // except when callers explicitly record ALLOW via saveExplicitAppRule.
            store.deleteAppRule(packageName)
        } else {
            val rule = AppFirewallRule(uid = uid, packageName = packageName, action = action)
            store.upsertAppRule(rule.toEntity(updatedAtMillis = currentTimeMillis()))
        }
    }

    suspend fun saveAppRule(rule: AppFirewallRule) {
        store.upsertAppRule(rule.toEntity(updatedAtMillis = currentTimeMillis()))
    }

    suspend fun removeAppRule(packageName: String) {
        store.deleteAppRule(packageName)
    }

    suspend fun addOrUpdateNetworkRule(rule: StoredNetworkRule): Long {
        val stamped = if (rule.createdAtMillis == 0L) {
            rule.copy(createdAtMillis = currentTimeMillis())
        } else {
            rule
        }
        return store.upsertNetworkRule(stamped.toEntity())
    }

    suspend fun setNetworkRuleEnabled(id: Long, enabled: Boolean) {
        store.setNetworkRuleEnabled(id = id, enabled = enabled)
    }

    suspend fun deleteNetworkRule(id: Long) {
        store.deleteNetworkRule(id = id)
    }

    suspend fun updateSettings(updated: FirewallSettings) {
        store.upsertSettings(updated.toEntity())
        store.trimTrafficLogs(updated.maxTrafficLogEntries)
    }

    /** Records packet decision metadata when logging is enabled; drops silently when disabled. */
    suspend fun recordTrafficLog(entry: TrafficLogEntry): Long? {
        val currentSettings = settings.first()
        if (!currentSettings.trafficLoggingEnabled) return null
        return store.insertAndTrimTrafficLog(
            entity = entry.toEntity(),
            maxEntries = currentSettings.maxTrafficLogEntries,
        )
    }

    suspend fun clearTrafficLogs() {
        store.clearTrafficLogs()
    }

    companion object {
        @Volatile
        private var instance: FirewallRepository? = null

        fun getInstance(database: FirewallDatabase): FirewallRepository =
            instance ?: synchronized(this) {
                instance ?: FirewallRepository(RoomFirewallLocalStore(database)).also {
                    instance = it
                }
            }

        internal fun compileActiveFirewallRules(
            appRules: List<AppFirewallRule>,
            networkRules: List<StoredNetworkRule>,
        ): List<FirewallRule> {
            val blockedUidRules = appRules
                .toEffectiveFirewallRules()
                .filter { it.action == FirewallAction.BLOCK }
            val enabledNetworkRules = networkRules
                .asSequence()
                .filter(StoredNetworkRule::enabled)
                .sortedWith(compareBy<StoredNetworkRule> { it.priority }.thenBy { it.id })
                .map(StoredNetworkRule::toFirewallRule)
                .toList()
            return blockedUidRules + enabledNetworkRules
        }
    }
}
