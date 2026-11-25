package com.localfirewall.app.data

import com.localfirewall.app.data.local.AppRuleEntity
import com.localfirewall.app.data.local.FirewallDatabase
import com.localfirewall.app.data.local.FirewallSettingsEntity
import com.localfirewall.app.data.local.NetworkRuleEntity
import com.localfirewall.app.data.local.TrafficLogEntity
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.update

/** Storage boundary decoupling [FirewallRepository] from Android SQLite drivers in unit tests. */
interface FirewallLocalStore {
    fun observeAppRules(): Flow<List<AppRuleEntity>>
    suspend fun upsertAppRule(entity: AppRuleEntity)
    suspend fun deleteAppRule(packageName: String)

    fun observeNetworkRules(): Flow<List<NetworkRuleEntity>>
    suspend fun upsertNetworkRule(entity: NetworkRuleEntity): Long
    suspend fun setNetworkRuleEnabled(id: Long, enabled: Boolean)
    suspend fun deleteNetworkRule(id: Long)

    fun observeSettings(): Flow<FirewallSettingsEntity?>
    suspend fun upsertSettings(entity: FirewallSettingsEntity)

    fun observeTrafficLogs(limit: Int): Flow<List<TrafficLogEntity>>
    suspend fun insertAndTrimTrafficLog(entity: TrafficLogEntity, maxEntries: Int): Long
    suspend fun trimTrafficLogs(maxEntries: Int)
    suspend fun clearTrafficLogs()
}

/** Production [FirewallLocalStore] backed by [FirewallDatabase]. */
class RoomFirewallLocalStore(
    private val database: FirewallDatabase,
) : FirewallLocalStore {
    override fun observeAppRules(): Flow<List<AppRuleEntity>> = database.appRuleDao().observeAll()

    override suspend fun upsertAppRule(entity: AppRuleEntity) {
        database.appRuleDao().upsert(entity)
    }

    override suspend fun deleteAppRule(packageName: String) {
        database.appRuleDao().deleteByPackageName(packageName)
    }

    override fun observeNetworkRules(): Flow<List<NetworkRuleEntity>> =
        database.networkRuleDao().observeAll()

    override suspend fun upsertNetworkRule(entity: NetworkRuleEntity): Long =
        database.networkRuleDao().upsert(entity)

    override suspend fun setNetworkRuleEnabled(id: Long, enabled: Boolean) {
        database.networkRuleDao().setEnabled(id, enabled)
    }

    override suspend fun deleteNetworkRule(id: Long) {
        database.networkRuleDao().deleteById(id)
    }

    override fun observeSettings(): Flow<FirewallSettingsEntity?> =
        database.settingsDao().observe()

    override suspend fun upsertSettings(entity: FirewallSettingsEntity) {
        database.settingsDao().upsert(entity)
    }

    override fun observeTrafficLogs(limit: Int): Flow<List<TrafficLogEntity>> =
        database.trafficLogDao().observeRecent(limit)

    override suspend fun insertAndTrimTrafficLog(entity: TrafficLogEntity, maxEntries: Int): Long =
        database.trafficLogDao().insertAndTrim(entity, maxEntries)

    override suspend fun trimTrafficLogs(maxEntries: Int) {
        database.trafficLogDao().trimToLatest(maxEntries)
    }

    override suspend fun clearTrafficLogs() {
        database.trafficLogDao().clearAll()
    }
}

/** Deterministic in-memory [FirewallLocalStore] for pure-JVM repository and ViewModel tests. */
@OptIn(ExperimentalCoroutinesApi::class)
class InMemoryFirewallLocalStore : FirewallLocalStore {
    private val appRules = MutableStateFlow<Map<String, AppRuleEntity>>(emptyMap())
    private val networkRules = MutableStateFlow<Map<Long, NetworkRuleEntity>>(emptyMap())
    private val settings = MutableStateFlow<FirewallSettingsEntity?>(null)
    private val trafficLogs = MutableStateFlow<List<TrafficLogEntity>>(emptyList())
    private var nextNetworkRuleId = 1L
    private var nextTrafficLogId = 1L

    override fun observeAppRules(): Flow<List<AppRuleEntity>> =
        appRules.map { map -> map.values.sortedBy(AppRuleEntity::packageName) }

    override suspend fun upsertAppRule(entity: AppRuleEntity) {
        appRules.update { it + (entity.packageName to entity) }
    }

    override suspend fun deleteAppRule(packageName: String) {
        appRules.update { it - packageName }
    }

    override fun observeNetworkRules(): Flow<List<NetworkRuleEntity>> =
        networkRules.map { map ->
            map.values.sortedWith(
                compareBy<NetworkRuleEntity> { it.priority }.thenBy { it.id },
            )
        }

    override suspend fun upsertNetworkRule(entity: NetworkRuleEntity): Long {
        var assignedId = entity.id
        networkRules.update { current ->
            if (assignedId == 0L) {
                assignedId = nextNetworkRuleId++
            } else if (assignedId >= nextNetworkRuleId) {
                nextNetworkRuleId = assignedId + 1
            }
            current + (assignedId to entity.copy(id = assignedId))
        }
        return assignedId
    }

    override suspend fun setNetworkRuleEnabled(id: Long, enabled: Boolean) {
        networkRules.update { current ->
            val existing = current[id] ?: return@update current
            current + (id to existing.copy(enabled = enabled))
        }
    }

    override suspend fun deleteNetworkRule(id: Long) {
        networkRules.update { it - id }
    }

    override fun observeSettings(): Flow<FirewallSettingsEntity?> = settings

    override suspend fun upsertSettings(entity: FirewallSettingsEntity) {
        settings.value = entity
    }

    override fun observeTrafficLogs(limit: Int): Flow<List<TrafficLogEntity>> =
        trafficLogs.map { list ->
            list.sortedWith(
                compareByDescending<TrafficLogEntity> { it.timestampMillis }
                    .thenByDescending { it.id },
            ).take(limit)
        }

    override suspend fun insertAndTrimTrafficLog(entity: TrafficLogEntity, maxEntries: Int): Long {
        var assignedId = 0L
        trafficLogs.update { current ->
            assignedId = if (entity.id == 0L) nextTrafficLogId++ else entity.id
            (current + entity.copy(id = assignedId))
                .sortedWith(
                    compareByDescending<TrafficLogEntity> { it.timestampMillis }
                        .thenByDescending { it.id },
                )
                .take(maxEntries)
        }
        return assignedId
    }

    override suspend fun trimTrafficLogs(maxEntries: Int) {
        trafficLogs.update { current ->
            current
                .sortedWith(
                    compareByDescending<TrafficLogEntity> { it.timestampMillis }
                        .thenByDescending { it.id },
                )
                .take(maxEntries)
        }
    }

    override suspend fun clearTrafficLogs() {
        trafficLogs.value = emptyList()
    }
}
