package com.localfirewall.app.data.local

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Transaction
import kotlinx.coroutines.flow.Flow

@Dao
interface AppRuleDao {
    @Query("SELECT * FROM app_rules ORDER BY packageName ASC")
    fun observeAll(): Flow<List<AppRuleEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: AppRuleEntity)

    @Query("DELETE FROM app_rules WHERE packageName = :packageName")
    suspend fun deleteByPackageName(packageName: String)
}

@Dao
interface NetworkRuleDao {
    @Query("SELECT * FROM network_rules ORDER BY priority ASC, id ASC")
    fun observeAll(): Flow<List<NetworkRuleEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: NetworkRuleEntity): Long

    @Query("UPDATE network_rules SET enabled = :enabled WHERE id = :id")
    suspend fun setEnabled(id: Long, enabled: Boolean)

    @Query("DELETE FROM network_rules WHERE id = :id")
    suspend fun deleteById(id: Long)
}

@Dao
interface FirewallSettingsDao {
    @Query("SELECT * FROM firewall_settings WHERE singletonId = :singletonId LIMIT 1")
    fun observe(singletonId: Int = FirewallSettingsEntity.SINGLETON_ID): Flow<FirewallSettingsEntity?>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun upsert(entity: FirewallSettingsEntity)
}

@Dao
interface TrafficLogDao {
    @Query("SELECT * FROM traffic_logs ORDER BY timestampMillis DESC, id DESC LIMIT :limit")
    fun observeRecent(limit: Int): Flow<List<TrafficLogEntity>>

    @Insert(onConflict = OnConflictStrategy.ABORT)
    suspend fun insert(entity: TrafficLogEntity): Long

    @Query(
        """
        DELETE FROM traffic_logs
        WHERE id NOT IN (
            SELECT id FROM traffic_logs
            ORDER BY timestampMillis DESC, id DESC
            LIMIT :maxEntries
        )
        """,
    )
    suspend fun trimToLatest(maxEntries: Int)

    @Transaction
    suspend fun insertAndTrim(entity: TrafficLogEntity, maxEntries: Int): Long {
        val insertedId = insert(entity)
        trimToLatest(maxEntries)
        return insertedId
    }

    @Query("DELETE FROM traffic_logs")
    suspend fun clearAll()
}
