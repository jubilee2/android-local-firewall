package com.localfirewall.app.data.local

import android.content.Context
import androidx.room.Database
import androidx.room.Room
import androidx.room.RoomDatabase

@Database(
    entities = [
        AppRuleEntity::class,
        NetworkRuleEntity::class,
        FirewallSettingsEntity::class,
        TrafficLogEntity::class,
    ],
    version = 1,
    exportSchema = false,
)
abstract class FirewallDatabase : RoomDatabase() {
    abstract fun appRuleDao(): AppRuleDao
    abstract fun networkRuleDao(): NetworkRuleDao
    abstract fun settingsDao(): FirewallSettingsDao
    abstract fun trafficLogDao(): TrafficLogDao

    companion object {
        private const val DATABASE_NAME = "local_firewall.db"

        @Volatile
        private var instance: FirewallDatabase? = null

        fun getInstance(context: Context): FirewallDatabase =
            instance ?: synchronized(this) {
                instance ?: Room.databaseBuilder(
                    context.applicationContext,
                    FirewallDatabase::class.java,
                    DATABASE_NAME,
                ).build().also { instance = it }
            }
    }
}
