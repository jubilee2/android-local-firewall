package com.localfirewall.app.data

import android.content.Context
import androidx.room.Room
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.localfirewall.app.data.local.FirewallDatabase
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.IPv6Cidr
import com.localfirewall.app.network.TransportProtocol
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class FirewallDatabaseInstrumentedTest {
    private lateinit var database: FirewallDatabase
    private lateinit var repository: FirewallRepository

    @Before
    fun setUp() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        database = Room.inMemoryDatabaseBuilder(context, FirewallDatabase::class.java)
            .allowMainThreadQueries()
            .build()
        repository = FirewallRepository(RoomFirewallLocalStore(database))
    }

    @After
    fun tearDown() {
        database.close()
    }

    @Test
    fun persistsAppRulesIpv6NetworkRulesAndPrunesTrafficLogsInSqlite() = runBlocking {
        repository.setAppRule(uid = 10400, packageName = "org.example.client", action = FirewallAction.BLOCK)
        repository.addOrUpdateNetworkRule(
            StoredNetworkRule(
                action = FirewallAction.BLOCK,
                destinationIpv6Cidr = IPv6Cidr.parse("2001:db8::/32"),
                protocol = TransportProtocol.TCP,
                destinationPort = 443,
            ),
        )
        repository.updateSettings(
            FirewallSettings(
                trafficLoggingEnabled = true,
                includeSystemApps = false,
                maxTrafficLogEntries = 10,
            ),
        )

        for (index in 1..12) {
            repository.recordTrafficLog(
                TrafficLogEntry(
                    timestampMillis = index * 1_000L,
                    uid = 10400,
                    applicationName = "Example Client",
                    packageName = "org.example.client",
                    protocol = TransportProtocol.TCP,
                    sourceAddress = "2001:db8:1::2",
                    destinationAddress = "2001:db8::99",
                    sourcePort = 50000 + index,
                    destinationPort = 443,
                    action = FirewallAction.BLOCK,
                ),
            )
        }

        assertEquals(2, repository.activeFirewallRules.first().size)
        val logs = repository.trafficLogs.first()
        assertEquals(10, logs.size)
        assertEquals(12_000L, logs.first().timestampMillis)
        assertEquals(3_000L, logs.last().timestampMillis)
    }
}
