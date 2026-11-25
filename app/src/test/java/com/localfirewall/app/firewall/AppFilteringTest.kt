package com.localfirewall.app.firewall

import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.InetAddress
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class AppFilteringTest {
    @Test
    fun `AppFirewallRule validates UID and packageName`() {
        assertThrows(IllegalArgumentException::class.java) {
            AppFirewallRule(uid = -1, packageName = "com.example.app", action = FirewallAction.BLOCK)
        }
        assertThrows(IllegalArgumentException::class.java) {
            AppFirewallRule(uid = 10100, packageName = " ", action = FirewallAction.BLOCK)
        }
    }

    @Test
    fun `shared UID app rules fail closed when any package is blocked`() {
        val appRules = listOf(
            AppFirewallRule(uid = 10200, packageName = "com.shared.alpha", action = FirewallAction.ALLOW),
            AppFirewallRule(uid = 10200, packageName = "com.shared.beta", action = FirewallAction.BLOCK),
            AppFirewallRule(uid = 10100, packageName = "com.single.allowed", action = FirewallAction.ALLOW),
        )

        val compiled = appRules.toEffectiveFirewallRules()

        assertEquals(
            listOf(
                FirewallRule(action = FirewallAction.ALLOW, uid = 10100),
                FirewallRule(action = FirewallAction.BLOCK, uid = 10200),
            ),
            compiled,
        )

        val engine = RuleEngine(rules = compiled)
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packetForUid(10100)))
        assertEquals(FirewallAction.BLOCK, engine.evaluate(packetForUid(10200)))
        assertEquals(FirewallAction.ALLOW, engine.evaluate(packetForUid(10300)))
    }

    @Test
    fun `InstalledAppsProvider filters non-internet and excluded apps and sorts deterministically`() {
        val scanner = InstalledPackageScanner {
            listOf(
                RawInstalledPackage(
                    uid = 10050,
                    packageName = "com.android.systemui",
                    label = "System UI",
                    isSystemApp = true,
                    hasInternetPermission = true,
                ),
                RawInstalledPackage(
                    uid = 10120,
                    packageName = "org.example.zeta",
                    label = "zeta client",
                    isSystemApp = false,
                    hasInternetPermission = true,
                ),
                RawInstalledPackage(
                    uid = 10110,
                    packageName = "org.example.alpha",
                    label = "Alpha Browser",
                    isSystemApp = false,
                    hasInternetPermission = true,
                ),
                RawInstalledPackage(
                    uid = 10115,
                    packageName = "org.example.nolabel",
                    label = "   ",
                    isSystemApp = false,
                    hasInternetPermission = true,
                ),
                RawInstalledPackage(
                    uid = 10130,
                    packageName = "org.example.offline",
                    label = "Offline Calculator",
                    isSystemApp = false,
                    hasInternetPermission = false,
                ),
                RawInstalledPackage(
                    uid = 10199,
                    packageName = "com.localfirewall.app",
                    label = "Android Local Firewall",
                    isSystemApp = false,
                    hasInternetPermission = true,
                ),
            )
        }

        val provider = InstalledAppsProvider(
            scanner = scanner,
            excludedPackages = setOf("com.localfirewall.app"),
        )

        assertEquals(
            listOf(
                InstalledApp(uid = 10110, packageName = "org.example.alpha", appName = "Alpha Browser", isSystemApp = false),
                InstalledApp(uid = 10115, packageName = "org.example.nolabel", appName = "org.example.nolabel", isSystemApp = false),
                InstalledApp(uid = 10120, packageName = "org.example.zeta", appName = "zeta client", isSystemApp = false),
                InstalledApp(uid = 10050, packageName = "com.android.systemui", appName = "System UI", isSystemApp = true),
            ),
            provider.listInternetApps(includeSystemApps = true),
        )

        assertEquals(
            listOf(
                InstalledApp(uid = 10110, packageName = "org.example.alpha", appName = "Alpha Browser", isSystemApp = false),
                InstalledApp(uid = 10115, packageName = "org.example.nolabel", appName = "org.example.nolabel", isSystemApp = false),
                InstalledApp(uid = 10120, packageName = "org.example.zeta", appName = "zeta client", isSystemApp = false),
            ),
            provider.listInternetApps(includeSystemApps = false),
        )
    }

    private fun packetForUid(uid: Int?) = PacketMetadata(
        sourceAddress = InetAddress.getByName("192.0.2.10"),
        destinationAddress = InetAddress.getByName("198.51.100.20"),
        protocol = TransportProtocol.TCP,
        sourcePort = 54321,
        destinationPort = 443,
        identification = 1,
        fragmentOffset = 0,
        moreFragments = false,
        uid = uid,
    )
}
