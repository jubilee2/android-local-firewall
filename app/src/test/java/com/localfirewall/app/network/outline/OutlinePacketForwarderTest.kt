package com.localfirewall.app.network.outline

import com.localfirewall.app.BuildConfig
import com.localfirewall.app.firewall.ConnectionOwnerLookup
import com.localfirewall.app.firewall.ConnectionOwnerResolver
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.FirewallRule
import com.localfirewall.app.firewall.FragmentDecisionEngine
import com.localfirewall.app.firewall.IPv4Cidr
import com.localfirewall.app.firewall.RuleEngine
import com.localfirewall.app.network.PacketForwarderLifecycle
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

class OutlinePacketForwarderTest {
    private val pinnedCommit = BuildConfig.OUTLINE_SDK_COMMIT
    private val validMetadataJson = """
        {
          "pinnedOutlineCommit": "$pinnedCommit",
          "outlineModulePath": "golang.getoutline.org/sdk",
          "outlineVersion": "v0.1.1-0.20261110205933-${pinnedCommit.take(12)}",
          "outlineSum": "h1:94QVqUhUqnxyOu2tdmU597tNBODQ81abccIAsNTz2x8=",
          "lwipModulePath": "github.com/eycorsican/go-tun2socks",
          "lwipVersion": "v1.16.11",
          "lwipSum": "h1:+hJDNgisrYaGEqoSxhdikMgMJ4Ilfwm/IZDrWRrbaH8=",
          "goVersion": "go1.25.0"
        }
    """.trimIndent()

    @Test
    fun `rejects tampered or unverified native module metadata during start`() {
        val mismatchedJson = validMetadataJson.replace(pinnedCommit.take(12), "deadbeefcafe")
        val fakeNative = FakeOutlineNativeApi(metadataJson = mismatchedJson)
        val forwarder = OutlinePacketForwarder(
            tunFdProvider = { 10 },
            connectionOwnerResolver = ConnectionOwnerResolver(ConnectionOwnerLookup { _, _, _ -> 10100 }),
            evaluatePacket = { FirewallAction.ALLOW },
            socketProtector = { true },
            nativeApi = fakeNative,
        )

        assertThrows(IllegalStateException::class.java) {
            forwarder.start()
        }
        assertEquals(0, fakeNative.startCalls)
    }

    @Test
    fun `admitPacket fails closed on unknown UID blocked rule and orphan fragments`() {
        val fakeNative = FakeOutlineNativeApi(metadataJson = validMetadataJson)
        var resolvedUid = 10200
        val ruleEngine = RuleEngine(
            rules = listOf(
                FirewallRule(
                    action = FirewallAction.BLOCK,
                    destinationAddress = IPv4Cidr.parseAddress("8.8.8.8"),
                ),
            ),
            defaultAction = FirewallAction.ALLOW,
            failClosedOnUnknownUid = true,
        )
        val fragmentEngine = FragmentDecisionEngine(ruleEngine)

        val forwarder = OutlinePacketForwarder(
            tunFdProvider = { 42 },
            connectionOwnerResolver = ConnectionOwnerResolver(
                lookup = ConnectionOwnerLookup { _, _, _ -> resolvedUid },
            ),
            evaluatePacket = fragmentEngine::evaluate,
            socketProtector = { fd -> fd == 99 },
            nativeApi = fakeNative,
        )
        val lifecycle = PacketForwarderLifecycle { forwarder }
        lifecycle.start()

        val cb = requireNotNull(fakeNative.capturedCallbacks)
        val srcIp = byteArrayOf(10, 0, 0, 2)
        val allowedDst = byteArrayOf(1, 1, 1, 1)
        val blockedDst = byteArrayOf(8, 8, 8, 8)

        // Allowed destination with valid UID succeeds, including subsequent fragment.
        assertTrue(
            cb.admitPacket(
                ipVersion = 4,
                protocol = 17,
                sourceAddress = srcIp,
                sourcePort = 51000,
                destinationAddress = allowedDst,
                destinationPort = 53,
                identification = 77,
                fragmentOffset = 0,
                moreFragments = true,
            ),
        )
        assertTrue(
            cb.admitPacket(
                ipVersion = 4,
                protocol = 17,
                sourceAddress = srcIp,
                sourcePort = -1,
                destinationAddress = allowedDst,
                destinationPort = -1,
                identification = 77,
                fragmentOffset = 1,
                moreFragments = false,
            ),
        )

        // Orphan non-initial fragment without cached decision fails closed.
        assertFalse(
            cb.admitPacket(
                ipVersion = 4,
                protocol = 17,
                sourceAddress = srcIp,
                sourcePort = -1,
                destinationAddress = allowedDst,
                destinationPort = -1,
                identification = 888,
                fragmentOffset = 1,
                moreFragments = false,
            ),
        )

        // Blocked destination fails closed.
        assertFalse(
            cb.admitPacket(
                ipVersion = 4,
                protocol = 6,
                sourceAddress = srcIp,
                sourcePort = 51001,
                destinationAddress = blockedDst,
                destinationPort = 443,
                identification = 1,
                fragmentOffset = 0,
                moreFragments = false,
            ),
        )

        // Unknown UID (-1 == Process.INVALID_UID) fails closed even for otherwise allowed destination.
        resolvedUid = -1
        assertFalse(
            cb.admitPacket(
                ipVersion = 4,
                protocol = 6,
                sourceAddress = srcIp,
                sourcePort = 51002,
                destinationAddress = allowedDst,
                destinationPort = 443,
                identification = 2,
                fragmentOffset = 0,
                moreFragments = false,
            ),
        )

        // Socket protection validates descriptor and propagates false on non-protected FDs.
        assertTrue(cb.protectSocket(99))
        assertFalse(cb.protectSocket(100))
        assertFalse(cb.protectSocket(-1))

        lifecycle.stop()
        assertEquals(1, fakeNative.stopCalls)
    }

    private class FakeOutlineNativeApi(
        private val metadataJson: String,
    ) : OutlineNativeApi {
        var startCalls = 0
        var stopCalls = 0
        var capturedCallbacks: NativeForwarderCallbacks? = null

        override fun metadataJson(): String = metadataJson

        override fun start(
            tunFd: Int,
            callbacks: NativeForwarderCallbacks,
            maxTcpStreams: Int,
            maxUdpAssociations: Int,
            udpIdleTimeoutMillis: Int,
        ): Long {
            startCalls += 1
            capturedCallbacks = callbacks
            return 1L
        }

        override fun stop(handle: Long) {
            stopCalls += 1
        }
    }
}
