package com.localfirewall.app.network.outline

import com.localfirewall.app.BuildConfig
import com.localfirewall.app.firewall.ConnectionOwnerResolver
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.network.PacketForwarder
import com.localfirewall.app.network.PacketMetadata
import com.localfirewall.app.network.TransportProtocol
import java.net.Inet6Address
import java.net.InetAddress

/**
 * [PacketForwarder] backed by the verified Outline SDK `network/lwip2transport` Go/JNI bridge.
 *
 * Enforces fail-closed semantics at every boundary:
 * - Verifies compiled Outline SDK & lwIP module metadata against [BuildConfig.OUTLINE_SDK_COMMIT] before starting.
 * - Resolves owning Android UID on initial packets and drops any flow whose UID is unavailable (`null`).
 * - Protects every outbound host socket synchronously via [socketProtector] before `connect()`/`sendto()`.
 */
internal class OutlinePacketForwarder(
    private val tunFdProvider: () -> Int,
    private val connectionOwnerResolver: ConnectionOwnerResolver,
    private val evaluatePacket: (PacketMetadata) -> FirewallAction,
    private val socketProtector: (Int) -> Boolean,
    private val onFatalError: (String) -> Unit = {},
    private val nativeApi: OutlineNativeApi = OutlineNativeBridge,
    private val expectedOutlineCommit: String = BuildConfig.OUTLINE_SDK_COMMIT,
    private val maxTcpStreams: Int = DEFAULT_MAX_TCP_STREAMS,
    private val maxUdpAssociations: Int = DEFAULT_MAX_UDP_ASSOCIATIONS,
    private val udpIdleTimeoutMillis: Int = DEFAULT_UDP_IDLE_TIMEOUT_MILLIS,
) : PacketForwarder {
    private var nativeHandle: Long = NO_HANDLE

    @Synchronized
    override fun start() {
        if (nativeHandle != NO_HANDLE) return

        val metadata = OutlineBridgeMetadata.fromJson(nativeApi.metadataJson())
        metadata.validateAgainstPin(expectedOutlineCommit)

        val tunFd = tunFdProvider()
        require(tunFd >= 0) { "TUN file descriptor must be non-negative" }

        val startedHandle = nativeApi.start(
            tunFd = tunFd,
            callbacks = callbacks,
            maxTcpStreams = maxTcpStreams,
            maxUdpAssociations = maxUdpAssociations,
            udpIdleTimeoutMillis = udpIdleTimeoutMillis,
        )
        check(startedHandle != NO_HANDLE) { "Native forwarder returned invalid handle" }
        nativeHandle = startedHandle
    }

    @Synchronized
    override fun stop() {
        val handle = nativeHandle
        if (handle == NO_HANDLE) return
        nativeApi.stop(handle)
        nativeHandle = NO_HANDLE
    }

    private val callbacks = object : NativeForwarderCallbacks {
        override fun admitPacket(
            ipVersion: Int,
            protocol: Int,
            sourceAddress: ByteArray,
            sourcePort: Int,
            destinationAddress: ByteArray,
            destinationPort: Int,
            identification: Int,
            fragmentOffset: Int,
            moreFragments: Boolean,
        ): Boolean = try {
            val transportProtocol = when (protocol) {
                6 -> TransportProtocol.TCP
                17 -> TransportProtocol.UDP
                else -> return false
            }
            val srcInet = decodeAddress(ipVersion, sourceAddress) ?: return false
            val dstInet = decodeAddress(ipVersion, destinationAddress) ?: return false

            val rawMetadata = PacketMetadata(
                sourceAddress = srcInet,
                destinationAddress = dstInet,
                protocol = transportProtocol,
                sourcePort = sourcePort.takeIf { it in 0..65535 },
                destinationPort = destinationPort.takeIf { it in 0..65535 },
                identification = identification,
                fragmentOffset = fragmentOffset,
                moreFragments = moreFragments,
            )

            if (fragmentOffset == 0) {
                val uid = connectionOwnerResolver.resolve(rawMetadata) ?: return false
                evaluatePacket(rawMetadata.copy(uid = uid)) == FirewallAction.ALLOW
            } else {
                // Non-initial fragments rely on FragmentDecisionEngine's cached first-fragment decision;
                // orphan fragments without a cached decision must be evaluated with failClosedOnUnknownUid = true.
                evaluatePacket(rawMetadata) == FirewallAction.ALLOW
            }
        } catch (_: Throwable) {
            false
        }

        override fun protectSocket(fd: Int): Boolean = try {
            fd >= 0 && socketProtector(fd)
        } catch (_: Throwable) {
            false
        }

        override fun onFatalError(reason: String) {
            runCatching { this@OutlinePacketForwarder.onFatalError(reason) }
        }
    }

    private fun decodeAddress(ipVersion: Int, rawBytes: ByteArray): InetAddress? = when (ipVersion) {
        4 -> if (rawBytes.size == 4) InetAddress.getByAddress(rawBytes) else null
        6 -> if (rawBytes.size == 16) Inet6Address.getByAddress(null, rawBytes, -1) else null
        else -> null
    }

    companion object {
        private const val NO_HANDLE = 0L
        const val DEFAULT_MAX_TCP_STREAMS = 256
        const val DEFAULT_MAX_UDP_ASSOCIATIONS = 256
        const val DEFAULT_UDP_IDLE_TIMEOUT_MILLIS = 60_000
    }
}
