package com.localfirewall.app.network.outline

import android.os.Process
import android.system.ErrnoException
import android.system.Os
import android.system.OsConstants
import android.system.StructPollfd
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.localfirewall.app.BuildConfig
import com.localfirewall.app.firewall.ConnectionOwnerLookup
import com.localfirewall.app.firewall.ConnectionOwnerResolver
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.FirewallRule
import com.localfirewall.app.firewall.FragmentDecisionEngine
import com.localfirewall.app.firewall.RuleEngine
import com.localfirewall.app.network.PacketForwarderLifecycle
import com.localfirewall.app.network.TransportProtocol
import java.io.FileDescriptor
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.ByteBuffer
import java.util.Collections
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OutlineForwarderInstrumentedTest {
    @Test
    fun jniBridgeLoadsVerifiedPinnedLwip2TransportMetadata() {
        val metadata = OutlineBridgeMetadata.fromJson(OutlineNativeBridge.metadataJson())
        metadata.validateAgainstPin(BuildConfig.OUTLINE_SDK_COMMIT)
        assertEquals(BuildConfig.OUTLINE_SDK_COMMIT, metadata.pinnedOutlineCommit)
        assertEquals("golang.getoutline.org/sdk", metadata.outlineModulePath)
        assertEquals("github.com/eycorsican/go-tun2socks", metadata.lwipModulePath)
    }

    @Test
    fun directTcpAndUdpForwardingProtectBeforeIoAndFailClosedEnforcementOnAndroid() {
        val udpServer = DatagramSocket(0, InetAddress.getByName("127.0.0.1"))
        val tcpServer = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))
        val blockedTcpServer = ServerSocket(0, 8, InetAddress.getByName("127.0.0.1"))

        val udpEchoThread = Thread {
            runCatching {
                val buf = ByteArray(1024)
                val pkt = DatagramPacket(buf, buf.size)
                udpServer.receive(pkt)
                val reply = "android-udp-ok:".toByteArray() + pkt.data.copyOf(pkt.length)
                udpServer.send(DatagramPacket(reply, reply.size, pkt.address, pkt.port))
            }
        }.apply { start() }

        val tcpAcceptedCount = AtomicInteger(0)
        val tcpEchoThread = Thread {
            runCatching {
                tcpServer.accept().use { sock ->
                    tcpAcceptedCount.incrementAndGet()
                    val buf = ByteArray(64)
                    val read = sock.getInputStream().read(buf)
                    if (read > 0) {
                        sock.getOutputStream().write("android-tcp-ok:".toByteArray() + buf.copyOf(read))
                        sock.getOutputStream().flush()
                    }
                }
            }
        }.apply { start() }

        val blockedAcceptedCount = AtomicInteger(0)
        Thread {
            runCatching {
                blockedTcpServer.accept().use {
                    blockedAcceptedCount.incrementAndGet()
                }
            }
        }.start()

        val appFd = FileDescriptor()
        val tunFd = FileDescriptor()
        Os.socketpair(OsConstants.AF_UNIX, OsConstants.SOCK_DGRAM, 0, appFd, tunFd)
        val tunPfd = android.os.ParcelFileDescriptor.dup(tunFd)

        val events = Collections.synchronizedList(ArrayList<String>())
        val allowSocketProtect = AtomicBoolean(true)
        val currentOwnerUid = AtomicInteger(10555)
        val failedProtectLatch = CountDownLatch(1)

        val rules = listOf(
            FirewallRule(
                action = FirewallAction.BLOCK,
                protocol = TransportProtocol.TCP,
                destinationPort = blockedTcpServer.localPort,
            ),
        )
        val fragmentEngine = FragmentDecisionEngine(
            RuleEngine(
                rules = rules,
                defaultAction = FirewallAction.ALLOW,
                failClosedOnUnknownUid = true,
            ),
        )

        val lifecycle = PacketForwarderLifecycle {
            OutlinePacketForwarder(
                tunFdProvider = { tunPfd.fd },
                connectionOwnerResolver = ConnectionOwnerResolver(
                    lookup = ConnectionOwnerLookup { _, _, remote ->
                        events.add("admit:${remote.port}")
                        currentOwnerUid.get()
                    },
                ),
                evaluatePacket = fragmentEngine::evaluate,
                socketProtector = { fd ->
                    val unconnectedBeforeIo = try {
                        android.os.ParcelFileDescriptor.fromFd(fd).use { dupPfd ->
                            Os.getpeername(dupPfd.fileDescriptor)
                        }
                        false
                    } catch (err: ErrnoException) {
                        err.errno == OsConstants.ENOTCONN
                    }
                    events.add(if (unconnectedBeforeIo) "protect-before-io" else "protect-too-late")
                    val decision = allowSocketProtect.get()
                    if (!decision) {
                        failedProtectLatch.countDown()
                    }
                    decision
                },
                udpIdleTimeoutMillis = 5_000,
            )
        }

        try {
            lifecycle.start()

            // 1. Direct original-destination UDP relay over Android JNI.
            val udpReq = buildIpv4UdpPacket(
                srcPort = 52001,
                dstPort = udpServer.localPort,
                payload = "ping64".toByteArray(),
            )
            Os.write(appFd, udpReq, 0, udpReq.size)
            val udpResp = pollReadPacket(appFd, timeoutMillis = 3_000)
            assertArrayEquals(
                "android-udp-ok:ping64".toByteArray(),
                udpResp.copyOfRange(28, udpResp.size),
            )

            // 2. Direct original-destination TCP handshake & payload relay over Android JNI.
            val syn = buildIpv4TcpPacket(srcPort = 52002, dstPort = tcpServer.localPort, seq = 500L, ack = 0L, flags = 0x02, payload = ByteArray(0))
            Os.write(appFd, syn, 0, syn.size)
            val synAck = pollReadPacket(appFd, timeoutMillis = 3_000)
            val serverSeq = ByteBuffer.wrap(synAck, 24, 4).int.toLong() and 0xffffffffL
            assertEquals(0x12, synAck[33].toInt() and 0x12)

            val ack = buildIpv4TcpPacket(srcPort = 52002, dstPort = tcpServer.localPort, seq = 501L, ack = serverSeq + 1, flags = 0x10, payload = ByteArray(0))
            Os.write(appFd, ack, 0, ack.size)
            val psh = buildIpv4TcpPacket(srcPort = 52002, dstPort = tcpServer.localPort, seq = 501L, ack = serverSeq + 1, flags = 0x18, payload = "hi".toByteArray())
            Os.write(appFd, psh, 0, psh.size)

            var collectedTcp = ByteArray(0)
            val deadline = System.currentTimeMillis() + 3_000L
            while (System.currentTimeMillis() < deadline && !collectedTcp.contentEquals("android-tcp-ok:hi".toByteArray())) {
                val pkt = pollReadPacket(appFd, timeoutMillis = 1_500)
                val ihl = (pkt[0].toInt() and 0x0f) * 4
                val dataOff = ((pkt[ihl + 12].toInt() and 0xff) ushr 4) * 4
                if (pkt.size > ihl + dataOff) {
                    collectedTcp += pkt.copyOfRange(ihl + dataOff, pkt.size)
                }
            }
            assertArrayEquals("android-tcp-ok:hi".toByteArray(), collectedTcp)

            assertTrue("Expected protect-before-io in $events", "protect-before-io" in events)
            assertTrue("Unexpected protect-too-late in $events", "protect-too-late" !in events)

            // 3. BLOCK rule opens zero outbound sockets.
            val eventsBeforeBlock = events.count { it.startsWith("protect") }
            val blockedSyn = buildIpv4TcpPacket(srcPort = 52003, dstPort = blockedTcpServer.localPort, seq = 1L, ack = 0L, flags = 0x02, payload = ByteArray(0))
            Os.write(appFd, blockedSyn, 0, blockedSyn.size)
            Thread.sleep(150)
            assertEquals(eventsBeforeBlock, events.count { it.startsWith("protect") })
            assertEquals(0, blockedAcceptedCount.get())

            // 4. Unknown UID (INVALID_UID) fails closed without creating sockets.
            currentOwnerUid.set(Process.INVALID_UID)
            val unknownUidUdp = buildIpv4UdpPacket(srcPort = 52004, dstPort = udpServer.localPort, payload = "drop".toByteArray())
            Os.write(appFd, unknownUidUdp, 0, unknownUidUdp.size)
            Thread.sleep(150)
            assertEquals(eventsBeforeBlock, events.count { it.startsWith("protect") })

            // 5. Failed protectSocket(fd) == false closes socket and fails flow closed.
            currentOwnerUid.set(10555)
            allowSocketProtect.set(false)
            val failProtectUdp = buildIpv4UdpPacket(srcPort = 52005, dstPort = udpServer.localPort, payload = "unprotected".toByteArray())
            Os.write(appFd, failProtectUdp, 0, failProtectUdp.size)
            assertTrue("Expected failed protect callback", failedProtectLatch.await(3, TimeUnit.SECONDS))
        } finally {
            lifecycle.stop()
            lifecycle.stop() // Verify idempotent shutdown on Android runtime.
            runCatching { tunPfd.close() }
            runCatching { Os.close(appFd) }
            runCatching { Os.close(tunFd) }
            runCatching { udpServer.close() }
            runCatching { tcpServer.close() }
            runCatching { blockedTcpServer.close() }
            udpEchoThread.join(1_000)
            tcpEchoThread.join(1_000)
        }
    }

    private fun pollReadPacket(fd: FileDescriptor, timeoutMillis: Int): ByteArray {
        val pollfd = StructPollfd().apply {
            this.fd = fd
            this.events = OsConstants.POLLIN.toShort()
        }
        val ready = Os.poll(arrayOf(pollfd), timeoutMillis)
        check(ready > 0) { "Timed out waiting for response packet from lwip2transport" }
        val buf = ByteArray(4096)
        val len = Os.read(fd, buf, 0, buf.size)
        check(len > 0) { "Unexpected EOF reading response packet" }
        return buf.copyOf(len)
    }

    private fun buildIpv4UdpPacket(srcPort: Int, dstPort: Int, payload: ByteArray): ByteArray {
        val udpLen = 8 + payload.size
        val totalLen = 20 + udpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xff).toByte()
        pkt[3] = (totalLen and 0xff).toByte()
        pkt[6] = 0x40
        pkt[8] = 64
        pkt[9] = 17
        byteArrayOf(10, 0, 0, 2).copyInto(pkt, 12)
        byteArrayOf(127, 0, 0, 1).copyInto(pkt, 16)
        val ipCsum = ipv4Checksum(pkt, 0, 20)
        pkt[10] = ((ipCsum ushr 8) and 0xff).toByte()
        pkt[11] = (ipCsum and 0xff).toByte()

        pkt[20] = ((srcPort ushr 8) and 0xff).toByte()
        pkt[21] = (srcPort and 0xff).toByte()
        pkt[22] = ((dstPort ushr 8) and 0xff).toByte()
        pkt[23] = (dstPort and 0xff).toByte()
        pkt[24] = ((udpLen ushr 8) and 0xff).toByte()
        pkt[25] = (udpLen and 0xff).toByte()
        payload.copyInto(pkt, 28)
        val udpCsum = transportChecksum(pkt, 20, udpLen, 17)
        pkt[26] = ((udpCsum ushr 8) and 0xff).toByte()
        pkt[27] = (udpCsum and 0xff).toByte()
        return pkt
    }

    private fun buildIpv4TcpPacket(
        srcPort: Int,
        dstPort: Int,
        seq: Long,
        ack: Long,
        flags: Int,
        payload: ByteArray,
    ): ByteArray {
        val tcpLen = 20 + payload.size
        val totalLen = 20 + tcpLen
        val pkt = ByteArray(totalLen)
        pkt[0] = 0x45
        pkt[2] = ((totalLen ushr 8) and 0xff).toByte()
        pkt[3] = (totalLen and 0xff).toByte()
        pkt[6] = 0x40
        pkt[8] = 64
        pkt[9] = 6
        byteArrayOf(10, 0, 0, 2).copyInto(pkt, 12)
        byteArrayOf(127, 0, 0, 1).copyInto(pkt, 16)
        val ipCsum = ipv4Checksum(pkt, 0, 20)
        pkt[10] = ((ipCsum ushr 8) and 0xff).toByte()
        pkt[11] = (ipCsum and 0xff).toByte()

        ByteBuffer.wrap(pkt, 20, 20).apply {
            putShort(srcPort.toShort())
            putShort(dstPort.toShort())
            putInt(seq.toInt())
            putInt(ack.toInt())
            put((5 shl 4).toByte())
            put(flags.toByte())
            putShort(65535.toShort())
            putShort(0)
            putShort(0)
        }
        payload.copyInto(pkt, 40)
        val tcpCsum = transportChecksum(pkt, 20, tcpLen, 6)
        pkt[36] = ((tcpCsum ushr 8) and 0xff).toByte()
        pkt[37] = (tcpCsum and 0xff).toByte()
        return pkt
    }

    private fun ipv4Checksum(buf: ByteArray, offset: Int, length: Int): Int {
        var sum = 0L
        var i = 0
        while (i + 1 < length) {
            sum += ((buf[offset + i].toInt() and 0xff) shl 8) or (buf[offset + i + 1].toInt() and 0xff)
            i += 2
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xffffL) + (sum ushr 16)
        }
        return (sum.inv() and 0xffffL).toInt()
    }

    private fun transportChecksum(pkt: ByteArray, offset: Int, segLen: Int, proto: Int): Int {
        var sum = 0L
        for (i in 12..18 step 2) {
            sum += ((pkt[i].toInt() and 0xff) shl 8) or (pkt[i + 1].toInt() and 0xff)
        }
        sum += proto.toLong() + segLen.toLong()
        var i = 0
        while (i + 1 < segLen) {
            sum += ((pkt[offset + i].toInt() and 0xff) shl 8) or (pkt[offset + i + 1].toInt() and 0xff)
            i += 2
        }
        if (segLen % 2 == 1) {
            sum += (pkt[offset + segLen - 1].toInt() and 0xff) shl 8
        }
        while ((sum ushr 16) != 0L) {
            sum = (sum and 0xffffL) + (sum ushr 16)
        }
        val csum = (sum.inv() and 0xffffL).toInt()
        return if (proto == 17 && csum == 0) 0xffff else csum
    }
}
