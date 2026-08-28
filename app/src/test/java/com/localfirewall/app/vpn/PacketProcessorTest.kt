package com.localfirewall.app.vpn

import java.io.IOException
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import kotlinx.coroutines.Dispatchers
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class PacketProcessorTest {
    @Test
    fun `one packet is passed to the handler`() {
        val packets = mutableListOf<ByteArray>()
        val processor = processor(SequenceSource(listOf(byteArrayOf(1, 2, 3))), packets::add)

        processor.start()
        awaitStopped(processor)

        assertEquals(1, packets.size)
        assertArrayEquals(byteArrayOf(1, 2, 3), packets.single())
    }

    @Test
    fun `multiple packets are processed sequentially using only bytes read`() {
        val packets = mutableListOf<ByteArray>()
        val processor = processor(
            SequenceSource(listOf(byteArrayOf(1, 2, 3, 4), byteArrayOf(9))),
            packets::add,
        )

        processor.start()
        awaitStopped(processor)

        assertEquals(2, packets.size)
        assertArrayEquals(byteArrayOf(1, 2, 3, 4), packets[0])
        assertArrayEquals(byteArrayOf(9), packets[1])
    }

    @Test
    fun `malformed packets do not prevent later packets from being read`() {
        val reads = AtomicInteger()
        val processor = processor(
            SequenceSource(listOf(byteArrayOf(0), validIpv4Packet())),
        ) { packet ->
            reads.incrementAndGet()
            // Exercise the production parser path without assuming every packet is valid.
            com.localfirewall.app.network.IPv4PacketParser.parse(packet)
        }

        processor.start()
        awaitStopped(processor)

        assertEquals(2, reads.get())
    }

    @Test
    fun `stop cancels blocked reading and is safe when repeated`() {
        val source = BlockingSource()
        val handled = AtomicInteger()
        val processor = processor(source) { handled.incrementAndGet() }
        processor.start()
        assertTrue(source.readStarted.await(1, TimeUnit.SECONDS))

        processor.close()
        assertFalse(processor.isRunning())

        // Cancellation is deliberately non-blocking; the owning TUN resource must be closed too.
        source.close()
        assertTrue(source.readExited.await(1, TimeUnit.SECONDS))
        processor.close()

        assertFalse(processor.isRunning())
        assertEquals(1, source.closeCount.get())
        assertEquals(0, handled.get())
    }

    @Test
    fun `EOF exits without continuing the worker`() {
        val processor = processor(SequenceSource(emptyList())) {}

        processor.start()
        awaitStopped(processor)

        assertFalse(processor.isRunning())
    }

    private fun processor(source: PacketSource, handler: (ByteArray) -> Unit): PacketProcessor =
        PacketProcessor(source, handler, Dispatchers.IO, bufferSize = 64)

    private fun awaitStopped(processor: PacketProcessor) {
        repeat(100) {
            if (!processor.isRunning()) return
            Thread.sleep(10)
        }
        error("packet processor did not stop")
    }

    private class SequenceSource(private val packets: List<ByteArray>) : PacketSource {
        private var index = 0

        override fun read(buffer: ByteArray): Int {
            if (index == packets.size) return -1
            val packet = packets[index++]
            packet.copyInto(buffer)
            return packet.size
        }
    }

    private class BlockingSource : PacketSource {
        val readStarted = CountDownLatch(1)
        val readExited = CountDownLatch(1)
        val closeCount = AtomicInteger()
        private val closed = CountDownLatch(1)

        override fun read(buffer: ByteArray): Int {
            readStarted.countDown()
            closed.await()
            readExited.countDown()
            throw IOException("closed")
        }

        override fun close() {
            if (closed.count == 1L) {
                closeCount.incrementAndGet()
                closed.countDown()
            }
        }
    }

    private fun validIpv4Packet(): ByteArray = ByteArray(20).also {
        it[0] = 0x45
        it[2] = 0
        it[3] = 20
    }
}
