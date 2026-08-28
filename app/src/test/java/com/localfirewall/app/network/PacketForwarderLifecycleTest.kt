package com.localfirewall.app.network

import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PacketForwarderLifecycleTest {
    @Test
    fun `start starts created forwarder`() {
        val forwarder = RecordingForwarder()
        val lifecycle = PacketForwarderLifecycle { forwarder }

        lifecycle.start()

        assertEquals(1, forwarder.startCount)
    }

    @Test
    fun `repeated start is ignored`() {
        val forwarder = RecordingForwarder()
        var createCount = 0
        val lifecycle = PacketForwarderLifecycle {
            createCount += 1
            forwarder
        }

        lifecycle.start()
        lifecycle.start()

        assertEquals(1, createCount)
        assertEquals(1, forwarder.startCount)
    }

    @Test
    fun `stop stops active forwarder`() {
        val forwarder = RecordingForwarder()
        val lifecycle = PacketForwarderLifecycle { forwarder }
        lifecycle.start()

        lifecycle.stop()

        assertEquals(1, forwarder.stopCount)
    }

    @Test
    fun `repeated stop is ignored`() {
        val forwarder = RecordingForwarder()
        val lifecycle = PacketForwarderLifecycle { forwarder }
        lifecycle.start()

        lifecycle.stop()
        lifecycle.stop()

        assertEquals(1, forwarder.stopCount)
    }

    @Test
    fun `failed start cleans candidate and permits retry`() {
        val failed = RecordingForwarder(startFailure = IllegalStateException("not ready"))
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        val lifecycle = PacketForwarderLifecycle { candidates.removeFirst() }

        assertThrows(IllegalStateException::class.java) { lifecycle.start() }
        lifecycle.start()

        assertEquals(1, failed.stopCount)
        assertEquals(1, replacement.startCount)
    }

    @Test
    fun `stop failure still permits a new forwarder`() {
        val failed = RecordingForwarder(stopFailure = IllegalStateException("stop failed"))
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        val lifecycle = PacketForwarderLifecycle { candidates.removeFirst() }
        lifecycle.start()

        lifecycle.stop()
        lifecycle.start()

        assertEquals(1, failed.stopCount)
        assertEquals(1, replacement.startCount)
    }

    private class RecordingForwarder(
        private val startFailure: Throwable? = null,
        private val stopFailure: Throwable? = null,
    ) : PacketForwarder {
        var startCount = 0
        var stopCount = 0

        override fun start() {
            startCount += 1
            startFailure?.let { throw it }
        }

        override fun stop() {
            stopCount += 1
            stopFailure?.let { throw it }
        }
    }
}
