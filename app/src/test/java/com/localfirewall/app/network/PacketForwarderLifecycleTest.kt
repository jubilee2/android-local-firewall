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
    fun `linkage failure during start cleans candidate and permits retry`() {
        val failed = RecordingForwarder(startFailure = UnsatisfiedLinkError("native library missing"))
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        val lifecycle = PacketForwarderLifecycle { candidates.removeFirst() }

        assertThrows(UnsatisfiedLinkError::class.java) { lifecycle.start() }
        lifecycle.start()

        assertEquals(1, failed.stopCount)
        assertEquals(1, replacement.startCount)
    }

    @Test
    fun `stop failure retains forwarder until cleanup retry succeeds`() {
        val failed = RecordingForwarder(
            stopFailures = ArrayDeque(listOf(IllegalStateException("stop failed"))),
        )
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        val lifecycle = PacketForwarderLifecycle { candidates.removeFirst() }
        lifecycle.start()

        assertThrows(IllegalStateException::class.java) { lifecycle.stop() }
        lifecycle.start()

        assertEquals(1, failed.startCount)
        assertEquals(0, replacement.startCount)

        lifecycle.stop()
        lifecycle.start()

        assertEquals(2, failed.stopCount)
        assertEquals(1, replacement.startCount)
    }

    @Test
    fun `failed startup retains ownership until failed cleanup can be retried`() {
        val startupFailure = UnsatisfiedLinkError("not ready")
        val cleanupFailure = IllegalStateException("still running")
        val failed = RecordingForwarder(
            startFailure = startupFailure,
            stopFailures = ArrayDeque(listOf(cleanupFailure)),
        )
        val replacement = RecordingForwarder()
        var createCount = 0
        val lifecycle = PacketForwarderLifecycle {
            createCount += 1
            if (createCount == 1) failed else replacement
        }

        val thrown = assertThrows(UnsatisfiedLinkError::class.java) { lifecycle.start() }
        assertEquals(startupFailure, thrown)
        assertEquals(listOf(cleanupFailure), thrown.suppressed.toList())
        lifecycle.start()
        assertEquals(1, createCount)
        assertEquals(0, replacement.startCount)

        lifecycle.stop()
        lifecycle.start()
        assertEquals(2, failed.stopCount)
        assertEquals(2, createCount)
        assertEquals(1, replacement.startCount)
    }

    @Test
    fun `same startup and cleanup throwable does not mask startup failure`() {
        val failure = IllegalStateException("shared failure")
        val failed = RecordingForwarder(
            startFailure = failure,
            stopFailures = ArrayDeque(listOf(failure)),
        )
        val lifecycle = PacketForwarderLifecycle { failed }

        assertEquals(failure, assertThrows(IllegalStateException::class.java) { lifecycle.start() })
        lifecycle.stop()
        assertEquals(2, failed.stopCount)
    }

    private class RecordingForwarder(
        private val startFailure: Throwable? = null,
        private val stopFailures: ArrayDeque<Throwable> = ArrayDeque(),
    ) : PacketForwarder {
        var startCount = 0
        var stopCount = 0

        override fun start() {
            startCount += 1
            startFailure?.let { throw it }
        }

        override fun stop() {
            stopCount += 1
            if (stopFailures.isNotEmpty()) throw stopFailures.removeFirst()
        }
    }
}
