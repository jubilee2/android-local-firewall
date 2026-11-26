package com.localfirewall.app.network

import java.io.IOException
import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
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
    fun `failed start with failed cleanup retains candidate and preserves diagnostics`() {
        val startFailure = IllegalStateException("not ready")
        val cleanupFailure = IOException("failed closing native handle")
        val failed = RecordingForwarder(
            startFailure = startFailure,
            stopFailures = ArrayDeque(listOf(cleanupFailure)),
        )
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        var createCount = 0
        val lifecycle = PacketForwarderLifecycle {
            createCount += 1
            candidates.removeFirst()
        }

        val thrown = assertThrows(IllegalStateException::class.java) { lifecycle.start() }
        assertSame(startFailure, thrown)
        assertEquals(listOf<Throwable>(cleanupFailure), thrown.suppressed.toList())

        val retryFailure = assertThrows(IllegalStateException::class.java) { lifecycle.start() }
        assertSame(cleanupFailure, retryFailure.cause)
        assertThrows(IllegalStateException::class.java) { lifecycle.start() }

        assertEquals(1, createCount)
        assertEquals(1, failed.startCount)
        assertEquals(1, failed.stopCount)
        assertEquals(0, replacement.startCount)

        lifecycle.stop()
        lifecycle.start()

        assertEquals(2, createCount)
        assertEquals(2, failed.stopCount)
        assertEquals(1, replacement.startCount)
    }

    @Test
    fun `linkage failure with repeated cleanup failures retains candidate until stop succeeds`() {
        val startFailure = UnsatisfiedLinkError("symbol missing")
        val firstCleanupFailure = IllegalStateException("worker join timed out")
        val secondCleanupFailure = IOException("descriptor still busy")
        val failed = RecordingForwarder(
            startFailure = startFailure,
            stopFailures = ArrayDeque(listOf(firstCleanupFailure, secondCleanupFailure)),
        )
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        var createCount = 0
        val lifecycle = PacketForwarderLifecycle {
            createCount += 1
            candidates.removeFirst()
        }

        val thrown = assertThrows(UnsatisfiedLinkError::class.java) { lifecycle.start() }
        assertSame(startFailure, thrown)
        assertEquals(listOf<Throwable>(firstCleanupFailure), thrown.suppressed.toList())

        val firstStopRetry = assertThrows(IOException::class.java) { lifecycle.stop() }
        assertSame(secondCleanupFailure, firstStopRetry)

        val blockedStart = assertThrows(IllegalStateException::class.java) { lifecycle.start() }
        assertSame(secondCleanupFailure, blockedStart.cause)
        assertEquals(1, createCount)
        assertEquals(0, replacement.startCount)

        lifecycle.stop()
        lifecycle.start()

        assertEquals(2, createCount)
        assertEquals(3, failed.stopCount)
        assertEquals(1, replacement.startCount)
    }

    @Test
    fun `failed start throwing identical cleanup failure avoids self suppression`() {
        val sharedFailure = IllegalStateException("shared failure")
        val failed = RecordingForwarder(
            startFailure = sharedFailure,
            stopFailures = ArrayDeque(listOf(sharedFailure)),
        )
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        var createCount = 0
        val lifecycle = PacketForwarderLifecycle {
            createCount += 1
            candidates.removeFirst()
        }

        val thrown = assertThrows(IllegalStateException::class.java) { lifecycle.start() }
        assertSame(sharedFailure, thrown)
        assertEquals(emptyList<Throwable>(), thrown.suppressed.toList())
        assertThrows(IllegalStateException::class.java) { lifecycle.start() }
        assertEquals(1, createCount)

        lifecycle.stop()
        lifecycle.start()

        assertEquals(2, createCount)
        assertEquals(1, replacement.startCount)
    }

    @Test
    fun `stop failure retains forwarder until cleanup retry succeeds`() {
        val stopFailure = IllegalStateException("stop failed")
        val failed = RecordingForwarder(
            stopFailures = ArrayDeque(listOf(stopFailure)),
        )
        val replacement = RecordingForwarder()
        val candidates = ArrayDeque(listOf(failed, replacement))
        var createCount = 0
        val lifecycle = PacketForwarderLifecycle {
            createCount += 1
            candidates.removeFirst()
        }
        lifecycle.start()

        assertThrows(IllegalStateException::class.java) { lifecycle.stop() }
        val retryFailure = assertThrows(IllegalStateException::class.java) { lifecycle.start() }
        assertSame(stopFailure, retryFailure.cause)

        assertEquals(1, createCount)
        assertEquals(1, failed.startCount)
        assertEquals(0, replacement.startCount)

        lifecycle.stop()
        lifecycle.start()

        assertEquals(2, createCount)
        assertEquals(2, failed.stopCount)
        assertEquals(1, replacement.startCount)
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
