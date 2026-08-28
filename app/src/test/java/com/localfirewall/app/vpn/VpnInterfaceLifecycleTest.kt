package com.localfirewall.app.vpn

import java.io.Closeable
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class VpnInterfaceLifecycleTest {
    @Test
    fun `establish retains only one interface`() {
        val lifecycle = VpnInterfaceLifecycle<Closeable>()
        val first = RecordingCloseable()
        var creations = 0

        val established = lifecycle.establish {
            creations += 1
            first
        }
        val repeated = lifecycle.establish {
            creations += 1
            RecordingCloseable()
        }

        assertSame(first, established)
        assertSame(first, repeated)
        assertEquals(1, creations)
    }

    @Test
    fun `close releases retained interface`() {
        val lifecycle = VpnInterfaceLifecycle<Closeable>()
        val handle = RecordingCloseable()
        lifecycle.establish { handle }

        lifecycle.close()

        assertEquals(1, handle.closeCount)
    }

    @Test
    fun `close can safely run more than once`() {
        val lifecycle = VpnInterfaceLifecycle<Closeable>()
        val handle = RecordingCloseable()
        lifecycle.establish { handle }

        lifecycle.close()
        lifecycle.close()

        assertEquals(1, handle.closeCount)
    }

    @Test
    fun `null interface is not retained`() {
        val lifecycle = VpnInterfaceLifecycle<Closeable>()

        assertNull(lifecycle.establish { null })
        lifecycle.close()
    }

    @Test
    fun `close failure still releases retained interface`() {
        val lifecycle = VpnInterfaceLifecycle<Closeable>()
        var creations = 0
        lifecycle.establish { Closeable { error("close failed") } }

        lifecycle.close()
        lifecycle.establish {
            creations += 1
            RecordingCloseable()
        }

        assertEquals(1, creations)
    }

    private class RecordingCloseable : Closeable {
        var closeCount = 0

        override fun close() {
            closeCount += 1
        }
    }
}
