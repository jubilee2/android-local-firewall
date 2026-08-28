package com.localfirewall.app.network.outline

import org.junit.Assert.assertEquals
import org.junit.Assert.assertSame
import org.junit.Test

class OutlineForwarderProbeTest {
    @Test
    fun `expected native build is available`() {
        val loaded = mutableListOf<String>()
        val probe = OutlineForwarderProbe(
            libraryLoader = NativeLibraryLoader(loaded::add),
            probeCall = NativeProbeCall { EXPECTED_OUTLINE_PROBE },
        )

        assertEquals(OutlineProbeResult.Available(EXPECTED_OUTLINE_PROBE), probe.check())
        assertEquals(listOf("outline_forwarder_probe"), loaded)
    }

    @Test
    fun `native load failure fails safely`() {
        val probe = OutlineForwarderProbe(
            libraryLoader = NativeLibraryLoader { throw UnsatisfiedLinkError("unsupported ABI") },
            probeCall = NativeProbeCall { error("must not call JNI") },
        )

        assertSame(OutlineProbeResult.Unavailable, probe.check())
    }

    @Test
    fun `unexpected native build fails safely`() {
        val probe = OutlineForwarderProbe(
            libraryLoader = NativeLibraryLoader { },
            probeCall = NativeProbeCall { "unexpected" },
        )

        assertSame(OutlineProbeResult.Unavailable, probe.check())
    }
}
