package com.localfirewall.app.network.outline

import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertEquals
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class OutlineForwarderProbeInstrumentedTest {
    @Test
    fun packagedNativeComponentLoadsAndAnswers() {
        assertEquals(
            OutlineProbeResult.Available(EXPECTED_OUTLINE_PROBE),
            OutlineForwarderProbe().check(),
        )
    }
}
