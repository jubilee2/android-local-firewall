package com.localfirewall.app.network.outline

internal const val EXPECTED_OUTLINE_PROBE =
    "outline-sdk@6f5902f532d67ffde0c02f9ec19bb176d859f173;lwip2transport;jni-v1"

internal fun interface NativeLibraryLoader {
    fun load(name: String)
}

internal fun interface NativeProbeCall {
    fun probe(): String
}

internal sealed interface OutlineProbeResult {
    data class Available(val build: String) : OutlineProbeResult
    data object Unavailable : OutlineProbeResult
}

internal class OutlineForwarderProbe(
    private val libraryLoader: NativeLibraryLoader = NativeLibraryLoader(System::loadLibrary),
    private val probeCall: NativeProbeCall = NativeProbeCall(JniOutlineForwarderProbe::nativeProbe),
) {
    fun check(): OutlineProbeResult =
        try {
            libraryLoader.load(LIBRARY_NAME)
            val build = probeCall.probe()
            if (build == EXPECTED_OUTLINE_PROBE) {
                OutlineProbeResult.Available(build)
            } else {
                OutlineProbeResult.Unavailable
            }
        } catch (_: LinkageError) {
            OutlineProbeResult.Unavailable
        }

    private companion object {
        const val LIBRARY_NAME = "outline_forwarder_probe"
    }
}

internal object JniOutlineForwarderProbe {
    external fun nativeProbe(): String
}
