package com.localfirewall.app.network.outline

/**
 * Synchronous callbacks invoked from the native Outline/lwIP forwarder before flow admission or
 * outbound socket I/O.
 */
interface NativeForwarderCallbacks {
    fun admitPacket(
        ipVersion: Int,
        protocol: Int,
        sourceAddress: ByteArray,
        sourcePort: Int,
        destinationAddress: ByteArray,
        destinationPort: Int,
        identification: Int,
        fragmentOffset: Int,
        moreFragments: Boolean,
    ): Boolean

    fun protectSocket(fd: Int): Boolean

    fun onFatalError(reason: String)
}

/** Build-pinned and Go `debug.ReadBuildInfo()` module metadata reported by `liboutline_forwarder.so`. */
data class OutlineBridgeMetadata(
    val pinnedOutlineCommit: String,
    val outlineModulePath: String,
    val outlineVersion: String,
    val outlineSum: String,
    val lwipModulePath: String,
    val lwipVersion: String,
    val lwipSum: String,
    val goVersion: String,
) {
    fun validateAgainstPin(expectedOutlineCommit: String) {
        require(expectedOutlineCommit.length == 40 && expectedOutlineCommit.all { it in '0'..'9' || it in 'a'..'f' }) {
            "Expected 40-char lowercase hex Outline SDK commit pin"
        }
        check(pinnedOutlineCommit == expectedOutlineCommit) {
            "Native Outline commit '${pinnedOutlineCommit}' does not match pinned commit '$expectedOutlineCommit'"
        }
        check(outlineModulePath == EXPECTED_OUTLINE_MODULE) {
            "Unexpected Outline module path '$outlineModulePath'"
        }
        val shortCommit = expectedOutlineCommit.take(12)
        check(outlineVersion.endsWith("-$shortCommit")) {
            "Compiled Outline module version '$outlineVersion' does not end with '-$shortCommit'"
        }
        check(outlineSum.startsWith("h1:")) {
            "Missing cryptographic Go module sum for Outline SDK"
        }
        check(lwipModulePath == EXPECTED_LWIP_MODULE && lwipSum.startsWith("h1:")) {
            "Missing verified go-tun2socks/lwIP compiled dependency metadata"
        }
    }

    companion object {
        const val EXPECTED_OUTLINE_MODULE = "golang.getoutline.org/sdk"
        const val EXPECTED_LWIP_MODULE = "github.com/eycorsican/go-tun2socks"

        private val STRING_FIELD_PATTERN = Regex(""""([^"]+)"\s*:\s*"((?:\\.|[^"\\])*)"""")

        /** Parses flat JSON object returned by `nativeMetadata()` without Android framework stubs. */
        fun fromJson(json: String): OutlineBridgeMetadata {
            val fields = HashMap<String, String>()
            for (match in STRING_FIELD_PATTERN.findAll(json)) {
                fields[match.groupValues[1]] = match.groupValues[2]
                    .replace("\\\"", "\"")
                    .replace("\\\\", "\\")
            }
            return OutlineBridgeMetadata(
                pinnedOutlineCommit = fields["pinnedOutlineCommit"].orEmpty(),
                outlineModulePath = fields["outlineModulePath"].orEmpty(),
                outlineVersion = fields["outlineVersion"].orEmpty(),
                outlineSum = fields["outlineSum"].orEmpty(),
                lwipModulePath = fields["lwipModulePath"].orEmpty(),
                lwipVersion = fields["lwipVersion"].orEmpty(),
                lwipSum = fields["lwipSum"].orEmpty(),
                goVersion = fields["goVersion"].orEmpty(),
            )
        }
    }
}

/** Injectable JNI boundary so [OutlinePacketForwarder] can be unit-tested on the host JVM. */
internal interface OutlineNativeApi {
    fun metadataJson(): String

    fun start(
        tunFd: Int,
        callbacks: NativeForwarderCallbacks,
        maxTcpStreams: Int,
        maxUdpAssociations: Int,
        udpIdleTimeoutMillis: Int,
    ): Long

    fun stop(handle: Long)
}

/** Production JNI wrapper loading `liboutline_forwarder.so`. */
object OutlineNativeBridge : OutlineNativeApi {
    private const val LIBRARY_NAME = "outline_forwarder"

    @Volatile
    private var loaded = false

    private fun ensureLoaded() {
        if (loaded) return
        synchronized(this) {
            if (!loaded) {
                System.loadLibrary(LIBRARY_NAME)
                loaded = true
            }
        }
    }

    override fun metadataJson(): String {
        ensureLoaded()
        return nativeMetadata()
    }

    override fun start(
        tunFd: Int,
        callbacks: NativeForwarderCallbacks,
        maxTcpStreams: Int,
        maxUdpAssociations: Int,
        udpIdleTimeoutMillis: Int,
    ): Long {
        ensureLoaded()
        return nativeStart(
            tunFd = tunFd,
            callbacks = callbacks,
            maxTcpStreams = maxTcpStreams,
            maxUdpAssociations = maxUdpAssociations,
            udpIdleTimeoutMillis = udpIdleTimeoutMillis,
        )
    }

    override fun stop(handle: Long) {
        ensureLoaded()
        nativeStop(handle)
    }

    @JvmStatic
    private external fun nativeMetadata(): String

    @JvmStatic
    private external fun nativeStart(
        tunFd: Int,
        callbacks: NativeForwarderCallbacks,
        maxTcpStreams: Int,
        maxUdpAssociations: Int,
        udpIdleTimeoutMillis: Int,
    ): Long

    @JvmStatic
    private external fun nativeStop(handle: Long)
}
