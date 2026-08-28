package com.localfirewall.app.network

/**
 * Owns the future userspace network stack that forwards packets from the VPN TUN interface.
 *
 * Implementations must not return from [start] until their resources are ready, and [stop]
 * must be safe after a partially failed start. The VPN service must not install a default route
 * until a working implementation is wired to this boundary.
 */
internal interface PacketForwarder {
    fun start()

    fun stop()
}

/** Serializes a forwarder's lifecycle and cleans up a partially started implementation. */
internal class PacketForwarderLifecycle(
    private val create: () -> PacketForwarder,
) {
    private var forwarder: PacketForwarder? = null

    @Synchronized
    fun start() {
        if (forwarder != null) return

        val candidate = create()
        try {
            candidate.start()
            forwarder = candidate
        } catch (failure: Throwable) {
            runCatching { candidate.stop() }
            throw failure
        }
    }

    @Synchronized
    fun stop() {
        val active = forwarder ?: return
        active.stop()
        forwarder = null
    }
}
