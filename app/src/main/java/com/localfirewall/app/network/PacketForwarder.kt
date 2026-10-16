package com.localfirewall.app.network

/**
 * Owns the future Outline/lwIP bridge that forwards packets from the VPN TUN interface.
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
        forwarder = candidate
        try {
            candidate.start()
        } catch (failure: Throwable) {
            try {
                stop()
            } catch (cleanupFailure: Throwable) {
                // Keep ownership until a later stop confirms the candidate is quiescent.
                if (cleanupFailure !== failure) failure.addSuppressed(cleanupFailure)
            }
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
