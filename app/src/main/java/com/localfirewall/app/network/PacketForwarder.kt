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

/**
 * Serializes a forwarder's lifecycle and cleans up a partially started implementation.
 *
 * If cleanup ([PacketForwarder.stop]) fails—whether after an active session or during rollback of
 * a failed [PacketForwarder.start]—ownership of that instance is retained in a cleanup-pending
 * state. Subsequent [start] attempts fail without creating a replacement until [stop] succeeds.
 */
internal class PacketForwarderLifecycle(
    private val create: () -> PacketForwarder,
) {
    private var state: State = State.Idle

    @Synchronized
    fun start() {
        when (val current = state) {
            is State.Active -> return
            is State.CleanupPending -> throw IllegalStateException(
                "Previous forwarder failed cleanup; stop() must succeed before starting a new instance",
                current.lastCleanupFailure,
            )
            State.Idle -> Unit
        }

        val candidate = create()
        try {
            candidate.start()
            state = State.Active(candidate)
        } catch (failure: Throwable) {
            try {
                stopForwarder(candidate)
            } catch (cleanupFailure: Throwable) {
                if (cleanupFailure !== failure) {
                    failure.addSuppressed(cleanupFailure)
                }
            }
            throw failure
        }
    }

    @Synchronized
    fun stop() {
        val target = when (val current = state) {
            State.Idle -> return
            is State.Active -> current.forwarder
            is State.CleanupPending -> current.forwarder
        }
        stopForwarder(target)
    }

    private fun stopForwarder(target: PacketForwarder) {
        try {
            target.stop()
            state = State.Idle
        } catch (cleanupFailure: Throwable) {
            state = State.CleanupPending(target, cleanupFailure)
            throw cleanupFailure
        }
    }

    private sealed interface State {
        data object Idle : State

        data class Active(val forwarder: PacketForwarder) : State

        data class CleanupPending(
            val forwarder: PacketForwarder,
            val lastCleanupFailure: Throwable,
        ) : State
    }
}
