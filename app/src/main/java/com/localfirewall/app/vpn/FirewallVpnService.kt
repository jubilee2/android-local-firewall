package com.localfirewall.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import androidx.core.app.ServiceCompat
import com.localfirewall.app.R
import com.localfirewall.app.data.FirewallRepository
import com.localfirewall.app.data.local.FirewallDatabase
import com.localfirewall.app.firewall.AndroidConnectionOwnerLookup
import com.localfirewall.app.firewall.ConnectionOwnerResolver
import com.localfirewall.app.network.PacketForwarder
import com.localfirewall.app.network.PacketForwarderLifecycle
import com.localfirewall.app.network.outline.OutlinePacketForwarder
import java.io.Closeable

class FirewallVpnService : VpnService() {
    private val mainHandler = Handler(Looper.getMainLooper())
    private val sessionOrchestrator = FirewallVpnSessionOrchestrator<ParcelFileDescriptor, PacketDecisionCoordinator>(
        establishTun = ::establishVpnInterface,
        startDecisionCoordinator = ::createAndStartDecisionCoordinator,
        startNetworkMonitor = ::createAndStartNetworkMonitor,
        createForwarder = ::createOutlinePacketForwarder,
        onStartedChanged = FirewallServiceState::setStarted,
    )

    companion object {
        const val ACTION_START = "com.localfirewall.app.vpn.action.START"
        const val ACTION_STOP = "com.localfirewall.app.vpn.action.STOP"
        const val NOTIFICATION_CHANNEL_ID = "firewall_vpn"
        const val NOTIFICATION_ID = 1001
        internal const val VPN_MTU = 1500
        internal const val VPN_ADDRESS = "10.0.0.2"
        internal const val VPN_PREFIX_LENGTH = 32
        internal const val IPV4_DEFAULT_ROUTE_ADDRESS = "0.0.0.0"
        internal const val IPV4_DEFAULT_ROUTE_PREFIX = 0
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return FirewallServiceCommandHandler(
            start = {
                startForeground(NOTIFICATION_ID, createNotification())
                val started = sessionOrchestrator.startSession()
                if (!started) {
                    stopService()
                }
                started
            },
            stop = ::stopService,
        ).handle(intent?.action)
    }

    override fun onRevoke() {
        stopService()
        super.onRevoke()
    }

    private fun stopService() {
        sessionOrchestrator.stopSession()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        stopSelf()
    }

    override fun onDestroy() {
        sessionOrchestrator.stopSession()
        super.onDestroy()
    }

    private fun establishVpnInterface(): ParcelFileDescriptor? = try {
        // Per ADR-001 Gate #10, install only the IPv4 default capture route (0.0.0.0/0) and omit
        // allowFamily(AF_INET6) so Android blocks uncaptured AF_INET6 sockets rather than bypassing
        // firewall policy over IPv6 while upstream go-tun2socks UDP PCB support is IPv4-only.
        Builder()
            .setSession(getString(R.string.vpn_session_name))
            .setMtu(VPN_MTU)
            .addAddress(VPN_ADDRESS, VPN_PREFIX_LENGTH)
            .addRoute(IPV4_DEFAULT_ROUTE_ADDRESS, IPV4_DEFAULT_ROUTE_PREFIX)
            .establish()
    } catch (_: IllegalStateException) {
        null
    } catch (_: SecurityException) {
        null
    }

    private fun createAndStartDecisionCoordinator(): PacketDecisionCoordinator =
        PacketDecisionCoordinator(
            repository = FirewallRepository.getInstance(FirewallDatabase.getInstance(applicationContext)),
            failClosedOnUnknownUid = true,
            uidApplicationLookup = PackageManagerUidApplicationLookup(packageManager),
        ).also(PacketDecisionCoordinator::start)

    private fun createAndStartNetworkMonitor(): Closeable? {
        val connectivityManager = getSystemService(ConnectivityManager::class.java) ?: return null
        return AndroidUnderlyingNetworkMonitor(
            connectivityManager = connectivityManager,
            applyUnderlyingNetworks = ::setUnderlyingNetworks,
        ).also(AndroidUnderlyingNetworkMonitor::start)
    }

    private fun createOutlinePacketForwarder(
        tunInterface: ParcelFileDescriptor,
        coordinator: PacketDecisionCoordinator,
    ): PacketForwarder = OutlinePacketForwarder(
        tunFdProvider = { tunInterface.fd },
        connectionOwnerResolver = ConnectionOwnerResolver(
            AndroidConnectionOwnerLookup(getSystemService(ConnectivityManager::class.java)),
        ),
        evaluatePacket = coordinator::evaluateAndRecord,
        socketProtector = ::protect,
        onFatalError = {
            mainHandler.post {
                stopService()
            }
        },
    )

    private fun createNotification(): Notification =
        Notification.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_launcher_foreground)
            .setContentTitle(getString(R.string.firewall_notification_title))
            .setContentText(getString(R.string.firewall_notification_text))
            .setCategory(Notification.CATEGORY_SERVICE)
            .setOngoing(true)
            .build()

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val name = "Firewall VPN"
            val descriptionText = "Shows the status of the local firewall VPN service."
            val importance = NotificationManager.IMPORTANCE_LOW
            val channel = NotificationChannel(NOTIFICATION_CHANNEL_ID, name, importance).apply {
                description = descriptionText
            }
            val notificationManager: NotificationManager =
                getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            notificationManager.createNotificationChannel(channel)
        }
    }
}

/**
 * Coordinates fail-closed startup and ordered teardown across the TUN interface,
 * [PacketForwarderLifecycle], decision coordinator, and underlying-network monitor.
 */
internal class FirewallVpnSessionOrchestrator<TunHandle : Closeable, Coordinator : Closeable>(
    private val vpnInterface: VpnInterfaceLifecycle<TunHandle> = VpnInterfaceLifecycle(),
    private val establishTun: () -> TunHandle?,
    private val startDecisionCoordinator: () -> Coordinator,
    private val startNetworkMonitor: () -> Closeable?,
    private val createForwarder: (tunHandle: TunHandle, coordinator: Coordinator) -> PacketForwarder,
    private val onStartedChanged: (Boolean) -> Unit,
) {
    private var activeTun: TunHandle? = null
    private var decisionCoordinator: Coordinator? = null
    private var networkMonitor: Closeable? = null
    private val forwarderLifecycle = PacketForwarderLifecycle {
        createForwarder(
            checkNotNull(activeTun) { "TUN interface must be established before starting PacketForwarder" },
            checkNotNull(decisionCoordinator) { "Decision coordinator must be started before starting PacketForwarder" },
        )
    }

    @Synchronized
    fun startSession(): Boolean {
        val tun = vpnInterface.establish(establishTun)
        if (tun == null) {
            stopSession()
            return false
        }
        activeTun = tun
        return try {
            if (decisionCoordinator == null) {
                decisionCoordinator = startDecisionCoordinator()
            }
            forwarderLifecycle.start()
            if (networkMonitor == null) {
                networkMonitor = startNetworkMonitor()
            }
            onStartedChanged(true)
            true
        } catch (_: Throwable) {
            stopSession()
            false
        }
    }

    @Synchronized
    fun stopSession() {
        // 1. Stop native forwarder first while TUN descriptor and coordinator are still open.
        runCatching { forwarderLifecycle.stop() }
        // 2. Close rule/logging coordinator and underlying network callback.
        runCatching { decisionCoordinator?.close() }
        decisionCoordinator = null
        runCatching { networkMonitor?.close() }
        networkMonitor = null
        // 3. Release the service's TUN ParcelFileDescriptor last, removing the 0.0.0.0/0 route.
        activeTun = null
        vpnInterface.close()
        onStartedChanged(false)
    }
}

/** Owns one closeable VPN interface and makes repeated shutdown safe. */
internal class VpnInterfaceLifecycle<T : Closeable> {
    private var interfaceHandle: T? = null

    @Synchronized
    fun establish(create: () -> T?): T? {
        interfaceHandle?.let { return it }
        return create()?.also { interfaceHandle = it }
    }

    @Synchronized
    fun close() {
        val handle = interfaceHandle
        interfaceHandle = null
        runCatching { handle?.close() }
    }
}

internal class FirewallServiceCommandHandler(
    private val start: () -> Boolean,
    private val stop: () -> Unit,
) {
    fun handle(action: String?): Int = when (action) {
        FirewallVpnService.ACTION_START,
        VpnService.SERVICE_INTERFACE,
        null,
        -> {
            if (start()) Service.START_REDELIVER_INTENT else Service.START_NOT_STICKY
        }
        FirewallVpnService.ACTION_STOP -> {
            stop()
            Service.START_NOT_STICKY
        }
        else -> Service.START_NOT_STICKY
    }
}
