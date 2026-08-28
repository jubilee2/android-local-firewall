package com.localfirewall.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.ServiceCompat
import com.localfirewall.app.R
import java.io.Closeable
import java.io.FileInputStream

class FirewallVpnService : VpnService() {
    private val vpnInterface = VpnInterfaceLifecycle<ParcelFileDescriptor>()
    private val mainHandler = Handler(Looper.getMainLooper())
    private var packetProcessor: PacketProcessor? = null

    companion object {
        const val ACTION_START = "com.localfirewall.app.vpn.action.START"
        const val ACTION_STOP = "com.localfirewall.app.vpn.action.STOP"
        const val NOTIFICATION_CHANNEL_ID = "firewall_vpn"
        const val NOTIFICATION_ID = 1001
        private const val VPN_ADDRESS = "10.0.0.2"
        private const val VPN_PREFIX_LENGTH = 32
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return FirewallServiceCommandHandler(
            start = {
                startForeground(NOTIFICATION_ID, createNotification())
                val tunInterface = establishVpnInterface()
                if (tunInterface != null) {
                    startPacketProcessor(tunInterface)
                    FirewallServiceState.setStarted(true)
                    true
                } else {
                    stopService()
                    false
                }
            },
            stop = ::stopService,
        ).handle(intent?.action)
    }

    private fun stopService() {
        stopPacketProcessor()
        // ParcelFileDescriptor owns the TUN descriptor; closing it unblocks a blocking read.
        vpnInterface.close()
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        FirewallServiceState.setStarted(false)
        stopSelf()
    }

    override fun onDestroy() {
        stopPacketProcessor()
        // This is idempotent and also releases a read still blocked in PacketProcessor.
        vpnInterface.close()
        FirewallServiceState.setStarted(false)
        super.onDestroy()
    }

    private fun establishVpnInterface(): ParcelFileDescriptor? = try {
        vpnInterface.establish {
            Builder()
                .setSession(getString(R.string.vpn_session_name))
                .addAddress(VPN_ADDRESS, VPN_PREFIX_LENGTH)
                .allowFamily(OsConstants.AF_INET6)
                .setBlocking(true)
                .establish()
        }
    } catch (_: IllegalStateException) {
        vpnInterface.close()
        null
    } catch (_: SecurityException) {
        vpnInterface.close()
        null
    }

    private fun startPacketProcessor(tunInterface: ParcelFileDescriptor) {
        if (packetProcessor != null) return
        packetProcessor = PacketProcessor(
            InputStreamPacketSource(FileInputStream(tunInterface.fileDescriptor)),
            onUnexpectedTermination = { terminatedProcessor ->
                mainHandler.post {
                    if (packetProcessor === terminatedProcessor) stopService()
                }
            },
        ).also(PacketProcessor::start)
    }

    private fun stopPacketProcessor() {
        packetProcessor?.close()
        packetProcessor = null
    }

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
        FirewallVpnService.ACTION_START -> {
            if (start()) Service.START_REDELIVER_INTENT else Service.START_NOT_STICKY
        }
        FirewallVpnService.ACTION_STOP -> {
            stop()
            Service.START_NOT_STICKY
        }
        else -> Service.START_NOT_STICKY
    }
}
