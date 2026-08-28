package com.localfirewall.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import androidx.core.app.ServiceCompat
import com.localfirewall.app.R

class FirewallVpnService : VpnService() {
    companion object {
        const val ACTION_START = "com.localfirewall.app.vpn.action.START"
        const val ACTION_STOP = "com.localfirewall.app.vpn.action.STOP"
        const val NOTIFICATION_CHANNEL_ID = "firewall_vpn"
        const val NOTIFICATION_ID = 1001
    }

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return FirewallServiceCommandHandler(
            start = {
                startForeground(NOTIFICATION_ID, createNotification())
                FirewallServiceState.setStarted(true)
            },
            stop = ::stopService,
        ).handle(intent?.action)
    }

    private fun stopService() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        getSystemService(NotificationManager::class.java).cancel(NOTIFICATION_ID)
        FirewallServiceState.setStarted(false)
        stopSelf()
    }

    override fun onDestroy() {
        FirewallServiceState.setStarted(false)
        super.onDestroy()
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

internal class FirewallServiceCommandHandler(
    private val start: () -> Unit,
    private val stop: () -> Unit,
) {
    fun handle(action: String?): Int = when (action) {
        FirewallVpnService.ACTION_START -> {
            start()
            Service.START_REDELIVER_INTENT
        }
        FirewallVpnService.ACTION_STOP -> {
            stop()
            Service.START_NOT_STICKY
        }
        else -> Service.START_NOT_STICKY
    }
}
