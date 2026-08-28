package com.localfirewall.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.tooling.preview.Preview

enum class FirewallStatus(val displayName: String) {
    OFF("OFF"),
    STARTED("STARTED"),
}

@Composable
fun AndroidLocalFirewallApp(
    serviceStarted: Boolean = false,
    onStartFirewall: () -> Unit = {},
    onStopFirewall: () -> Unit = {},
) {
    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            MainScreen(
                status = if (serviceStarted) FirewallStatus.STARTED else FirewallStatus.OFF,
                onStartFirewall = onStartFirewall,
                onStopFirewall = onStopFirewall,
            )
        }
    }
}

@Composable
fun MainScreen(
    status: FirewallStatus = FirewallStatus.OFF,
    onStartFirewall: () -> Unit = {},
    onStopFirewall: () -> Unit = {},
) {
    Column(
        modifier = Modifier.fillMaxSize(),
        verticalArrangement = Arrangement.SpaceEvenly,
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Text(
            text = "Android Local Firewall",
            style = MaterialTheme.typography.headlineMedium,
        )
        Text(
            text = "Firewall: ${status.displayName}",
            style = MaterialTheme.typography.titleLarge,
        )
        val isStarted = status == FirewallStatus.STARTED
        Button(onClick = if (isStarted) onStopFirewall else onStartFirewall) {
            Text(if (isStarted) "Stop Firewall" else "Start Firewall")
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun MainScreenPreview() {
    AndroidLocalFirewallApp()
}
