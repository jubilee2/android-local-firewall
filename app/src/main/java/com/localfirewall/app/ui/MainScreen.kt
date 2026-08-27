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
}

@Composable
fun AndroidLocalFirewallApp() {
    MaterialTheme {
        Surface(modifier = Modifier.fillMaxSize()) {
            MainScreen()
        }
    }
}

@Composable
fun MainScreen(
    status: FirewallStatus = FirewallStatus.OFF,
    onStartFirewall: () -> Unit = {},
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
        Button(onClick = onStartFirewall) {
            Text("Start Firewall")
        }
    }
}

@Preview(showBackground = true)
@Composable
private fun MainScreenPreview() {
    AndroidLocalFirewallApp()
}
