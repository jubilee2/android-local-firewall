package com.localfirewall.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Card
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.localfirewall.app.data.TrafficLogEntry
import com.localfirewall.app.firewall.FirewallAction
import java.time.Instant
import java.time.ZoneId
import java.time.format.DateTimeFormatter

private val LOG_TIME_FORMATTER: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")

@Composable
fun LogsTabContent(
    logs: List<TrafficLogEntry>,
    loggingEnabled: Boolean,
    onLoggingEnabledChange: (Boolean) -> Unit,
    onClearLogs: () -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = "Record local traffic metadata",
                    style = MaterialTheme.typography.bodyMedium,
                )
                Switch(
                    checked = loggingEnabled,
                    onCheckedChange = onLoggingEnabledChange,
                )
            }
            OutlinedButton(
                onClick = onClearLogs,
                enabled = logs.isNotEmpty(),
            ) {
                Text("Clear")
            }
        }

        if (logs.isEmpty()) {
            Text(
                text = "No local traffic log entries recorded yet.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(
                    items = logs,
                    key = TrafficLogEntry::id,
                ) { entry ->
                    TrafficLogRow(entry = entry)
                }
            }
        }
    }
}

@Composable
private fun TrafficLogRow(entry: TrafficLogEntry) {
    val timestampText = Instant.ofEpochMilli(entry.timestampMillis)
        .atZone(ZoneId.systemDefault())
        .format(LOG_TIME_FORMATTER)
    val appText = when {
        entry.applicationName != null && entry.packageName != null ->
            "${entry.applicationName} (${entry.packageName})"
        entry.packageName != null -> entry.packageName
        entry.uid != null -> "UID ${entry.uid}"
        else -> "Unknown application"
    }
    val sourceEndpoint = formatEndpoint(entry.sourceAddress, entry.sourcePort)
    val destinationEndpoint = formatEndpoint(entry.destinationAddress, entry.destinationPort)
    val decisionColor = if (entry.action == FirewallAction.BLOCK) {
        MaterialTheme.colorScheme.error
    } else {
        MaterialTheme.colorScheme.primary
    }

    Card(modifier = Modifier.fillMaxWidth()) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            verticalArrangement = Arrangement.spacedBy(4.dp),
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Text(
                    text = entry.action.name,
                    color = decisionColor,
                    style = MaterialTheme.typography.labelLarge,
                )
                Text(
                    text = timestampText,
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Text(
                text = appText,
                style = MaterialTheme.typography.titleSmall,
            )
            Text(
                text = "${entry.protocol.name}  $sourceEndpoint -> $destinationEndpoint",
                style = MaterialTheme.typography.bodySmall,
            )
        }
    }
}

private fun formatEndpoint(address: String, port: Int?): String = when {
    port == null -> address
    ':' in address -> "[$address]:$port"
    else -> "$address:$port"
}
