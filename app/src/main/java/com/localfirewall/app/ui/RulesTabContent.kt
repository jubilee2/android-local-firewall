package com.localfirewall.app.ui

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.localfirewall.app.data.StoredNetworkRule
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.network.TransportProtocol

@Composable
fun RulesTabContent(
    rules: List<StoredNetworkRule>,
    inputError: String?,
    onAddRule: (FirewallAction, String, TransportProtocol, String) -> Boolean,
    onClearError: () -> Unit,
    onToggleRuleEnabled: (Long, Boolean) -> Unit,
    onDeleteRule: (Long) -> Unit,
    modifier: Modifier = Modifier,
) {
    var selectedAction by rememberSaveable { mutableStateOf(FirewallAction.BLOCK) }
    var selectedProtocol by rememberSaveable { mutableStateOf(TransportProtocol.ANY) }
    var destinationInput by rememberSaveable { mutableStateOf("") }
    var portInput by rememberSaveable { mutableStateOf("") }

    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        Card(modifier = Modifier.fillMaxWidth()) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(12.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                Text(
                    text = "Add Network Rule",
                    style = MaterialTheme.typography.titleMedium,
                )
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    FirewallAction.entries.forEach { action ->
                        FilterChip(
                            selected = selectedAction == action,
                            onClick = { selectedAction = action },
                            label = { Text(action.name) },
                        )
                    }
                }
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TransportProtocol.entries.forEach { protocol ->
                        FilterChip(
                            selected = selectedProtocol == protocol,
                            onClick = { selectedProtocol = protocol },
                            label = { Text(protocol.name) },
                        )
                    }
                }
                OutlinedTextField(
                    value = destinationInput,
                    onValueChange = {
                        destinationInput = it
                        if (inputError != null) onClearError()
                    },
                    label = { Text("IPv4 or CIDR (optional, e.g. 8.8.8.8 or 192.168.0.0/16)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                OutlinedTextField(
                    value = portInput,
                    onValueChange = {
                        portInput = it
                        if (inputError != null) onClearError()
                    },
                    label = { Text("Destination port (optional, 0-65535)") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth(),
                )
                if (inputError != null) {
                    Text(
                        text = inputError,
                        color = MaterialTheme.colorScheme.error,
                        style = MaterialTheme.typography.bodySmall,
                    )
                }
                Button(
                    onClick = {
                        val added = onAddRule(
                            selectedAction,
                            destinationInput,
                            selectedProtocol,
                            portInput,
                        )
                        if (added) {
                            destinationInput = ""
                            portInput = ""
                        }
                    },
                ) {
                    Text("Save Rule")
                }
            }
        }

        if (rules.isEmpty()) {
            Text(
                text = "No custom network rules configured. Default policy: ALLOW.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(
                    items = rules,
                    key = StoredNetworkRule::id,
                ) { rule ->
                    NetworkRuleRow(
                        rule = rule,
                        onToggleEnabled = { enabled -> onToggleRuleEnabled(rule.id, enabled) },
                        onDelete = { onDeleteRule(rule.id) },
                    )
                }
            }
        }
    }
}

@Composable
private fun NetworkRuleRow(
    rule: StoredNetworkRule,
    onToggleEnabled: (Boolean) -> Unit,
    onDelete: () -> Unit,
) {
    val destinationSummary = rule.destinationAddress?.hostAddress
        ?: rule.destinationCidr?.format()
        ?: "Any destination"
    val portSummary = rule.destinationPort?.let { "port $it" } ?: "any port"

    Card(modifier = Modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(12.dp),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Column(
                modifier = Modifier
                    .weight(1f)
                    .padding(end = 8.dp),
            ) {
                Text(
                    text = "${rule.action.name} ${rule.protocol.name} $destinationSummary ($portSummary)",
                    style = MaterialTheme.typography.bodyLarge,
                )
                Text(
                    text = if (rule.enabled) "Enabled" else "Disabled",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Switch(
                    checked = rule.enabled,
                    onCheckedChange = onToggleEnabled,
                )
                OutlinedButton(onClick = onDelete) {
                    Text("Delete")
                }
            }
        }
    }
}
