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
import androidx.compose.material3.FilterChip
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import com.localfirewall.app.firewall.FirewallAction
import com.localfirewall.app.firewall.InstalledApp

@Composable
fun AppsTabContent(
    apps: List<AppPolicyItem>,
    searchQuery: String,
    includeSystemApps: Boolean,
    onSearchQueryChange: (String) -> Unit,
    onIncludeSystemAppsChange: (Boolean) -> Unit,
    onAppActionChange: (InstalledApp, FirewallAction) -> Unit,
    modifier: Modifier = Modifier,
) {
    Column(
        modifier = modifier
            .fillMaxSize()
            .padding(16.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp),
    ) {
        OutlinedTextField(
            value = searchQuery,
            onValueChange = onSearchQueryChange,
            label = { Text("Search installed applications") },
            singleLine = true,
            modifier = Modifier.fillMaxWidth(),
        )

        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically,
        ) {
            Text(
                text = "Show system applications",
                style = MaterialTheme.typography.bodyMedium,
            )
            Switch(
                checked = includeSystemApps,
                onCheckedChange = onIncludeSystemAppsChange,
            )
        }

        if (apps.isEmpty()) {
            Text(
                text = "No matching internet-capable applications found.",
                style = MaterialTheme.typography.bodyMedium,
                color = MaterialTheme.colorScheme.onSurfaceVariant,
            )
        } else {
            LazyColumn(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
            ) {
                items(
                    items = apps,
                    key = { it.app.packageName },
                ) { item ->
                    AppPolicyRow(
                        item = item,
                        onActionSelected = { action -> onAppActionChange(item.app, action) },
                    )
                }
            }
        }
    }
}

@Composable
private fun AppPolicyRow(
    item: AppPolicyItem,
    onActionSelected: (FirewallAction) -> Unit,
) {
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
                    text = item.app.appName,
                    style = MaterialTheme.typography.titleMedium,
                )
                Text(
                    text = "${item.app.packageName} (UID ${item.app.uid})",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                )
            }
            Row(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                FilterChip(
                    selected = item.action == FirewallAction.ALLOW,
                    onClick = { onActionSelected(FirewallAction.ALLOW) },
                    label = { Text("Allow") },
                )
                FilterChip(
                    selected = item.action == FirewallAction.BLOCK,
                    onClick = { onActionSelected(FirewallAction.BLOCK) },
                    label = { Text("Block") },
                )
            }
        }
    }
}
