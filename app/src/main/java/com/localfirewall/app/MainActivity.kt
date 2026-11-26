package com.localfirewall.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.activity.viewModels
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.core.content.ContextCompat
import com.localfirewall.app.data.FirewallRepository
import com.localfirewall.app.data.local.FirewallDatabase
import com.localfirewall.app.firewall.InstalledAppsProvider
import com.localfirewall.app.firewall.PackageManagerInstalledPackageScanner
import com.localfirewall.app.ui.AndroidLocalFirewallApp
import com.localfirewall.app.ui.FirewallViewModel
import com.localfirewall.app.vpn.FirewallServiceState
import com.localfirewall.app.vpn.FirewallVpnService
import com.localfirewall.app.vpn.VpnPermissionAction
import com.localfirewall.app.vpn.VpnPermissionDecision

class MainActivity : ComponentActivity() {
    private val viewModel: FirewallViewModel by viewModels {
        FirewallViewModel.Factory(
            repository = FirewallRepository.getInstance(FirewallDatabase.getInstance(applicationContext)),
            installedAppsProvider = InstalledAppsProvider(
                scanner = PackageManagerInstalledPackageScanner(packageManager),
                excludedPackages = setOf(packageName),
            ),
        )
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult(),
    ) { result ->
        handlePermissionAction(
            VpnPermissionDecision.afterPermissionResult(result.resultCode == Activity.RESULT_OK),
        )
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent {
            val serviceStarted by FirewallServiceState.isStarted.collectAsState()
            val uiState by viewModel.uiState.collectAsState()
            val stateHolder = viewModel.stateHolder
            AndroidLocalFirewallApp(
                serviceStarted = serviceStarted,
                uiState = uiState,
                onStartFirewall = ::requestVpnPermission,
                onStopFirewall = ::stopFirewallService,
                onSelectTab = stateHolder::selectTab,
                onAppSearchQueryChange = stateHolder::updateAppSearchQuery,
                onIncludeSystemAppsChange = stateHolder::setIncludeSystemApps,
                onAppActionChange = stateHolder::setAppAction,
                onAddNetworkRule = stateHolder::addNetworkRule,
                onClearRuleError = stateHolder::clearRuleInputError,
                onToggleNetworkRuleEnabled = stateHolder::setNetworkRuleEnabled,
                onDeleteNetworkRule = stateHolder::deleteNetworkRule,
                onTrafficLoggingEnabledChange = stateHolder::setTrafficLoggingEnabled,
                onClearTrafficLogs = stateHolder::clearTrafficLogs,
            )
        }
    }

    private fun requestVpnPermission() {
        val permissionIntent = VpnService.prepare(this)
        when (VpnPermissionDecision.afterPrepare(permissionIntent != null)) {
            VpnPermissionAction.RequestPermission ->
                vpnPermissionLauncher.launch(requireNotNull(permissionIntent))
            VpnPermissionAction.StartService -> startFirewallService()
            VpnPermissionAction.KeepFirewallOff -> Unit
        }
    }

    private fun handlePermissionAction(action: VpnPermissionAction) {
        when (action) {
            VpnPermissionAction.StartService -> startFirewallService()
            VpnPermissionAction.RequestPermission,
            VpnPermissionAction.KeepFirewallOff,
            -> Unit
        }
    }

    private fun startFirewallService() {
        val intent = Intent(this, FirewallVpnService::class.java).apply {
            action = FirewallVpnService.ACTION_START
        }
        ContextCompat.startForegroundService(this, intent)
    }

    private fun stopFirewallService() {
        val intent = Intent(this, FirewallVpnService::class.java).apply {
            action = FirewallVpnService.ACTION_STOP
        }
        startService(intent)
    }
}
