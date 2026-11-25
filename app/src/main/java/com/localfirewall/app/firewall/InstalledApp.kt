package com.localfirewall.app.firewall

import android.Manifest
import android.content.pm.ApplicationInfo
import android.content.pm.PackageManager
import android.os.Build

/** Metadata for an internet-capable installed Android application. */
data class InstalledApp(
    val uid: Int,
    val packageName: String,
    val appName: String,
    val isSystemApp: Boolean,
) {
    init {
        require(uid >= 0) { "uid must be non-negative" }
        require(packageName.isNotBlank()) { "packageName must not be blank" }
    }
}

/** Raw package record decoupling [InstalledAppsProvider] from Android's [PackageManager]. */
data class RawInstalledPackage(
    val uid: Int,
    val packageName: String,
    val label: String?,
    val isSystemApp: Boolean,
    val hasInternetPermission: Boolean,
)

/** Injectable boundary for enumerating installed packages. */
fun interface InstalledPackageScanner {
    fun scan(): List<RawInstalledPackage>
}

/** Production [InstalledPackageScanner] backed by Android's [PackageManager]. */
class PackageManagerInstalledPackageScanner(
    private val packageManager: PackageManager,
) : InstalledPackageScanner {
    override fun scan(): List<RawInstalledPackage> {
        val applications = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledApplications(PackageManager.ApplicationInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledApplications(0)
        }
        return applications.map { appInfo ->
            val isSystem = (appInfo.flags and ApplicationInfo.FLAG_SYSTEM) != 0 ||
                (appInfo.flags and ApplicationInfo.FLAG_UPDATED_SYSTEM_APP) != 0
            val hasInternet = packageManager.checkPermission(
                Manifest.permission.INTERNET,
                appInfo.packageName,
            ) == PackageManager.PERMISSION_GRANTED
            RawInstalledPackage(
                uid = appInfo.uid,
                packageName = appInfo.packageName,
                label = packageManager.getApplicationLabel(appInfo).toString(),
                isSystemApp = isSystem,
                hasInternetPermission = hasInternet,
            )
        }
    }
}

/** Filters, normalizes, and deterministically sorts internet-capable installed applications. */
class InstalledAppsProvider(
    private val scanner: InstalledPackageScanner,
    private val excludedPackages: Set<String> = emptySet(),
) {
    fun listInternetApps(includeSystemApps: Boolean = true): List<InstalledApp> =
        scanner.scan()
            .asSequence()
            .filter { it.uid >= 0 && it.packageName.isNotBlank() }
            .filter { it.hasInternetPermission }
            .filter { it.packageName !in excludedPackages }
            .filter { includeSystemApps || !it.isSystemApp }
            .distinctBy(RawInstalledPackage::packageName)
            .map { raw ->
                val normalizedName = raw.label?.trim().takeUnless { it.isNullOrEmpty() }
                    ?: raw.packageName
                InstalledApp(
                    uid = raw.uid,
                    packageName = raw.packageName,
                    appName = normalizedName,
                    isSystemApp = raw.isSystemApp,
                )
            }
            .sortedWith(
                compareBy<InstalledApp> { it.isSystemApp }
                    .thenBy(String.CASE_INSENSITIVE_ORDER, InstalledApp::appName)
                    .thenBy(InstalledApp::packageName),
            )
            .toList()
}
