package com.localfirewall.app.firewall

/** Per-application firewall rule configured for an installed package and its Android UID. */
data class AppFirewallRule(
    val uid: Int,
    val packageName: String,
    val action: FirewallAction,
) {
    init {
        require(uid >= 0) { "uid must be non-negative" }
        require(packageName.isNotBlank()) { "packageName must not be blank" }
    }

    fun toFirewallRule(): FirewallRule = FirewallRule(
        action = action,
        uid = uid,
    )
}

/**
 * Compiles per-package [AppFirewallRule] entries into UID-level [FirewallRule]s.
 *
 * Android socket attribution ([ConnectionOwnerResolver]) resolves ownership at the kernel UID
 * boundary rather than individual package names. When multiple packages share an Android UID and
 * have conflicting policies, [FirewallAction.BLOCK] wins so shared-UID packages fail closed.
 */
fun Iterable<AppFirewallRule>.toEffectiveFirewallRules(): List<FirewallRule> =
    groupBy(AppFirewallRule::uid)
        .toSortedMap()
        .map { (uid, rulesForUid) ->
            val effectiveAction = if (rulesForUid.any { it.action == FirewallAction.BLOCK }) {
                FirewallAction.BLOCK
            } else {
                FirewallAction.ALLOW
            }
            FirewallRule(
                action = effectiveAction,
                uid = uid,
            )
        }
