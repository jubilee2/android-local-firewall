package com.localfirewall.app.vpn

import java.io.File
import javax.xml.parsers.DocumentBuilderFactory
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class FirewallVpnServiceManifestTest {
    @Test
    fun `vpn service declares required foreground service configuration`() {
        val manifest = sequenceOf(
            File("src/main/AndroidManifest.xml"),
            File("app/src/main/AndroidManifest.xml"),
        ).first(File::isFile)
        val document = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
        }.newDocumentBuilder().parse(manifest)
        val androidNamespace = "http://schemas.android.com/apk/res/android"
        val toolsNamespace = "http://schemas.android.com/tools"

        val permissions = document.getElementsByTagName("uses-permission")
            .let { nodes ->
                (0 until nodes.length)
                    .map { nodes.item(it).attributes.getNamedItemNS(androidNamespace, "name").nodeValue }
                    .toSet()
            }
        assertTrue("android.permission.FOREGROUND_SERVICE" in permissions)
        assertTrue("android.permission.FOREGROUND_SERVICE_SYSTEM_EXEMPTED" in permissions)

        val service = document.getElementsByTagName("service")
            .let { nodes -> (0 until nodes.length).map(nodes::item) }
            .single {
                it.attributes.getNamedItemNS(androidNamespace, "name").nodeValue ==
                    ".vpn.FirewallVpnService"
            }
        assertEquals(
            "systemExempted",
            service.attributes.getNamedItemNS(androidNamespace, "foregroundServiceType").nodeValue,
        )
        assertEquals(
            "ForegroundServicePermission",
            service.attributes.getNamedItemNS(toolsNamespace, "ignore").nodeValue,
        )

        val alwaysOnMetadata = service.childNodes
            .let { nodes -> (0 until nodes.length).map(nodes::item) }
            .single {
                it.nodeName == "meta-data" &&
                    it.attributes.getNamedItemNS(androidNamespace, "name").nodeValue ==
                    "android.net.VpnService.SUPPORTS_ALWAYS_ON"
            }
        assertEquals(
            "false",
            alwaysOnMetadata.attributes.getNamedItemNS(androidNamespace, "value").nodeValue,
        )
    }
}
