package dev.jokelbaf.netcap.core.desktop

import kotlin.test.Test
import kotlin.test.assertTrue

class PcapDevicesNativeTest {

    @Test
    fun listsDevicesWithoutError() {
        val devices = pcapDevices()
        assertTrue(devices.any { it.name == "lo" || it.name == "any" || it.name.isNotBlank() })
    }
}
