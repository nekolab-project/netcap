package dev.jokelbaf.netcap.core.desktop

import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.PacketSniffer

internal actual fun pcapDevicesImpl(): List<PcapDevice> = findAllDevices()

internal actual fun openPcapSnifferImpl(
    device: String,
    options: CaptureOptions,
    log: (String) -> Unit,
): PacketSniffer = DesktopSniffer(device, options, log)
