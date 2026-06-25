package dev.jokelbaf.netcap.core.desktop

import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.PacketSniffer

/**
 * Desktop passive capture entry points, backed by libpcap (Linux/macOS, via the JVM Foreign
 * Function & Memory API) or by cinterop bindings on the native targets. The same API is
 * available whether the library is consumed from the JVM or a Kotlin/Native binary.
 */

/** Lists the interfaces available for capture. */
fun pcapDevices(): List<PcapDevice> = pcapDevicesImpl()

/**
 * Opens a passive-capture [PacketSniffer] on [device] (a name from [pcapDevices]). Capture
 * starts on [PacketSniffer.start]; that call throws [PcapException] if the device can't be opened.
 */
fun openPcapSniffer(
    device: String,
    options: CaptureOptions = CaptureOptions(),
    log: (String) -> Unit = {},
): PacketSniffer = openPcapSnifferImpl(device, options, log)

internal expect fun pcapDevicesImpl(): List<PcapDevice>

internal expect fun openPcapSnifferImpl(
    device: String,
    options: CaptureOptions,
    log: (String) -> Unit,
): PacketSniffer
