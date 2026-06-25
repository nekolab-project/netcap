# netcap

A pure Kotlin Multiplatform network packet capture library. It provides one capture API across
Android, iOS, JVM desktop and native desktop (Linux, macOS, Windows), together with a lazily
decoded packet model and read/write support for the classic pcap file format.

The library is written entirely in Kotlin. It has no JNI wrappers and no bundled native binaries.
Desktop capture binds to the system libpcap or Npcap through the Java Foreign Function and Memory
API on the JVM and through cinterop on native targets.

## Capture models

The library uses the capture mechanism each platform actually offers, and does not hide the
difference behind a false abstraction.

Desktop (Linux, macOS, Windows) uses passive capture through libpcap or Npcap. Packets are read
straight off the wire and start at the link layer (usually Ethernet).

Mobile (Android, iOS) uses an active TUN interface with a userspace NAT. Traffic is routed into the
process as raw IP packets, captured, forwarded to the real destination, and the responses are
captured on the way back. Packets start at the IP layer.

Both models surface the same `PacketSniffer` interface and the same packet model.

## Supported targets

- `android`
- `iosArm64`, `iosSimulatorArm64`
- `jvm`
- `linuxX64`, `macosArm64`, `mingwX64`

## Installation

The library is published to Maven Central as `dev.jokelbaf:netcap`.

In a Kotlin Multiplatform project:

```kotlin
kotlin {
    sourceSets {
        commonMain.dependencies {
            implementation("dev.jokelbaf:netcap:0.1.0")
        }
    }
}
```

In a single platform (for example JVM) project:

```kotlin
dependencies {
    implementation("dev.jokelbaf:netcap:0.1.0")
}
```

## The capture API

Every backend implements `PacketSniffer`:

```kotlin
interface PacketSniffer {
    val packets: Flow<Packet>
    val state: StateFlow<CaptureState>
    val stats: StateFlow<CaptureStats>
    fun start()
    fun stop()
}
```

Construction is platform specific. Observation is identical everywhere: collect `packets`, watch
`state` and `stats`.

### Desktop (JVM and native)

```kotlin
import dev.jokelbaf.netcap.core.CaptureFilter
import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.desktop.openPcapSniffer
import dev.jokelbaf.netcap.core.desktop.pcapDevices
import dev.jokelbaf.netcap.core.protocol.ip
import dev.jokelbaf.netcap.core.protocol.tcp

val device = pcapDevices().first()
val sniffer = openPcapSniffer(
    device = device.name,
    options = CaptureOptions(filter = CaptureFilter.Bpf("tcp port 443")),
)

sniffer.start()
scope.launch {
    sniffer.packets.collect { packet ->
        val tcp = packet.tcp ?: return@collect
        println("${packet.ip?.sourceAddress}:${tcp.sourcePort} -> ${tcp.destinationPort}")
    }
}
```

`pcapDevices()` and `openPcapSniffer()` are available on the JVM and on the three native desktop
targets through the same import.

### Android

```kotlin
import dev.jokelbaf.netcap.core.CaptureFilter
import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.android.AndroidSniffer

val sniffer = AndroidSniffer(
    context = context,
    options = CaptureOptions(filter = CaptureFilter.Rules(ports = setOf(443))),
)

sniffer.onRequestConsent = { intent -> consentLauncher.launch(intent) }
sniffer.start()
```

Starting capture requires the system VPN consent dialog, which can only be shown from an Activity.
Set `onRequestConsent` to launch the intent, then call `onConsentResult(granted)` with the result.
The host app must declare `SnifferVpnService` in its manifest with the VPN service intent filter and
the `BIND_VPN_SERVICE` permission.

### iOS

The engine runs inside a Network Extension packet tunnel. In the extension target, drive
`IosPacketTunnel` from the `NEPacketTunnelProvider` callbacks. In the app target, observe capture
through `IosSniffer`, which reads the shared App Group snapshot the extension publishes.

```kotlin
import dev.jokelbaf.netcap.core.ios.IosSniffer

val sniffer = IosSniffer(appGroup = "group.com.example.app")
sniffer.start()
```

The app and the extension must share an App Group, and the extension must be configured as a packet
tunnel provider. Nothing app specific (bundle ids, App Group names, interface names) is hardcoded in
the library.

## Packet model

`Packet` exposes a lazily decoded layer chain over a single owned frame buffer. Nothing is parsed
until a layer is accessed, and no bytes are copied between layers.

```kotlin
val ip = packet.ip                 // IpPacket, IPv4 or IPv6
val v4 = packet.ipv4               // Ipv4Packet or null
val v6 = packet.ipv6               // Ipv6Packet or null
val transport = packet.transport   // TcpSegment or UdpDatagram
val tcp = packet.tcp
val udp = packet.udp
val eth = packet.ethernet          // present on desktop, null on mobile
```

Each accessor walks the chain to the first layer of the requested type, decoding on demand. Raw
bytes are reachable through `packet.frame.bytes` for the whole frame, or `payload.toByteArray()` for
one layer. The packet also carries `timestamp` (`kotlin.time.Instant`), `direction` and
`interfaceName`.

## Filtering

`CaptureOptions.filter` accepts two kinds of filter:

```kotlin
CaptureFilter.Bpf("udp port 53")                       // desktop only, compiled to a kernel BPF program
CaptureFilter.Rules(                                   // works on every platform
    protocols = setOf(TransportProtocol.TCP),
    ports = setOf(80, 443),
    hosts = setOf("93.184.216.34"),
)
```

On desktop, both are pushed into the kernel through libpcap, which is the most effective way to cut
load. On mobile, `Rules` are evaluated in software on the decoded packet and a raw `Bpf` expression
is ignored.

## pcap file I/O

The library reads and writes the classic libpcap savefile format, which Wireshark and tcpdump read
natively. It only encodes and decodes bytes. It never opens, reads or writes files, so it stays
pure Kotlin and platform agnostic. The caller performs the actual file I/O.

```kotlin
import dev.jokelbaf.netcap.core.format.PcapReader
import dev.jokelbaf.netcap.core.format.PcapWriter
import dev.jokelbaf.netcap.core.protocol.LinkType

// write
val writer = PcapWriter(LinkType.ETHERNET)
output.write(writer.fileHeader())
output.write(writer.record(packet))

// read, incrementally, in any chunk sizes
val reader = PcapReader()
reader.decode(chunk).forEach { packet -> /* ... */ }
```

`PcapReader` detects byte order and timestamp resolution from the file magic number and buffers a
partial trailing record until more bytes arrive. Capture direction and interface name are not part
of the format and are not persisted.

## Platform requirements

JVM desktop requires a JDK with the Foreign Function and Memory API (JDK 22 or newer). It links the
system capture library at runtime: libpcap on Linux and macOS, Npcap on Windows. Capturing traffic
usually requires elevated privileges or the appropriate capabilities.

Native desktop links the same capture library at build time. The Linux and macOS targets link
libpcap. The Windows target links Npcap and needs the Npcap SDK available at build time.

Android targets minSdk 24 and uses `VpnService`. The user must grant VPN consent before capture can
start.

iOS requires a Network Extension packet tunnel target and an App Group shared between the app and
the extension.

## Building from source

```
./gradlew build        # compile and test every target available on the host
./gradlew jvmTest      # JVM tests
./gradlew linuxX64Test # native tests, requires libpcap
```

The macOS and Windows native targets, and the iOS targets, build only on their respective host
operating systems.

## License

Released under the MIT License. See [LICENSE](LICENSE).
