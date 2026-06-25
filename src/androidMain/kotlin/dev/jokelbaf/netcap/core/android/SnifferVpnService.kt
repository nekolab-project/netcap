package dev.jokelbaf.netcap.core.android

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.stack.SnifferEngine
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * The Android TUN provider. It establishes a VPN interface that routes all IPv4
 * traffic through this process, hands the raw packets to [SnifferEngine] for
 * capture + forwarding, and writes the engine's responses back into the TUN.
 */
class SnifferVpnService : VpnService() {

    private var tunInterface: ParcelFileDescriptor? = null
    private var engine: SnifferEngine? = null
    private var readThread: Thread? = null
    private var serviceScope: CoroutineScope? = null

    @Volatile
    private var running = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                stopCapture()
                return START_NOT_STICKY
            }
            else -> startCapture()
        }
        return START_STICKY
    }

    private fun startCapture() {
        if (running) return
        AndroidCapture.state.value = CaptureState.STARTING
        startInForeground()

        val tun = try {
            Builder()
                .setSession(SESSION_NAME)
                .setMtu(MTU)
                .addAddress(TUN_ADDRESS, TUN_PREFIX)
                .addRoute("0.0.0.0", 0)
                .addDnsServer(DNS_SERVER)
                // Claim global-unicast (2000::/3) and ULA (fc00::/7) IPv6 so v6 TCP/UDP
                // is captured too; link-local/multicast stay on the real interface.
                .addAddress(TUN_ADDRESS6, TUN_PREFIX6)
                .addRoute("2000::", 3)
                .addRoute("fc00::", 7)
                .addDnsServer(DNS_SERVER6)
                .establish()
        } catch (t: Throwable) {
            t.printStackTrace()
            null
        }

        if (tun == null) {
            AndroidCapture.state.value = CaptureState.IDLE
            stopSelf()
            return
        }
        tunInterface = tun

        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        serviceScope = scope

        Log.i(TAG, "TUN established: addr=$TUN_ADDRESS/$TUN_PREFIX mtu=$MTU dns=$DNS_SERVER")
        val output = FileOutputStream(tun.fileDescriptor)
        val createdEngine = SnifferEngine(
            channelFactory = AndroidNetworkChannelFactory(this, scope),
            tunWriter = { packet -> runCatching { output.write(packet) } },
            packetSink = AndroidCapture.sink,
            logger = { message ->
                Log.d(TAG, message)
                AndroidCapture.logs.log(message)
            },
        )
        createdEngine.start()
        engine = createdEngine

        running = true
        AndroidCapture.state.value = CaptureState.RUNNING

        readThread = Thread({ readLoop(tun) }, "sniffer-tun-read").apply { start() }
    }

    private fun readLoop(tun: ParcelFileDescriptor) {
        val input = FileInputStream(tun.fileDescriptor)
        val buffer = ByteArray(MTU + HEADROOM)
        var count = 0L
        Log.i(TAG, "TUN read loop started")
        try {
            while (running) {
                val read = input.read(buffer)
                if (read <= 0) continue
                engine?.onTunPacket(buffer, read)
                if (++count % 200L == 0L) Log.d(TAG, "TUN packets read: $count")
            }
        } catch (t: Throwable) {
            Log.w(TAG, "TUN read loop ended: ${t.message}")
        }
    }

    private fun stopCapture() {
        if (!running && tunInterface == null) {
            stopForegroundCompat()
            stopSelf()
            return
        }
        AndroidCapture.state.value = CaptureState.STOPPING
        running = false

        readThread?.interrupt()
        readThread = null

        engine?.stop()
        engine = null

        serviceScope?.cancel()
        serviceScope = null

        runCatching { tunInterface?.close() }
        tunInterface = null

        AndroidCapture.state.value = CaptureState.IDLE
        stopForegroundCompat()
        stopSelf()
    }

    override fun onRevoke() {
        stopCapture()
    }

    override fun onDestroy() {
        if (running) stopCapture()
        super.onDestroy()
    }

    // region foreground notification

    private fun startInForeground() {
        createNotificationChannel()
        val notification = buildNotification()
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(NOTIFICATION_ID, notification, ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE)
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val manager = getSystemService(NotificationManager::class.java)
        if (manager.getNotificationChannel(CHANNEL_ID) == null) {
            manager.createNotificationChannel(
                NotificationChannel(CHANNEL_ID, "Capture", NotificationManager.IMPORTANCE_LOW),
            )
        }
    }

    private fun buildNotification(): Notification {
        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }
        return builder
            .setContentTitle("Sniffer")
            .setContentText("Capturing network traffic")
            .setSmallIcon(android.R.drawable.ic_menu_view)
            .setOngoing(true)
            .build()
    }

    private fun stopForegroundCompat() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
            stopForeground(STOP_FOREGROUND_REMOVE)
        } else {
            @Suppress("DEPRECATION")
            stopForeground(true)
        }
    }

    // endregion

    companion object {
        private const val TAG = "Sniffer"
        const val ACTION_START = "dev.jokelbaf.netcap.action.START"
        const val ACTION_STOP = "dev.jokelbaf.netcap.action.STOP"

        private const val SESSION_NAME = "Sniffer"
        private const val TUN_ADDRESS = "10.215.173.1"
        private const val TUN_PREFIX = 24
        private const val TUN_ADDRESS6 = "fd00:2:fd00:1:fd00:1:fd00:1"
        private const val TUN_PREFIX6 = 128
        private const val DNS_SERVER = "8.8.8.8"
        private const val DNS_SERVER6 = "2001:4860:4860::8888"
        private const val MTU = 1500
        private const val HEADROOM = 80

        private const val CHANNEL_ID = "sniffer_capture"
        private const val NOTIFICATION_ID = 1
    }
}
