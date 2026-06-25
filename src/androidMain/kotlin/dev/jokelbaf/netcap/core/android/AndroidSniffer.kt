package dev.jokelbaf.netcap.core.android

import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import dev.jokelbaf.netcap.core.CaptureOptions
import dev.jokelbaf.netcap.core.CaptureState
import dev.jokelbaf.netcap.core.CaptureStats
import dev.jokelbaf.netcap.core.PacketSniffer
import dev.jokelbaf.netcap.core.protocol.Packet
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.stateIn

/**
 * Android [PacketSniffer]. Capture runs in the in-process [SnifferVpnService]; this exposes its
 * unified observation surface: a hot [packets] flow, [state] and [stats].
 *
 * Bringing the TUN up requires the system VPN consent dialog, which can only be shown from an
 * Activity. The host Activity must set [onRequestConsent] and call [onConsentResult] once the user
 * responds. [start] shows the dialog through [onRequestConsent] when consent isn't yet granted, and
 * starts capture directly once it is.
 *
 * @param options [CaptureOptions.filter] is honoured in software (the TUN can't push BPF into the
 *   kernel); [CaptureOptions.snapLength] and [CaptureOptions.promiscuous] don't apply.
 */
class AndroidSniffer(
    context: Context,
    private val options: CaptureOptions = CaptureOptions(),
) : PacketSniffer {

    private val appContext = context.applicationContext
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Default)

    /** Set by the host Activity to launch the VPN consent intent it must own. */
    var onRequestConsent: ((Intent) -> Unit)? = null

    override val packets: Flow<Packet> = AndroidCapture.packets.asSharedFlow()

    override val state: StateFlow<CaptureState> = AndroidCapture.state.asStateFlow()

    override val stats: StateFlow<CaptureStats> = AndroidCapture.store.totalCount
        .map { CaptureStats(received = it) }
        .stateIn(scope, SharingStarted.Eagerly, CaptureStats())

    override fun start() {
        AndroidCapture.filter = options.filter
        val consent = VpnService.prepare(appContext)
        if (consent != null) onRequestConsent?.invoke(consent) else launch(SnifferVpnService.ACTION_START)
    }

    /** Forwards the consent dialog result; capture starts when [granted]. */
    fun onConsentResult(granted: Boolean) {
        if (granted) launch(SnifferVpnService.ACTION_START)
    }

    override fun stop() = launch(SnifferVpnService.ACTION_STOP)

    private fun launch(action: String) {
        val intent = Intent(appContext, SnifferVpnService::class.java).setAction(action)
        if (action == SnifferVpnService.ACTION_START && Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            appContext.startForegroundService(intent)
        } else {
            appContext.startService(intent)
        }
    }
}
