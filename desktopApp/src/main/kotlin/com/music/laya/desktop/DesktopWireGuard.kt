package com.music.laya.desktop

import com.music.laya.data.AppProxyKind
import com.music.laya.data.AppProxyRoute
import com.music.laya.data.Http
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.bytedeco.ffmpeg.avutil.AVDictionary
import org.bytedeco.ffmpeg.global.avutil.av_dict_set
import java.io.BufferedReader
import java.io.File
import java.io.IOException
import java.io.InputStreamReader
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.StandardCopyOption
import java.util.Base64
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

/**
 * App-local WireGuard for the desktop, the counterpart of Android's AppWireGuard.
 *
 * The engine is the same Go code the iOS build links in (WireGuard/), built as a small executable
 * (`laya_wg.exe`) and shipped inside the jar. At launch, before any network client exists, it is
 * started as a child process; it brings up a userspace WireGuard tunnel (no system VPN, no admin
 * rights, no driver) and listens on 127.0.0.1 for HTTP CONNECT and SOCKS5. Every network stack in
 * this process is then pointed at that listener:
 *
 *  - the shared OkHttp client (API, lyrics, downloads), through [Http.configureAtStartup];
 *  - everything else on the JVM — the JavaFX WebView sign-in and PoToken minting,
 *    HttpURLConnection, java.net.http — through a default [ProxySelector];
 *  - FFmpeg, which opens stream URLs itself, through its `http_proxy` option ([applyToFfmpeg]).
 *
 * If WireGuard is on but cannot start, the app fails closed: every route points at a dead local
 * port rather than silently going direct. The engine exits by itself when this process does,
 * because it runs until its stdin closes.
 *
 * Changes apply at the next launch, as on Android.
 */
internal object DesktopWireGuard {

    enum class State { OFF, RUNNING, FAILED }

    data class Status(val state: State, val detail: String = "")

    private const val KEY_ENABLED = "wireguard_enabled"
    private const val KEY_PROFILE = "wireguard_profile"
    private const val LOOPBACK = "127.0.0.1"

    private val _status = MutableStateFlow(Status(State.OFF))
    val status: StateFlow<Status> = _status

    /** The local listener's port while the tunnel runs, else null. */
    @Volatile var port: Int? = null
        private set

    /** Where traffic is sent when WireGuard is on but failed: a closed port, so nothing leaks. */
    @Volatile private var blockedPort: Int? = null

    @Volatile private var process: Process? = null

    private val persistence by lazy { DesktopPersistence() }

    // ---- Settings ---------------------------------------------------------------------------

    fun enabled(): Boolean = persistence.boolean(KEY_ENABLED, false)

    fun setEnabled(value: Boolean) = persistence.saveBoolean(KEY_ENABLED, value)

    fun hasProfile(): Boolean = loadProfile() != null

    /** The stored profile, sealed with DPAPI on Windows. Never logged or shown. */
    fun loadProfile(): String? {
        val stored = persistence.string(KEY_PROFILE).takeIf(String::isNotBlank) ?: return null
        if (!DesktopPlatform.isWindows) return stored
        return runCatching { Base64.getDecoder().decode(stored) }.getOrNull()
            ?.let(DesktopWindowsCrypto::unprotect)
            ?.toString(StandardCharsets.UTF_8)
    }

    fun saveProfile(text: String?) {
        val value = when {
            text.isNullOrBlank() -> ""
            !DesktopPlatform.isWindows -> text
            else -> DesktopWindowsCrypto.protect(text.toByteArray(StandardCharsets.UTF_8))
                ?.let(Base64.getEncoder()::encodeToString)
                ?: error("Windows could not protect the WireGuard profile")
        }
        persistence.saveString(KEY_PROFILE, value)
    }

    /**
     * A light check of a wg-quick `.conf` before it is stored; the engine does the real parsing at
     * launch. Returns an error message, or null when it looks usable.
     */
    fun problemWith(text: String): String? {
        val lines = text.lineSequence().map { it.substringBefore('#').trim() }.filter(String::isNotEmpty).toList()
        fun has(key: String) = lines.any { it.substringBefore('=').trim().equals(key, ignoreCase = true) }
        return when {
            lines.none { it.equals("[Interface]", ignoreCase = true) } -> "No [Interface] section"
            lines.none { it.equals("[Peer]", ignoreCase = true) } -> "No [Peer] section"
            !has("PrivateKey") -> "No PrivateKey"
            !has("PublicKey") -> "No peer PublicKey"
            !has("Endpoint") -> "No peer Endpoint"
            !has("Address") -> "No Address"
            else -> null
        }
    }

    /** Non-secret facts about a profile for the settings screen: the endpoint's host only. */
    fun describe(text: String): String {
        val endpoint = text.lineSequence()
            .map { it.substringBefore('#').trim() }
            .firstOrNull { it.substringBefore('=').trim().equals("Endpoint", ignoreCase = true) }
            ?.substringAfter('=')?.trim().orEmpty()
        val host = endpoint.substringBeforeLast(':').removePrefix("[").removeSuffix("]")
        return host.ifBlank { "?" }
    }

    // ---- Launch -----------------------------------------------------------------------------

    /** Exactly once, first thing in main(), before any network client or WebView exists. */
    @Synchronized
    fun startAtLaunch() {
        if (!enabled()) {
            _status.value = Status(State.OFF)
            return
        }
        try {
            val profile = loadProfile() ?: throw IOException("No WireGuard profile has been imported")
            val listening = launchEngine(profile)
            port = listening
            route(listening)
            _status.value = Status(State.RUNNING, "127.0.0.1:$listening")
            DesktopTrackLog.log("WireGuard/I: tunnel up, local proxy on port $listening")
        } catch (error: Throwable) {
            // No direct fallback. The message is the engine's own, which never carries keys.
            port = null
            failClosed()
            val message = error.message?.take(200) ?: error.javaClass.simpleName
            _status.value = Status(State.FAILED, message)
            DesktopTrackLog.log("WireGuard/E: could not start ($message); network blocked until it is fixed or turned off")
        }
    }

    private fun launchEngine(profile: String): Int {
        val executable = unpackEngine()
        val child = ProcessBuilder(executable.absolutePath)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .start()
        process = child
        Runtime.getRuntime().addShutdownHook(Thread({ runCatching { child.destroy() } }, "laya-wireguard-stop"))
        val request = JsonObject(
            mapOf(
                "profile" to JsonPrimitive(profile),
                "user" to JsonPrimitive(""),
                "pass" to JsonPrimitive(""),
                "openLocal" to JsonPrimitive(true),
            ),
        ).toString() + "\n"
        child.outputStream.write(request.toByteArray(StandardCharsets.UTF_8))
        child.outputStream.flush()
        // Deliberately left open: closing stdin is what tells the engine to stop.

        val reader = BufferedReader(InputStreamReader(child.inputStream, StandardCharsets.UTF_8))
        val line = CompletableFuture.supplyAsync { reader.readLine() }
            .get(30, TimeUnit.SECONDS)
            ?: throw IOException("The WireGuard engine exited (code ${child.waitFor(2, TimeUnit.SECONDS).let { if (it) child.exitValue() else -1 }})")
        val reply = Json.parseToJsonElement(line).jsonObject
        if (reply["ok"]?.jsonPrimitive?.booleanOrNull != true) {
            child.destroy()
            throw IOException(reply["error"]?.jsonPrimitive?.content ?: "The WireGuard engine refused the profile")
        }
        val listening = reply["port"]?.jsonPrimitive?.intOrNull ?: throw IOException("No local port")
        check(listening in 1..65535) { "Invalid local port" }
        return listening
    }

    /** Copies the engine out of the jar, beside the analyser's natives, when it changed. */
    private fun unpackEngine(): File {
        val name = if (DesktopPlatform.isWindows) "laya_wg.exe" else "laya_wg"
        val resource = "/native/$name"
        val home = File(DesktopAnalysisRuntime.analysisHome().parentFile, "wireguard").apply { mkdirs() }
        val target = File(home, name)
        val url = javaClass.getResource(resource)
            ?: throw IOException("This build does not include the WireGuard engine")
        val connection = url.openConnection()
        val expected = connection.contentLengthLong
        if (!(target.isFile && expected > 0 && target.length() == expected &&
                target.lastModified() >= connection.lastModified)
        ) {
            val partial = File(home, "$name.partial")
            connection.getInputStream().use { Files.copy(it, partial.toPath(), StandardCopyOption.REPLACE_EXISTING) }
            Files.move(partial.toPath(), target.toPath(), StandardCopyOption.REPLACE_EXISTING)
        }
        target.setExecutable(true, true)
        return target
    }

    // ---- Routing ----------------------------------------------------------------------------

    private fun route(listening: Int) {
        // The shared OkHttp client: HTTP CONNECT to the loopback listener (no login needed).
        Http.configureAtStartup(AppProxyRoute(AppProxyKind.HTTP, LOOPBACK, listening))
        ProxySelector.setDefault(LoopbackProxySelector(listening))
    }

    private fun failClosed() {
        val dead = deadPort()
        blockedPort = dead
        runCatching { Http.configureAtStartup(AppProxyRoute(AppProxyKind.HTTP, LOOPBACK, dead)) }
        ProxySelector.setDefault(LoopbackProxySelector(dead))
    }

    /** A loopback port nothing listens on: bound, read, released. */
    private fun deadPort(): Int = runCatching {
        java.net.ServerSocket(0, 1, InetAddress.getByName(LOOPBACK)).use { it.localPort }
    }.getOrDefault(9)

    /**
     * FFmpeg opens stream URLs with its own network code, outside the JVM. Its http and tls
     * protocols (and the HLS/DASH demuxers, for their segments) take `http_proxy`, tunnelling
     * https through CONNECT. Plain http through it is refused by the engine, which fails closed.
     */
    fun applyToFfmpeg(options: AVDictionary) {
        val target = port ?: blockedPort ?: return
        av_dict_set(options, "http_proxy", "http://$LOOPBACK:$target", 0)
    }

    /** Proxy for JVM stacks other than the shared client. Loopback stays direct. */
    private class LoopbackProxySelector(private val listening: Int) : ProxySelector() {
        private val http = listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress(LOOPBACK, listening)))
        private val socks = listOf(Proxy(Proxy.Type.SOCKS, InetSocketAddress(LOOPBACK, listening)))

        override fun select(uri: URI?): List<Proxy> {
            val host = uri?.host?.trim('[', ']')?.lowercase().orEmpty()
            if (host.isEmpty() || isLoopback(host)) return listOf(Proxy.NO_PROXY)
            return when (uri?.scheme?.lowercase()) {
                "http", "https", "ws", "wss" -> http
                else -> socks
            }
        }

        override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: IOException?) = Unit

        private fun isLoopback(host: String): Boolean =
            host == "localhost" || host.endsWith(".localhost") || host == "::1" ||
                host.startsWith("127.") || host == "0:0:0:0:0:0:0:1"
    }
}
