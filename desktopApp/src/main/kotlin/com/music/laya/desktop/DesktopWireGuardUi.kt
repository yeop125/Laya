package com.music.laya.desktop

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Switch
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import java.awt.FileDialog
import java.awt.Frame
import java.awt.Toolkit
import java.awt.datatransfer.DataFlavor
import java.io.File
import kotlin.system.exitProcess

/** Settings → Advanced → WireGuard: turn the app-local tunnel on, import its profile. */
@Composable
internal fun DesktopWireGuardDialog(onDismiss: () -> Unit) {
    val status by DesktopWireGuard.status.collectAsState()
    var enabled by remember { mutableStateOf(DesktopWireGuard.enabled()) }
    var profileHost by remember { mutableStateOf(DesktopWireGuard.loadProfile()?.let(DesktopWireGuard::describe)) }
    var message by remember { mutableStateOf<Pair<String, Color>?>(null) }
    // Whether something changed that only takes effect at the next launch.
    var changed by remember { mutableStateOf(false) }

    fun import(text: String?) {
        if (text.isNullOrBlank()) {
            message = DesktopStrings["d_wg_nothing_to_import", "Nothing to import"] to WARNING
            return
        }
        val problem = DesktopWireGuard.problemWith(text)
        if (problem != null) {
            message = DesktopStrings["d_wg_not_a_profile", "This is not a WireGuard profile"] + " ($problem)" to WARNING
            return
        }
        runCatching { DesktopWireGuard.saveProfile(text) }
            .onSuccess {
                profileHost = DesktopWireGuard.describe(text)
                message = DesktopStrings["d_wg_imported", "Profile imported"] to OK
                changed = true
            }
            .onFailure { message = (it.message ?: "Could not save the profile") to WARNING }
    }

    DesktopDialogPanel(onDismiss = onDismiss, maxWidth = 460) {
        Column(
            Modifier.fillMaxWidth().padding(horizontal = panelInset(20.dp), vertical = 18.dp),
            verticalArrangement = Arrangement.spacedBy(14.dp),
        ) {
            Column {
                Text("WireGuard", style = MaterialTheme.typography.titleLarge, color = Color.White)
                Text(
                    DesktopStrings[
                        "d_wg_explainer",
                        "Sends only Laya's traffic through your WireGuard server. No system VPN or administrator rights are needed.",
                    ],
                    style = MaterialTheme.typography.bodyMedium,
                    color = DesktopSecondary,
                )
            }

            // What is running right now, in this launch.
            val (statusText, statusColor) = when (status.state) {
                DesktopWireGuard.State.RUNNING ->
                    DesktopStrings["d_wg_status_running", "Connected — all of Laya's traffic goes through the tunnel"] to OK
                DesktopWireGuard.State.FAILED ->
                    (DesktopStrings["d_wg_status_failed", "Could not start — the network is blocked until this is fixed or WireGuard is turned off"] +
                        "\n" + status.detail) to WARNING
                DesktopWireGuard.State.OFF ->
                    DesktopStrings["d_wg_status_off", "Off — Laya connects directly"] to DesktopSecondary
            }
            Text(statusText, color = statusColor, style = MaterialTheme.typography.bodyMedium)

            Row(
                Modifier.fillMaxWidth().clip(RoundedCornerShape(10.dp)).clickable {
                    if (!enabled && profileHost == null) {
                        message = DesktopStrings["d_wg_import_first", "Import a profile first"] to WARNING
                        return@clickable
                    }
                    enabled = !enabled
                    DesktopWireGuard.setEnabled(enabled)
                    changed = true
                }.padding(vertical = 8.dp),
                verticalAlignment = Alignment.CenterVertically,
            ) {
                Column(Modifier.weight(1f)) {
                    Text(DesktopStrings["d_wg_use", "Use WireGuard"], style = MaterialTheme.typography.bodyLarge, color = Color.White)
                    Text(
                        profileHost?.let { DesktopStrings["d_wg_profile_server", "Server"] + ": " + it }
                            ?: DesktopStrings["d_wg_no_profile", "No profile imported"],
                        style = MaterialTheme.typography.bodyMedium,
                        color = DesktopSecondary,
                    )
                }
                Spacer(Modifier.width(18.dp))
                Switch(
                    checked = enabled,
                    onCheckedChange = null,
                    colors = desktopSwitchColors(),
                )
            }

            Row(horizontalArrangement = Arrangement.spacedBy(10.dp)) {
                Pill(DesktopStrings["d_wg_import_file", "Import .conf file"]) { import(pickConfFile()) }
                Pill(DesktopStrings["d_wg_paste", "Paste from clipboard"]) { import(clipboardText()) }
                if (profileHost != null) {
                    Pill(DesktopStrings["d_wg_remove", "Remove"]) {
                        DesktopWireGuard.saveProfile(null)
                        DesktopWireGuard.setEnabled(false)
                        enabled = false
                        profileHost = null
                        changed = true
                        message = DesktopStrings["d_wg_removed", "Profile removed"] to DesktopSecondary
                    }
                }
            }

            message?.let { (text, color) -> Text(text, color = color, style = MaterialTheme.typography.bodyMedium) }

            if (changed) {
                Text(
                    DesktopStrings["d_wg_restart_needed", "Quit and reopen Laya to apply this change."],
                    color = Color.White,
                    fontWeight = FontWeight.SemiBold,
                    style = MaterialTheme.typography.bodyMedium,
                )
            }
        }

        Row(Modifier.fillMaxWidth().padding(horizontal = panelInset(20.dp), vertical = 14.dp)) {
            if (changed) {
                TextButton(onClick = { exitProcess(0) }) {
                    Text(DesktopStrings["d_wg_quit_now", "Quit Laya now"], color = Color.White)
                }
            }
            Spacer(Modifier.weight(1f))
            TextButton(onClick = onDismiss) { Text(DesktopStrings["done", "Done"], color = Color.White) }
        }
    }
}

@Composable
private fun Pill(label: String, onClick: () -> Unit) {
    Text(
        label,
        color = Color.Black,
        fontWeight = FontWeight.SemiBold,
        style = MaterialTheme.typography.bodyMedium,
        modifier = Modifier
            .clip(CircleShape)
            .background(DesktopAccent)
            .clickable(onClick = onClick)
            .padding(horizontal = 14.dp, vertical = 8.dp),
    )
}

private val OK = Color(0xFF34C759)
private val WARNING = Color(0xFFFF9F0A)

/** A native file picker for a wg-quick `.conf`; its text, or null when cancelled. */
private fun pickConfFile(): String? {
    val dialog = FileDialog(null as Frame?, "WireGuard", FileDialog.LOAD).apply {
        file = "*.conf"
        setFilenameFilter { _, name -> name.endsWith(".conf", ignoreCase = true) }
        isVisible = true
    }
    val name = dialog.file ?: return null
    val file = File(dialog.directory, name)
    // A real profile is a few hundred bytes; anything large is not one.
    if (!file.isFile || file.length() > 64 * 1024) return null
    return runCatching { file.readText(Charsets.UTF_8) }.getOrNull()
}

private fun clipboardText(): String? = runCatching {
    Toolkit.getDefaultToolkit().systemClipboard.getData(DataFlavor.stringFlavor) as? String
}.getOrNull()?.takeIf { it.length <= 64 * 1024 }
