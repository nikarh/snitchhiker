package dev.nikarh.snitchhiker.app.ui

import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color

// The app's own palette (not the stock one): a deep slate blue, with amber for what needs a look and red for what was
// refused. Dark first.
private val dark =
    darkColorScheme(
        primary = Color(0xFF8CB8E0),
        onPrimary = Color(0xFF0D2236),
        primaryContainer = Color(0xFF1F3A54),
        onPrimaryContainer = Color(0xFFD3E5F5),
        secondary = Color(0xFFB7C6D3),
        tertiary = Color(0xFFF2C46C),
        onTertiary = Color(0xFF3A2A00),
        error = Color(0xFFF08A80),
        background = Color(0xFF101418),
        surface = Color(0xFF101418),
        surfaceVariant = Color(0xFF1C2228),
        surfaceContainer = Color(0xFF171C21),
        onSurface = Color(0xFFE2E7EC),
        onSurfaceVariant = Color(0xFFA9B4BF),
        outline = Color(0xFF3B4650),
    )

private val light =
    lightColorScheme(
        primary = Color(0xFF285A85),
        onPrimary = Color.White,
        primaryContainer = Color(0xFFD3E5F5),
        onPrimaryContainer = Color(0xFF0D2236),
        secondary = Color(0xFF4F5F6D),
        tertiary = Color(0xFF8A6100),
        error = Color(0xFFB3261E),
        background = Color(0xFFF7F9FB),
        surface = Color(0xFFF7F9FB),
        surfaceVariant = Color(0xFFE3E9EE),
        surfaceContainer = Color(0xFFEDF1F4),
        onSurface = Color(0xFF161C21),
        onSurfaceVariant = Color(0xFF4A5560),
        outline = Color(0xFFBAC4CC),
    )

@Composable
fun SnitchhikerTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = if (isSystemInDarkTheme()) dark else light, content = content)
}
