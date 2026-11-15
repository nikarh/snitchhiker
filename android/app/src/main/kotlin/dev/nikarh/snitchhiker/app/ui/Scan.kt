package dev.nikarh.snitchhiker.app.ui

import android.Manifest
import android.content.pm.PackageManager
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.camera.core.CameraSelector
import androidx.camera.core.ImageAnalysis
import androidx.camera.core.Preview
import androidx.camera.lifecycle.ProcessCameraProvider
import androidx.camera.view.PreviewView
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Button
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.google.zxing.BinaryBitmap
import com.google.zxing.MultiFormatReader
import com.google.zxing.PlanarYUVLuminanceSource
import com.google.zxing.common.HybridBinarizer

/** Scans a node's pairing QR code (ZXing, on the device: no service involved). */
@Composable
fun ScanScreen(
    found: (String) -> Unit,
    cancel: () -> Unit,
) {
    val context = LocalContext.current
    val owner = LocalLifecycleOwner.current
    var allowed by remember {
        mutableStateOf(ContextCompat.checkSelfPermission(context, Manifest.permission.CAMERA) == PackageManager.PERMISSION_GRANTED)
    }
    val ask = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { allowed = it }
    LaunchedEffect(Unit) { if (!allowed) ask.launch(Manifest.permission.CAMERA) }
    Box(Modifier.fillMaxSize()) {
        if (allowed) {
            AndroidView(modifier = Modifier.fillMaxSize(), factory = { viewContext ->
                val view = PreviewView(viewContext)
                val providerFuture = ProcessCameraProvider.getInstance(viewContext)
                providerFuture.addListener({
                    val provider = providerFuture.get()
                    val preview = Preview.Builder().build().also { it.surfaceProvider = view.surfaceProvider }
                    val reader = MultiFormatReader()
                    val analysis =
                        ImageAnalysis.Builder().setBackpressureStrategy(ImageAnalysis.STRATEGY_KEEP_ONLY_LATEST).build()
                    var done = false
                    analysis.setAnalyzer(ContextCompat.getMainExecutor(viewContext)) { image ->
                        image.use {
                            if (done) return@use
                            val plane = it.planes[0]
                            val bytes = ByteArray(plane.buffer.remaining()).also { b -> plane.buffer.get(b) }
                            val source =
                                PlanarYUVLuminanceSource(bytes, plane.rowStride, it.height, 0, 0, it.width, it.height, false)
                            val text = runCatching { reader.decode(BinaryBitmap(HybridBinarizer(source))).text }.getOrNull()
                            if (text != null && text.startsWith("snitchhiker://pair")) {
                                done = true
                                provider.unbindAll()
                                found(text)
                            }
                        }
                    }
                    provider.unbindAll()
                    provider.bindToLifecycle(owner, CameraSelector.DEFAULT_BACK_CAMERA, preview, analysis)
                }, ContextCompat.getMainExecutor(viewContext))
                view
            })
        } else {
            Column(Modifier.align(Alignment.Center).padding(16.dp)) {
                Text("Scanning needs the camera. You can type the code or paste the link instead.")
            }
        }
        Button(onClick = cancel, modifier = Modifier.align(Alignment.BottomCenter).padding(24.dp)) { Text("Cancel") }
    }
}
