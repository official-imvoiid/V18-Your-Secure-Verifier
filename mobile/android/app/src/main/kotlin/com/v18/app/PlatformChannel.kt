package com.v18.app

import android.app.Activity
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.pdf.LoadParams
import android.graphics.pdf.PdfRenderer
import android.os.Build
import android.os.ParcelFileDescriptor
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.io.File
import java.io.FileOutputStream

/**
 * Checks about the phone itself, and PDF page rendering for e-Aadhaar import.
 *
 * Child accounts: Android has no public API that tells a normal app "this is
 * a Google Family Link (supervised) account". Family Link supervision lives in
 * Google Play services, and UserManager restrictions are not a reliable sign.
 * Google's Play Age Signals API is the planned real source, but it only works
 * for apps installed from Google Play. Until it is added, this returns
 * "unknown" and V18 says so honestly (docs/mobile/WALKTHROUGH.md).
 *
 * Phone integrity (Play Integrity) is not in v1 (PROTOCOL 4c.3 makes it
 * optional and off by default; it needs a Play Console project).
 */
class PlatformChannel(private val activity: Activity) : MethodChannel.MethodCallHandler {

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "childAccountStatus" -> result.success("unknown")
            "hasNfc" -> result.success(activity.packageManager.hasSystemFeature(PackageManager.FEATURE_NFC))
            // Credential Manager digital credentials work on Android 9+ with Google Play services.
            "hasDigitalCredentials" -> result.success(Build.VERSION.SDK_INT >= 28)
            "renderPdf" -> renderPdf(call, result)
            "deleteRenderedPages" -> {
                pageDir().listFiles()?.forEach { it.delete() }
                result.success(null)
            }
            else -> result.notImplemented()
        }
    }

    private fun pageDir(): File = File(activity.cacheDir, "v18_pdf_pages").apply { mkdirs() }

    /**
     * Renders the first pages of a PDF to PNG files in the app's private cache,
     * so the QR scanner can read them. The Dart side deletes them right after.
     * Password-protected PDFs (e-Aadhaar) can be opened on Android 15+ only;
     * older Android versions have no built-in way.
     */
    private fun renderPdf(call: MethodCall, result: MethodChannel.Result) {
        val path = call.argument<String>("path")!!
        val password = call.argument<String>("password")
        Thread {
            try {
                val pfd = ParcelFileDescriptor.open(File(path), ParcelFileDescriptor.MODE_READ_ONLY)
                val renderer = try {
                    if (Build.VERSION.SDK_INT >= 35 && !password.isNullOrEmpty()) {
                        PdfRenderer(pfd, LoadParams.Builder().setPassword(password).build())
                    } else {
                        PdfRenderer(pfd)
                    }
                } catch (e: SecurityException) {
                    pfd.close()
                    val code = if (Build.VERSION.SDK_INT >= 35) "pdf_password" else "pdf_password_unsupported"
                    activity.runOnUiThread { result.error(code, "PDF needs a password", null) }
                    return@Thread
                }
                val out = ArrayList<String>()
                renderer.use { r ->
                    val pages = minOf(r.pageCount, 3)
                    for (i in 0 until pages) {
                        r.openPage(i).use { page ->
                            val targetWidth = 2000
                            val scale = targetWidth.toFloat() / page.width
                            val bmp = Bitmap.createBitmap(
                                targetWidth, (page.height * scale).toInt(), Bitmap.Config.ARGB_8888
                            )
                            bmp.eraseColor(Color.WHITE)
                            page.render(bmp, null, null, PdfRenderer.Page.RENDER_MODE_FOR_DISPLAY)
                            val f = File(pageDir(), "page_$i.png")
                            FileOutputStream(f).use { bmp.compress(Bitmap.CompressFormat.PNG, 100, it) }
                            bmp.recycle()
                            out.add(f.absolutePath)
                        }
                    }
                }
                activity.runOnUiThread { result.success(out) }
            } catch (e: Exception) {
                activity.runOnUiThread { result.error("pdf_error", e.javaClass.simpleName, null) }
            }
        }.start()
    }
}
