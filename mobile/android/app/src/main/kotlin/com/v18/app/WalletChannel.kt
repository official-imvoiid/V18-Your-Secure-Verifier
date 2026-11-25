package com.v18.app

import android.app.Activity
import android.os.Build
import android.os.CancellationSignal
import android.util.Base64
import androidx.core.content.ContextCompat
import androidx.credentials.CredentialManager
import androidx.credentials.CredentialManagerCallback
import androidx.credentials.DigitalCredential
import androidx.credentials.ExperimentalDigitalCredentialApi
import androidx.credentials.GetCredentialRequest
import androidx.credentials.GetCredentialResponse
import androidx.credentials.GetDigitalCredentialOption
import androidx.credentials.exceptions.GetCredentialCancellationException
import androidx.credentials.exceptions.GetCredentialException
import androidx.credentials.exceptions.NoCredentialException
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.security.MessageDigest

/**
 * `mdoc_app` (PROTOCOL 4d.3): asks another wallet on this phone (Google Wallet,
 * an EU digital identity wallet, a national mDL app) for ONLY `age_over_18`,
 * through Android Credential Manager's digital credentials API.
 *
 * The request JSON comes from the V18 server (POST /v1/wallet/app-request) and
 * is passed on untouched; the wallet's answer (encrypted to the server) is
 * passed back untouched. This app never reads what is inside.
 */
class WalletChannel(private val activity: Activity) : MethodChannel.MethodCallHandler {

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "getDigitalCredential" -> get(call.argument<String>("requestJson")!!, result)
            "appOrigin" -> result.success(appOrigin())
            else -> result.notImplemented()
        }
    }

    @OptIn(ExperimentalDigitalCredentialApi::class)
    private fun get(requestJson: String, result: MethodChannel.Result) {
        val request = GetCredentialRequest(listOf(GetDigitalCredentialOption(requestJson = requestJson)))
        val manager = CredentialManager.create(activity)
        manager.getCredentialAsync(
            activity,
            request,
            CancellationSignal(),
            ContextCompat.getMainExecutor(activity),
            object : CredentialManagerCallback<GetCredentialResponse, GetCredentialException> {
                override fun onResult(r: GetCredentialResponse) {
                    val c = r.credential
                    if (c is DigitalCredential) {
                        result.success(c.credentialJson)
                    } else {
                        result.error("wrong_type", "Not a digital credential", null)
                    }
                }

                override fun onError(e: GetCredentialException) {
                    when (e) {
                        is GetCredentialCancellationException -> result.error("cancelled", "Cancelled", null)
                        is NoCredentialException -> result.error("no_credential", "No wallet ID", null)
                        else -> result.error("wallet_error", e.type, null)
                    }
                }
            },
        )
    }

    /**
     * The origin Credential Manager gives this app:
     * `android:apk-key-hash:<base64url SHA-256 of the signing certificate>`.
     */
    private fun appOrigin(): String? = try {
        val pm = activity.packageManager
        val cert: ByteArray = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            val info = pm.getPackageInfo(activity.packageName, android.content.pm.PackageManager.GET_SIGNING_CERTIFICATES)
            info.signingInfo!!.apkContentsSigners[0].toByteArray()
        } else {
            @Suppress("DEPRECATION")
            val info = pm.getPackageInfo(activity.packageName, android.content.pm.PackageManager.GET_SIGNATURES)
            @Suppress("DEPRECATION")
            info.signatures!![0].toByteArray()
        }
        val digest = MessageDigest.getInstance("SHA-256").digest(cert)
        "android:apk-key-hash:" + Base64.encodeToString(digest, Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP)
    } catch (e: Exception) {
        null
    }
}
