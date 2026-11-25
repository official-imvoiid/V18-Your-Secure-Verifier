package com.v18.app

import android.content.pm.PackageManager
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import java.math.BigInteger
import java.security.InvalidAlgorithmParameterException
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.ProviderException
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * V18 device keys (PROTOCOL 3.4): EC P-256 in the Android Keystore, StrongBox
 * when the phone has it. Every use needs the user to unlock (fingerprint,
 * strong face unlock, or the screen lock PIN/pattern on Android 11+), and the
 * signing object is unlocked through BiometricPrompt with a CryptoObject, so
 * the private key can never be used without the user.
 *
 * The private key never leaves the Keystore. Signatures are ES256 (DER).
 */
class DeviceKeyChannel(private val activity: FragmentActivity) : MethodChannel.MethodCallHandler {

    private fun keyStore(): KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    override fun onMethodCall(call: MethodCall, result: MethodChannel.Result) {
        try {
            when (call.method) {
                "lockStatus" -> result.success(lockStatus())
                "createKey" -> result.success(
                    createKey(
                        call.argument<String>("alias")!!,
                        call.argument<ByteArray>("attestationChallenge"),
                        call.argument<Boolean>("userAuth") ?: true,
                    )
                )
                "signNoAuth" -> result.success(signNoAuth(call))
                "hasKey" -> result.success(keyStore().containsAlias(call.argument<String>("alias")!!))
                "sign" -> sign(call, result)
                "deleteKey" -> {
                    val ks = keyStore()
                    val alias = call.argument<String>("alias")!!
                    if (ks.containsAlias(alias)) ks.deleteEntry(alias)
                    result.success(null)
                }
                "deleteAllKeys" -> {
                    val prefix = call.argument<String>("prefix")!!
                    val ks = keyStore()
                    for (alias in ks.aliases().toList()) {
                        if (alias.startsWith(prefix)) ks.deleteEntry(alias)
                    }
                    result.success(null)
                }
                else -> result.notImplemented()
            }
        } catch (e: InvalidAlgorithmParameterException) {
            // "Secure lock screen must be enabled to create keys requiring user authentication"
            result.error("no_lock", "Set up a screen lock first", null)
        } catch (e: IllegalStateException) {
            result.error("no_lock", "Set up a screen lock first", null)
        } catch (e: Exception) {
            result.error("error", e.javaClass.simpleName, null)
        }
    }

    private fun authenticators(): Int =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) BIOMETRIC_STRONG or DEVICE_CREDENTIAL
        else BIOMETRIC_STRONG

    private fun lockStatus(): String =
        when (BiometricManager.from(activity).canAuthenticate(authenticators())) {
            BiometricManager.BIOMETRIC_SUCCESS -> "ready"
            BiometricManager.BIOMETRIC_ERROR_NONE_ENROLLED -> "none_enrolled"
            BiometricManager.BIOMETRIC_ERROR_NO_HARDWARE,
            BiometricManager.BIOMETRIC_ERROR_HW_UNAVAILABLE -> "no_hardware"
            else -> "unavailable"
        }

    /**
     * Makes a new P-256 key. With [attestationChallenge] the Keystore also
     * makes an attestation certificate chain (PROTOCOL 4c.3) whose leaf
     * carries that challenge. [userAuth] false is only for the short-lived
     * key of the nullifier request, which is deleted right after.
     */
    private fun createKey(alias: String, attestationChallenge: ByteArray?, userAuth: Boolean): Map<String, Any> {
        val ks = keyStore()
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
        val hasStrongBox = Build.VERSION.SDK_INT >= Build.VERSION_CODES.P &&
            activity.packageManager.hasSystemFeature(PackageManager.FEATURE_STRONGBOX_KEYSTORE)
        var usedStrongBox = false
        if (hasStrongBox) {
            try {
                generate(alias, strongBox = true, attestationChallenge, userAuth)
                usedStrongBox = true
            } catch (e: StrongBoxUnavailableException) {
                generate(alias, strongBox = false, attestationChallenge, userAuth)
            } catch (e: ProviderException) {
                // Some StrongBox chips do not support every option; use the TEE.
                generate(alias, strongBox = false, attestationChallenge, userAuth)
            }
        } else {
            generate(alias, strongBox = false, attestationChallenge, userAuth)
        }
        val ks2 = keyStore()
        val pub = ks2.getCertificate(alias).publicKey as ECPublicKey
        val out = mutableMapOf<String, Any>(
            "x" to fixed32(pub.w.affineX),
            "y" to fixed32(pub.w.affineY),
            "strongBox" to usedStrongBox,
            "secureHardware" to isInSecureHardware(alias),
        )
        if (attestationChallenge != null) {
            // Leaf first, as the Keystore returns it.
            val chain = ks2.getCertificateChain(alias) ?: emptyArray()
            out["attestation"] = chain.map { it.encoded }
        }
        return out
    }

    private fun generate(alias: String, strongBox: Boolean, attestationChallenge: ByteArray?, userAuth: Boolean) {
        val builder = KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256)
        if (attestationChallenge != null) {
            builder.setAttestationChallenge(attestationChallenge)
        }
        if (!userAuth) {
            if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) builder.setIsStrongBoxBacked(true)
            val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
            kpg.initialize(builder.build())
            kpg.generateKeyPair()
            return
        }
        builder.setUserAuthenticationRequired(true)
            .setInvalidatedByBiometricEnrollment(true)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
            // 0 seconds = a fresh unlock for every single signature.
            builder.setUserAuthenticationParameters(
                0, KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
            )
        } else {
            @Suppress("DEPRECATION")
            builder.setUserAuthenticationValidityDurationSeconds(-1)
        }
        if (strongBox && Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
            builder.setIsStrongBoxBacked(true)
        }
        val kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        kpg.initialize(builder.build())
        kpg.generateKeyPair()
    }

    private fun isInSecureHardware(alias: String): Boolean = try {
        val key = keyStore().getKey(alias, null) as PrivateKey
        val info = KeyFactory.getInstance(key.algorithm, ANDROID_KEYSTORE)
            .getKeySpec(key, KeyInfo::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            info.securityLevel == KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT ||
                info.securityLevel == KeyProperties.SECURITY_LEVEL_STRONGBOX
        } else {
            @Suppress("DEPRECATION")
            info.isInsideSecureHardware
        }
    } catch (e: Exception) {
        false
    }

    /** Signs with a key made with userAuth = false (the nullifier request key). */
    private fun signNoAuth(call: MethodCall): ByteArray {
        val alias = call.argument<String>("alias")!!
        val message = call.argument<ByteArray>("message")!!
        val key = keyStore().getKey(alias, null) as? PrivateKey
            ?: throw IllegalStateException("No device key")
        val s = Signature.getInstance("SHA256withECDSA")
        s.initSign(key)
        s.update(message)
        return s.sign()
    }

    private fun sign(call: MethodCall, result: MethodChannel.Result) {
        val alias = call.argument<String>("alias")!!
        val message = call.argument<ByteArray>("message")!!
        val title = call.argument<String>("title") ?: "Confirm it's you"
        val subtitle = call.argument<String>("subtitle") ?: ""

        val key = keyStore().getKey(alias, null) as? PrivateKey
        if (key == null) {
            result.error("no_key", "No device key", null)
            return
        }
        val signature = Signature.getInstance("SHA256withECDSA")
        try {
            signature.initSign(key)
        } catch (e: KeyPermanentlyInvalidatedException) {
            result.error("key_invalidated", "Lock changed", null)
            return
        }

        val info = BiometricPrompt.PromptInfo.Builder()
            .setTitle(title)
            .setSubtitle(subtitle)
            .setConfirmationRequired(false)
            .setAllowedAuthenticators(authenticators())
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.R) {
            info.setNegativeButtonText("Cancel")
        }

        var answered = false
        val prompt = BiometricPrompt(
            activity,
            ContextCompat.getMainExecutor(activity),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(r: BiometricPrompt.AuthenticationResult) {
                    if (answered) return
                    answered = true
                    try {
                        val s = r.cryptoObject?.signature
                            ?: throw IllegalStateException("No crypto object")
                        s.update(message)
                        result.success(s.sign())
                    } catch (e: Exception) {
                        result.error("auth_error", e.javaClass.simpleName, null)
                    }
                }

                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    if (answered) return
                    answered = true
                    val c = when (code) {
                        BiometricPrompt.ERROR_USER_CANCELED,
                        BiometricPrompt.ERROR_NEGATIVE_BUTTON,
                        BiometricPrompt.ERROR_CANCELED -> "cancelled"
                        BiometricPrompt.ERROR_LOCKOUT,
                        BiometricPrompt.ERROR_LOCKOUT_PERMANENT -> "locked_out"
                        BiometricPrompt.ERROR_NO_BIOMETRICS,
                        BiometricPrompt.ERROR_NO_DEVICE_CREDENTIAL -> "no_lock"
                        BiometricPrompt.ERROR_HW_NOT_PRESENT,
                        BiometricPrompt.ERROR_HW_UNAVAILABLE -> "no_biometric_hardware"
                        else -> "auth_error"
                    }
                    result.error(c, msg.toString(), null)
                }
                // onAuthenticationFailed = one wrong finger; the prompt stays open.
            }
        )
        prompt.authenticate(info.build(), BiometricPrompt.CryptoObject(signature))
    }

    private fun fixed32(v: BigInteger): ByteArray {
        val raw = v.toByteArray()
        val out = ByteArray(32)
        val start = if (raw.size > 32) raw.size - 32 else 0
        val len = raw.size - start
        System.arraycopy(raw, start, out, 32 - len, len)
        return out
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}
