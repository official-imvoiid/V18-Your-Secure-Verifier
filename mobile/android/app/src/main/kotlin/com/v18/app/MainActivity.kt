package com.v18.app

import io.flutter.embedding.android.FlutterFragmentActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel

/**
 * FlutterFragmentActivity (not FlutterActivity) because BiometricPrompt needs a
 * FragmentActivity.
 */
class MainActivity : FlutterFragmentActivity() {
    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        val messenger = flutterEngine.dartExecutor.binaryMessenger
        MethodChannel(messenger, "com.v18.app/device_key")
            .setMethodCallHandler(DeviceKeyChannel(this))
        MethodChannel(messenger, "com.v18.app/platform")
            .setMethodCallHandler(PlatformChannel(this))
        MethodChannel(messenger, "com.v18.app/wallet")
            .setMethodCallHandler(WalletChannel(this))
    }
}
