# V18 R8 rules. Flutter adds its own rules for the engine and plugins.

# Kotlin method-channel handlers (called by name from Dart).
-keep class com.v18.app.** { *; }

# Credential Manager (mdoc_app) uses reflection to find the provider.
-keep class androidx.credentials.** { *; }
-keep class * extends androidx.credentials.CredentialProvider
-dontwarn androidx.credentials.**

# ML Kit text recognition (MRZ) and barcode scanning load models by class name.
-keep class com.google.mlkit.** { *; }
-dontwarn com.google.mlkit.**
-keep class com.google.android.gms.internal.mlkit_vision_** { *; }

# Play Core is referenced by the Flutter engine for deferred components (not used).
-dontwarn com.google.android.play.core.**
