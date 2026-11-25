import java.io.FileInputStream
import java.util.Properties

plugins {
    id("com.android.application")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

// Release signing (PROTOCOL 4c.7): the upload key lives OUTSIDE the project,
// in C:\Users\<you>\.v18-keys\ by default. Set V18_UPLOAD_KEY_PROPERTIES to use
// another file. See docs/mobile/RELEASE.md. The key is never in mobile/.
val uploadKeyProps: File = System.getenv("V18_UPLOAD_KEY_PROPERTIES")?.let { File(it) }
    ?: File(System.getProperty("user.home"), ".v18-keys/upload-key.properties")
val uploadKey = Properties().apply {
    if (uploadKeyProps.isFile) FileInputStream(uploadKeyProps).use { load(it) }
}

android {
    namespace = "com.v18.app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    defaultConfig {
        applicationId = "com.v18.app"
        // 28: BiometricPrompt, StrongBox and a stable Keystore API.
        minSdk = 28
        targetSdk = flutter.targetSdkVersion
        versionCode = flutter.versionCode
        versionName = flutter.versionName
        ndk {
            // The Anon Aadhaar prover (libv18_prover.so, mobile/native/v18_prover)
            // is built for 64-bit phones only (it needs more than 2 GB of memory
            // while proving). x86_64 is for the emulator.
            abiFilters += listOf("arm64-v8a", "x86_64")
        }
    }

    signingConfigs {
        create("upload") {
            if (uploadKey.isNotEmpty()) {
                storeFile = File(uploadKey.getProperty("storeFile"))
                storePassword = uploadKey.getProperty("storePassword")
                keyAlias = uploadKey.getProperty("keyAlias")
                keyPassword = uploadKey.getProperty("keyPassword")
            }
        }
    }

    buildTypes {
        release {
            val wantsRelease = gradle.startParameter.taskNames.any { it.contains("Release", ignoreCase = true) }
            if (uploadKey.isEmpty() && wantsRelease) {
                throw GradleException(
                    "No upload key found at $uploadKeyProps. Release builds are signed only with the " +
                        "V18 upload key kept outside the project. See docs/mobile/RELEASE.md."
                )
            }
            if (uploadKey.isNotEmpty()) signingConfig = signingConfigs.getByName("upload")
            // R8: shrink and obfuscate the Kotlin/Java side.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }

    packaging {
        jniLibs {
            // Keep native libraries uncompressed and page aligned (faster start).
            useLegacyPackaging = false
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

flutter {
    source = "../.."
}

dependencies {
    // BiometricPrompt with a CryptoObject for the device key (DeviceKeyChannel.kt).
    implementation("androidx.biometric:biometric:1.1.0")
    // Credential Manager digital credentials for mdoc_app (PROTOCOL 4d.3).
    implementation("androidx.credentials:credentials:1.5.0")
    implementation("androidx.credentials:credentials-play-services-auth:1.5.0")
}
