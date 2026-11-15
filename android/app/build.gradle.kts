import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
}

// One version for everything: `[workspace.package]` in the root Cargo.toml.
val appVersion: String =
    rootProject
        .file("../Cargo.toml")
        .readLines()
        .dropWhile { it.trim() != "[workspace.package]" }
        .first { it.trim().startsWith("version") }
        .substringAfter('"')
        .substringBefore('"')
val appVersionCode: Int = appVersion.split('.').map(String::toInt).let { (major, minor, patch) -> major * 10_000 + minor * 100 + patch }

// Release builds are signed with the release key when it is in the environment, and with the debug key otherwise.
val releaseKeystore: String? = System.getenv("ANDROID_KEYSTORE")?.takeIf { it.isNotEmpty() }

android {
    namespace = "dev.nikarh.snitchhiker.app"
    compileSdk = 37

    defaultConfig {
        applicationId = "dev.nikarh.snitchhiker"
        minSdk = 29
        targetSdk = 36
        versionCode = appVersionCode
        versionName = appVersion + System.getenv("SNITCHHIKER_VERSION_SUFFIX").orEmpty()
    }

    // Push (plan §8.5): `foss` wakes through UnifiedPush only (F-Droid); `play` through FCM, with the Firebase project
    // given at build time (FCM_PROJECT_ID, FCM_APP_ID, FCM_API_KEY, FCM_SENDER_ID), or UnifiedPush without one.
    flavorDimensions += "push"
    productFlavors {
        create("foss") {
            dimension = "push"
        }
        create("play") {
            dimension = "push"
            for (name in listOf("FCM_PROJECT_ID", "FCM_APP_ID", "FCM_API_KEY", "FCM_SENDER_ID")) {
                buildConfigField("String", name, "\"${System.getenv(name).orEmpty()}\"")
            }
        }
    }

    signingConfigs {
        if (releaseKeystore != null) {
            create("release") {
                storeFile = file(releaseKeystore)
                storePassword = System.getenv("ANDROID_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("ANDROID_KEY_ALIAS")
                keyPassword = System.getenv("ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            signingConfig = signingConfigs.findByName("release") ?: signingConfigs.getByName("debug")
        }
    }

    dependenciesInfo {
        includeInApk = false
        includeInBundle = false
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    lint {
        warningsAsErrors = true
        abortOnError = true
        checkDependencies = true
        disable += setOf("GradleDependency", "NewerVersionAvailable", "AndroidGradlePluginVersion", "OldTargetApi")
    }
}

kotlin {
    compilerOptions {
        jvmTarget = JvmTarget.JVM_17
        allWarningsAsErrors = true
    }
}

dependencies {
    implementation(project(":core"))
    implementation(platform(libs.compose.bom))
    implementation(libs.activity.compose)
    implementation(libs.camera.camera2)
    implementation(libs.camera.lifecycle)
    implementation(libs.camera.view)
    implementation(libs.compose.icons)
    implementation(libs.compose.material3)
    implementation(libs.compose.ui)
    implementation(libs.compose.ui.tooling.preview)
    implementation(libs.core.ktx)
    implementation(libs.coroutines.android)
    implementation(libs.lifecycle.runtime.compose)
    implementation(libs.lifecycle.viewmodel.compose)
    implementation(libs.unifiedpush.connector)
    implementation(libs.zxing.core)
    "playImplementation"(libs.firebase.messaging)
    debugImplementation(libs.compose.ui.tooling)
}
