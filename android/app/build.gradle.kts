plugins {
    id("com.android.application")
}

android {
    namespace = "io.ciphervaultx.app"
    compileSdk = 34

    defaultConfig {
        applicationId = "io.ciphervaultx.app"
        minSdk = 26
        targetSdk = 34
        versionCode = 1
        versionName = "0.1.0"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Sign release APK with debug keystore so the user can install it directly on Android without adb
            signingConfig = signingConfigs.getByName("debug")
        }
        debug {
            applicationIdSuffix = ""
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

dependencies {
}
