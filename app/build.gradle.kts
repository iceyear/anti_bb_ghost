plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.lptiyu.tanke.hook"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.lptiyu.tanke.hook"
        minSdk = 24
        targetSdk = 34
        versionCode = 1
        versionName = "1.0"

        externalNativeBuild {
            cmake {
                cppFlags += "-std=c++17"
                abiFilters += "arm64-v8a"
            }
        }
        ndk {
            abiFilters.add("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
    kotlinOptions {
        jvmTarget = "1.8"
    }
    externalNativeBuild {
        cmake {
            path("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildFeatures {
        prefab = true
    }
    packaging {
        jniLibs {
            useLegacyPackaging = false
            pickFirsts.add("**/libshadowhook.so")
        }
    }
}

dependencies {
    compileOnly("de.robv.android.xposed:api:82")
    implementation("com.bytedance.android:shadowhook:1.0.10")
}
