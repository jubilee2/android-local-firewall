import javax.inject.Inject
import org.gradle.api.DefaultTask
import org.gradle.api.file.ConfigurableFileCollection
import org.gradle.api.file.DirectoryProperty
import org.gradle.api.file.RegularFileProperty
import org.gradle.api.tasks.InputFile
import org.gradle.api.tasks.InputFiles
import org.gradle.api.tasks.OutputDirectory
import org.gradle.api.tasks.PathSensitive
import org.gradle.api.tasks.PathSensitivity
import org.gradle.api.tasks.TaskAction
import org.gradle.process.ExecOperations

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.devtools.ksp")
}

abstract class BuildOutlineForwarderTask @Inject constructor(
    private val execOperations: ExecOperations,
) : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val buildScript: RegularFileProperty

    @get:InputFiles
    @get:PathSensitive(PathSensitivity.RELATIVE)
    abstract val sourceInputs: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun buildJni() {
        val outPath = outputDir.get().asFile
        outPath.deleteRecursively()
        outPath.mkdirs()
        execOperations.exec {
            commandLine(buildScript.get().asFile.absolutePath, outPath.absolutePath)
        }
    }
}

val outlineSdkCommitFile = rootProject.file("native/outline-forwarder/OUTLINE_SDK_COMMIT")
val outlineSdkCommit = outlineSdkCommitFile.readText().trim()
require(outlineSdkCommit.matches(Regex("^[0-9a-f]{40}$"))) {
    "OUTLINE_SDK_COMMIT must contain a 40-character lowercase hex SHA"
}

val buildOutlineForwarderJni = tasks.register<BuildOutlineForwarderTask>("buildOutlineForwarderJni") {
    val nativeDir = rootProject.file("native/outline-forwarder")
    buildScript.set(nativeDir.resolve("build-android.sh"))
    sourceInputs.from(
        nativeDir.resolve("OUTLINE_SDK_COMMIT"),
        nativeDir.resolve("go.mod"),
        nativeDir.resolve("go.sum"),
        nativeDir.resolve("main.go"),
        nativeDir.resolve("packet_header.go"),
        nativeDir.resolve("forwarder.go"),
        nativeDir.resolve("jni_bridge.go"),
    )
}

android {
    namespace = "com.localfirewall.app"
    compileSdk = 35
    ndkVersion = "27.2.12479018"

    defaultConfig {
        applicationId = "com.localfirewall.app"
        minSdk = 29
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0"

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"

        ndk {
            abiFilters += listOf("arm64-v8a", "x86_64")
        }

        buildConfigField("String", "OUTLINE_SDK_COMMIT", "\"$outlineSdkCommit\"")
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }
}

androidComponents {
    onVariants { variant ->
        variant.sources.jniLibs?.addGeneratedSourceDirectory(
            buildOutlineForwarderJni,
            BuildOutlineForwarderTask::outputDir,
        )
    }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.01.00")
    val roomVersion = "2.8.5"

    implementation(composeBom)
    androidTestImplementation(composeBom)
    implementation("androidx.activity:activity-compose:1.10.0")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.9.0")
    implementation("androidx.room:room-runtime:$roomVersion")
    implementation("androidx.room:room-ktx:$roomVersion")
    ksp("androidx.room:room-compiler:$roomVersion")
    debugImplementation("androidx.compose.ui:ui-tooling")

    testImplementation("junit:junit:4.13.2")
    testImplementation("org.jetbrains.kotlinx:kotlinx-coroutines-test:1.9.0")
    androidTestImplementation("androidx.test.ext:junit:1.3.0")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.7.0")
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
}
