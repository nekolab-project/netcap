import com.vanniktech.maven.publish.MavenPublishBaseExtension
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    alias(libs.plugins.kotlinMultiplatform)
    alias(libs.plugins.androidMultiplatformLibrary)
    alias(libs.plugins.mavenPublish)
}

group = "dev.jokelbaf"
version = "0.1.2"

kotlin {
    jvmToolchain(25)

    iosArm64()
    iosSimulatorArm64()
    jvm()

    androidLibrary {
        namespace = "dev.jokelbaf.netcap"
        compileSdk = libs.versions.android.compileSdk.get().toInt()
        minSdk = libs.versions.android.minSdk.get().toInt()

        compilerOptions {
            jvmTarget = JvmTarget.JVM_11
        }
    }

    // Native desktop capture targets. cinterop is per-target (no commonization - no single
    // host has all three SDKs); the shared `actual` lives in src/nativePcap and is compiled
    // once per target against that target's libpcap/npcap binding.
    linuxX64 { pcapCinterop("pcap") }
    macosArm64 { pcapCinterop("pcap") }
    mingwX64 { pcapCinterop("npcap") }

    sourceSets {
        val pcapMain = create("pcapMain").apply { dependsOn(commonMain.get()) }
        jvmMain.get().dependsOn(pcapMain)
        for (name in listOf("linuxX64Main", "macosArm64Main", "mingwX64Main")) {
            getByName(name).apply {
                dependsOn(pcapMain)
                kotlin.srcDir("src/nativePcap/kotlin")
            }
        }
        for (name in listOf("linuxX64Test", "macosArm64Test", "mingwX64Test")) {
            getByName(name).kotlin.srcDir("src/nativePcapTest/kotlin")
        }

        val iosMain = create("iosMain").apply { dependsOn(commonMain.get()) }
        for (name in listOf("iosArm64Main", "iosSimulatorArm64Main")) {
            getByName(name).dependsOn(iosMain)
        }
        commonMain.dependencies {
            // api, not implementation: Flow/StateFlow appear in the public API signatures.
            api(libs.kotlinx.coroutinesCore)
        }
        commonTest.dependencies {
            implementation(libs.kotlin.test)
        }
    }
}

/** Adds the libpcap/npcap cinterop (def file [name].def) to a native target's main compilation. */
fun org.jetbrains.kotlin.gradle.plugin.mpp.KotlinNativeTarget.pcapCinterop(name: String) {
    compilations.getByName("main").cinterops.create("pcap") {
        definitionFile.set(project.file("src/nativeInterop/cinterop/$name.def"))
    }
}

configure<MavenPublishBaseExtension> {
    publishToMavenCentral()
    signAllPublications()
    coordinates("dev.jokelbaf", "netcap", version.toString())
    pom {
        name.set("netcap")
        description.set("A pure Kotlin Multiplatform network packet capture library for Android, iOS, JVM and native desktop.")
        url.set("https://github.com/jokelbaf/netcap")
        licenses {
            license {
                name.set("MIT License")
                url.set("https://opensource.org/licenses/MIT")
            }
        }
        developers {
            developer {
                id.set("jokelbaf")
                name.set("jokelbaf")
                url.set("https://github.com/jokelbaf")
            }
        }
        scm {
            url.set("https://github.com/jokelbaf/netcap")
            connection.set("scm:git:git://github.com/jokelbaf/netcap.git")
            developerConnection.set("scm:git:ssh://git@github.com/jokelbaf/netcap.git")
        }
    }
}
