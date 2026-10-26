plugins {
    id("org.jetbrains.kotlin.jvm") version "2.4.21"
    id("org.jetbrains.kotlin.plugin.allopen") version "2.4.21"
    id("com.google.devtools.ksp") version "2.3.12"
    id("io.micronaut.application") version "5.0.2"
    id("com.gradleup.shadow") version "9.6.1"
    id("io.micronaut.aot") version "5.0.2"
}

version = "0.1"
group = "at.yawk.deviceca"

val kotlinVersion = project.property("kotlinVersion")
repositories {
    mavenCentral()
}

dependencies {
    ksp("io.micronaut:micronaut-http-validation")
    ksp("io.micronaut.serde:micronaut-serde-processor")
    implementation("io.micronaut.kotlin:micronaut-kotlin-runtime")
    implementation("io.micronaut.serde:micronaut-serde-jackson")
    implementation("org.jetbrains.kotlin:kotlin-reflect:${kotlinVersion}")
    implementation("org.jetbrains.kotlin:kotlin-stdlib:${kotlinVersion}")
    compileOnly("io.micronaut:micronaut-http-client")
    runtimeOnly("ch.qos.logback:logback-classic")
    runtimeOnly("tools.jackson.module:jackson-module-kotlin")
    testImplementation("io.micronaut:micronaut-http-client")

    implementation("org.bouncycastle:bcpkix-jdk18on:1.86")
    implementation("org.apache.commons:commons-compress:1.28.0")
    implementation("org.shredzone.acme4j:acme4j-client:5.1.0")
}


application {
    mainClass = "at.yawk.deviceca.ApplicationKt"
}
java {
    sourceCompatibility = JavaVersion.toVersion("25")
}


graalvmNative.toolchainDetection = false

micronaut {
    runtime("netty")
    testRuntime("junit5")
    processing {
        incremental(true)
        annotations("at.yawk.deviceca.*")
    }
    aot {
        // Please review carefully the optimizations enabled below
        // Check https://micronaut-projects.github.io/micronaut-aot/latest/guide/ for more details
        optimizeServiceLoading = false
        convertYamlToJava = false
        precomputeOperations = true
        cacheEnvironment = true
        optimizeClassLoading = true
        deduceEnvironment = true
        optimizeNetty = true
        replaceLogbackXml = true
    }
}


tasks.named<io.micronaut.gradle.docker.NativeImageDockerfile>("dockerfileNative") {
    jdkVersion = "25"
}


