plugins {
    `java-library`
}

repositories {
    mavenCentral()
}

dependencies {
    api(project(":oprf"))
    api(project(":opaque"))

    implementation(libs.javax.inject)
    implementation(libs.bundles.core)

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}

java {
    toolchain {
        languageVersion = JavaLanguageVersion.of(21)
    }
}

tasks.named<Test>("test") {
    useJUnitPlatform()
}
