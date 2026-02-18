plugins {
    `java-library`
}

repositories {
    mavenCentral()
}

dependencies {
    api(project(":hofmann-server"))
    implementation(libs.bouncy.castle)
    api(libs.spring.boot.starter.webmvc)
    api(libs.spring.boot.starter.security)
    api(libs.spring.boot.starter.actuator)
    api(libs.spring.boot.autoconfigure)

    testImplementation(project(":hofmann-client"))
    testImplementation(libs.bundles.jackson)
    testImplementation(libs.spring.boot.starter.test)
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
