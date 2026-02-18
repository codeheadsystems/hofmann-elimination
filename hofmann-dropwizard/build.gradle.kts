plugins {
    `java-library`
}

repositories {
    mavenCentral()
}

dependencies {
    api(project(":hofmann-server"))

    api(libs.dropwizard.core)

    testImplementation(libs.dropwizard.testing)
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
