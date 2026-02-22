plugins {
    `java-library`
}

repositories {
    mavenCentral()
}

dependencies {
    api(project(":hofmann-rfc"))

    compileOnly(libs.jakarta.rs.api)
    implementation(libs.auth0.jwt)
    implementation(libs.javax.inject)
    implementation(libs.bundles.core)
    implementation(libs.bundles.jackson)

    testImplementation(libs.jakarta.rs.api)
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
