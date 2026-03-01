plugins {
    id("buildlogic.java-library-conventions")
}

description = "Integration tests for Hofmann OPRF/OPAQUE across cipher suites and clients"

dependencies {
    constraints {
        // Match the CVE fix from hofmann-springboot
        implementation(libs.tools.jackson.core) {
            because("CVE in tools.jackson.core:jackson-core <3.1.0 shipped by Spring Boot 4.0.3")
        }
        implementation(libs.tools.jackson.databind) {
            because("Align tools.jackson.core:jackson-databind with the patched jackson-core version")
        }
    }

    testImplementation(project(":hofmann-springboot"))
    testImplementation(project(":hofmann-client"))
    testImplementation(project(":hofmann-rfc"))
    testImplementation(libs.bundles.jackson)
    testImplementation(libs.spring.boot.starter.test)
    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
