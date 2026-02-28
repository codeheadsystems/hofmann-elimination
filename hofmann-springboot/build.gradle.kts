
plugins {
    id("buildlogic.java-library-conventions")
    id("buildlogic.publish-conventions")
}

description = "Hofmann spring boot starter for easy integration of Hofmann server into spring boot applications"

dependencies {
    constraints {
        // Spring Boot 4.0.3 ships tools.jackson.core 3.0.4 which has a known CVE.
        // Enforce the patched 3.1.0 for all transitive consumers of this module.
        api(libs.tools.jackson.core) {
            because("CVE in tools.jackson.core:jackson-core <3.1.0 shipped by Spring Boot 4.0.3; require patched 3.1.0")
        }
        api(libs.tools.jackson.databind) {
            because("Align tools.jackson.core:jackson-databind with the patched jackson-core version")
        }
    }

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
