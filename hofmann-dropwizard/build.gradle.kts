
plugins {
    id("buildlogic.java-library-conventions")
    id("buildlogic.publish-conventions")
}

description = "Hofmann dropwizard bundle for easy integration of Hofmann server into dropwizard applications"

dependencies {
    constraints {
        // Dropwizard 5.0.1 ships jackson-core 2.21.0 which has a known CVE.
        // Enforce the patched 2.21.1 for all transitive consumers of this module.
        api(libs.jackson.core) {
            because("CVE in jackson-core 2.21.0 shipped by Dropwizard 5.0.1; require patched 2.21.1")
        }
        api(libs.jackson.databind) {
            because("Align jackson-databind with the patched jackson-core version")
        }
    }

    api(project(":hofmann-server"))

    api(libs.dropwizard.auth)
    api(libs.dropwizard.core)

    testImplementation(project(":hofmann-client"))
    testImplementation(libs.dropwizard.testing)
    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")
}
