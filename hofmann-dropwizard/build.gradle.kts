
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

        // dropwizard-testing pulls jersey-apache5-connector, which pulls Apache HttpComponents
        // Client/Core 5.x, test-scope only — these never reach a published consumer of this
        // module. Floored on testImplementation (not api) to match that: the constraint has
        // nothing to bind to outside this module's own test classpath.
        testImplementation("org.apache.httpcomponents.client5:httpclient5:5.6.3") {
            because("GHSA-hjcp-jmpx-g3qm: connection leak on Content-Encoding decode error leads to pool exhaustion DoS, fixed in 5.6.3")
        }
        testImplementation("org.apache.httpcomponents.core5:httpcore5:5.4.3") {
            because("GHSA-hf6x-8p5f-cgmf: HTTP/1 header parsing memory-exhaustion DoS, fixed in 5.4.3")
        }
        testImplementation("org.apache.httpcomponents.core5:httpcore5-h2:5.4.3") {
            because("GHSA-v3jc-474w-2wm6: HPackDecoder unlimited header list size before SETTINGS ACK, fixed in 5.4.3")
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
