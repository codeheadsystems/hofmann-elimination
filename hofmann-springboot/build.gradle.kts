
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

        // Spring Boot 4.1.1 (the latest 4.1.x release as of this writing) ships
        // tomcat-embed-core 11.0.24, which carries three critical GHSA advisories fixed in
        // 11.0.25: GHSA-h3x4-894j-xpx5 (FORM auth incorrect authorization), GHSA-9xv2-5v5q-p794
        // (DIGEST authenticator replay bypass), and GHSA-gcx9-497g-6cp6 (improper access
        // control). A constraint (not `force`) floors the resolved version without declaring
        // Tomcat as a direct dependency, so a future Spring Boot release that ships a newer
        // Tomcat still wins and this entry becomes a no-op rather than holding anything back.
        api("org.apache.tomcat.embed:tomcat-embed-core:11.0.25") {
            because("3 critical GHSAs (h3x4-894j-xpx5, 9xv2-5v5q-p794, gcx9-497g-6cp6) fixed in 11.0.25; Spring Boot 4.1.1 ships 11.0.24")
        }
        // tomcat-embed-el and tomcat-embed-websocket are not named in the advisories, but Tomcat
        // publishes the embed family in lockstep, so core 11.0.25 alongside el/websocket 11.0.24
        // is not a combination Tomcat itself tests.
        api("org.apache.tomcat.embed:tomcat-embed-el:11.0.25") {
            because("keeps tomcat-embed-el in step with the floored tomcat-embed-core")
        }
        api("org.apache.tomcat.embed:tomcat-embed-websocket:11.0.25") {
            because("keeps tomcat-embed-websocket in step with the floored tomcat-embed-core")
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
