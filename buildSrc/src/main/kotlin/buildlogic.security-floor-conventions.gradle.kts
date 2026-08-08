/*
 * Minimum versions for transitive dependencies with published advisories.
 *
 * These are all pulled in by Dropwizard and Spring Boot rather than declared here, so bumping the
 * framework version is not an option that is always available — a patched Jetty usually ships
 * well before the Dropwizard release that picks it up. A constraint raises the resolved version
 * without adding the dependency, which is the mechanism that fits: modules that never see Jetty
 * are unaffected, and the constraint disappears on its own once the framework catches up.
 *
 * Constraints, not `force`. A constraint is a floor, so a later framework release that brings a
 * newer version still wins; `force` would pin us to these numbers and quietly hold the ecosystem
 * back. If a floor ever needs to become a ceiling, that is a different problem and should look
 * different in the build.
 *
 * Whole families move together. Jetty publishes its modules in lockstep and mixing 12.1.10
 * jetty-server with 12.1.9 jetty-http is not a configuration anyone tests, so every artifact in
 * the family gets the same floor even though only two are named in the advisories.
 *
 * Each entry says which advisory it answers and whether this project is actually exposed. That
 * second part matters: a floor kept for an issue that no longer applies is a version pin nobody
 * remembers the reason for, and the way to delete it safely is to have written down what it was
 * for.
 */

plugins {
    java
}

dependencies {
    constraints {
        // GHSA — Jetty digest authentication: ISO-8859-1 lossy encoding allows authentication
        // bypass via character substitution. Rated high. This project does not use digest auth
        // anywhere (the JWT arrives as a Bearer token and nothing configures a digest realm), so
        // it is not exposed directly. The floor exists because the bundle installs into other
        // people's Dropwizard applications, and their authentication configuration is not ours
        // to assume.
        implementation("org.eclipse.jetty:jetty-security:12.1.10") {
            because("digest authentication bypass via ISO-8859-1 lossy encoding, fixed in 12.1.10")
        }
        // GHSA — Jetty cross-request leakage for trailers on HTTP/1.1 keep-alive connections.
        // Rated medium. Trailers leaking across requests on a shared connection is exactly the
        // class of bug that matters for an authentication endpoint, where the request body
        // carries the OPRF evaluation and the response carries a session token.
        implementation("org.eclipse.jetty:jetty-server:12.1.10") {
            because("cross-request trailer leakage on keep-alive connections, fixed in 12.1.10")
        }
        // Moved with the two above so the family stays on one version.
        implementation("org.eclipse.jetty:jetty-http:12.1.10") {
            because("keeps the Jetty family on one version alongside the two advisories above")
        }
        implementation("org.eclipse.jetty:jetty-io:12.1.10") {
            because("keeps the Jetty family on one version alongside the two advisories above")
        }
        implementation("org.eclipse.jetty:jetty-util:12.1.10") {
            because("keeps the Jetty family on one version alongside the two advisories above")
        }
        implementation("org.eclipse.jetty:jetty-session:12.1.10") {
            because("keeps the Jetty family on one version alongside the two advisories above")
        }
        implementation("org.eclipse.jetty.ee10:jetty-ee10-servlet:12.1.10") {
            because("keeps the Jetty family on one version alongside the two advisories above")
        }
        // GHSA — logback object injection through HardenedObjectInputStream. Rated low, and it
        // needs a deserialization path this project does not open: nothing here enables the
        // socket receiver or deserializes a logging event. Floored anyway because it costs a
        // patch version.
        implementation("ch.qos.logback:logback-core:1.5.34") {
            because("object injection through HardenedObjectInputStream, fixed in 1.5.34")
        }
        // logback-classic is not named in that advisory, but it links against core's internals
        // and the two are released together. Leaving classic on 1.5.33 against core 1.5.34 is
        // the untested combination, which is a worse trade than one extra patch bump.
        implementation("ch.qos.logback:logback-classic:1.5.34") {
            because("keeps logback-classic in step with the floored logback-core")
        }
    }
}
