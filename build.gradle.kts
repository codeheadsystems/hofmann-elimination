/*
 * Root build configuration for PretenderDB
 *
 * Publishing is configured via the nmcp settings plugin in settings.gradle.kts.
 * Run: ./gradlew publishAggregationToCentralPortal
 */

plugins {
    id("org.owasp.dependencycheck") version "13.0.0"
}

// Repositories needed for nmcp plugin runtime dependencies
repositories {
    mavenCentral()
    gradlePluginPortal()
}

// The nmcp.aggregation plugin is auto-applied by the settings plugin
// No additional configuration needed here

/*
 * Dependency vulnerability scanning.
 *
 * The gap this closes: CI ran `gradle/actions/dependency-submission`, which feeds GitHub's
 * Dependabot alerts. That is advisory and post-hoc — it tells you about a vulnerable dependency
 * after the code is on main, in a place nobody looks during review, and it never fails anything.
 * It found the three advisories that `buildlogic.security-floor-conventions` now floors, and they
 * had been sitting open. Useful, but not a gate.
 *
 * `dependencyCheckAggregate` is the gate: it resolves every module's runtime classpath and fails
 * on a CVSS of 7.0 or above.
 *
 * *** It is deliberately NOT wired into `check`. *** Since version 9, Dependency-Check pulls the
 * NVD feed through an API that is severely rate-limited without a key — first run without one can
 * take the better part of an hour. Attaching that to `./gradlew build` would make every local
 * build depend on a network service with an unpredictable latency, and the predictable outcome is
 * that somebody disables it. It runs as its own CI job with NVD_API_KEY supplied, and can be run
 * locally on demand.
 *
 * Honest limitation: this configuration has not been executed end to end here — doing so requires
 * the NVD database and an API key. What has been verified is that the plugin resolves and the
 * task is registered. The first CI run is the real test of it.
 */
dependencyCheck {
    // 7.0 is the CVSS v3 floor for High. Fails the task rather than reporting, which is the
    // whole point of the finding — the existing Dependabot path already reports.
    failBuildOnCVSS = 7.0f
    formats = listOf("HTML", "JSON")
    // Without a key the NVD API rate-limits hard. Read from the environment so CI can supply a
    // secret, or from a Gradle property for local use.
    nvd {
        apiKey = System.getenv("NVD_API_KEY")
            ?: providers.gradleProperty("nvdApiKey").orNull
    }
    // Test-only dependencies do not ship, and a CVE in a test harness is not a vulnerability in
    // anything this project publishes. Scanning them turns the gate into noise, and a noisy gate
    // gets switched off.
    skipConfigurations = listOf(
        "testCompileClasspath", "testRuntimeClasspath",
        "testFixturesCompileClasspath", "testFixturesRuntimeClasspath",
    )
    suppressionFile = "config/dependency-check-suppressions.xml"
}
