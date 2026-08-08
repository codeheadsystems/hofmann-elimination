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
 * Dependabot alerts. That is advisory and post-hoc — it reports a vulnerable dependency after the
 * code is on main, in a place nobody looks during review, and it never fails anything. It found
 * the three advisories `buildlogic.security-floor-conventions` now floors, and they sat open.
 *
 * *** How to run it: `./gradlew --no-parallel dependencyCheckAggregate`, with an NVD API key. ***
 * Both parts are mandatory and both were discovered the hard way, by a reviewer running the job I
 * had written and could not run myself:
 *
 *   --no-parallel   gradle.properties sets org.gradle.parallel=true globally, and the aggregate
 *                   task resolves other projects' configurations at execution time, which Gradle 9
 *                   forbids under parallel execution: "Resolution of the configuration
 *                   ':hofmann-client:annotationProcessor' was attempted without an exclusive
 *                   lock." It fails in about ten seconds, before any network access.
 *
 *   NVD_API_KEY     Not optional, despite what the first version of this comment claimed. I wrote
 *                   that without a key the scan "still runs, rate-limited". It does not:
 *                   dependency-check ships nvd.api.key as an *empty string* rather than absent,
 *                   which passes its own null guard and gets sent as an empty apiKey header. NVD
 *                   answers that with 404 where it answers a missing header with 200, and the
 *                   resulting UpdateException fails the task. Get a key at
 *                   https://nvd.nist.gov/developers/request-an-api-key.
 *
 * *** Deliberately NOT wired into `check`. *** Building the NVD database is slow and depends on a
 * network service, and attaching that to `./gradlew build` would make every local build hostage to
 * it. The predictable outcome is that somebody disables it. It runs as its own CI job instead.
 *
 * What it catches: the CVSS floor is 4.0, not the 7.0 I first chose. At 7.0 this gate would have
 * fired on one of the three advisories that motivated it — the jetty-security bypass scores 8.7 on
 * CVSS v4, jetty-server's trailer leak scores 6.9, and the logback issue is unscored and low. A
 * gate that misses two thirds of the findings that prompted it is not a gate. 4.0 catches two of
 * the three; the third is unscored and no threshold reaches it.
 */
dependencyCheck {
    // Medium and above. See the note on 7.0 above — the threshold that sounded principled would
    // have missed most of what was actually open.
    failBuildOnCVSS = 4.0f
    formats = listOf("HTML", "JSON")
    nvd {
        apiKey = System.getenv("NVD_API_KEY")?.takeIf { it.isNotBlank() }
            ?: providers.gradleProperty("nvdApiKey").orNull
    }
    // annotationProcessor is compile-time only and does not ship, and it is scanned by default —
    // it is the configuration named in the parallel-lock failure above. The four test
    // configurations that used to be listed here were removed: skipTestGroups defaults to true and
    // already matches all of them, so naming them looked like protection and did nothing.
    skipConfigurations = listOf("annotationProcessor", "testAnnotationProcessor")
    // Absolute. The relative path was resolved against the daemon's working directory, which is
    // not guaranteed to be the project directory when a daemon is reused.
    suppressionFile = layout.projectDirectory.file("config/dependency-check-suppressions.xml")
        .asFile.absolutePath
}
