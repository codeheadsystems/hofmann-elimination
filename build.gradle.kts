/*
 * Root build configuration for PretenderDB
 *
 * Publishing is configured via the nmcp settings plugin in settings.gradle.kts.
 * Run: ./gradlew publishAggregationToCentralPortal
 */

// Repositories needed for nmcp plugin runtime dependencies
repositories {
    mavenCentral()
    gradlePluginPortal()
}

// The nmcp.aggregation plugin is auto-applied by the settings plugin
// No additional configuration needed here
