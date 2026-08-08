
plugins {
    id("buildlogic.java-library-conventions")
    id("buildlogic.publish-conventions")
    // Test-only construction helpers live in src/testFixtures rather than in the main source set.
    // OpaqueConfig.forTesting() builds a config with the identity KSF — no password stretching at
    // all — and it was public on the production API with nothing but a javadoc line between it
    // and a caller who wanted a quick config. Test fixtures are published as a separate
    // classifier and are not on any consumer's compile classpath by default.
    `java-test-fixtures`
}

description = "Hofmann's RFC implementation for OPRF and OPAQUE"

dependencies {
    implementation(libs.javax.inject)
    implementation(libs.bundles.core)
    implementation(libs.bundles.jackson)

    testImplementation(libs.bundles.test)
    testRuntimeOnly("org.junit.platform:junit-platform-launcher")

    testFixturesImplementation(libs.bundles.core)
}